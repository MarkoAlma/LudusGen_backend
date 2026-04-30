import express from 'express';
import Anthropic from '@anthropic-ai/sdk';
import OpenAI, { toFile } from 'openai';
import { fal } from '@fal-ai/client';
import admin from 'firebase-admin';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import dotenv from 'dotenv';
import axios from 'axios';
import FormData from 'form-data';
import multer from 'multer';
import dns from "dns";
dns.setDefaultResultOrder("ipv4first");
import https from "https";

import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
import { createWriteStream, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';
import sharp from 'sharp';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

import {
    buildContext,
    getMessagesForSummary,
    RECENT_MESSAGE_WINDOW,
    SUMMARY_TRIGGER_COUNT,
    trimToContextLimit,
} from './src/lib/contextBuilder.js';
import {
    buildTripoAssetNameFallback,
    buildTripoAssetNamingMessages,
    normalizeTripoAssetName,
} from './src/lib/tripoAssetNaming.js';
import {
    encodeImageGalleryCursor,
    decodeImageGalleryCursor,
    clampImageGalleryLimit,
} from './src/lib/imageGalleryCursor.js';
import { storageService } from './src/services/storageService.js';
import { canAccessMarketplaceStorageKey } from './src/services/marketplaceService.js';
import { verifyFirebaseToken } from './src/middleware/verifyFirebaseToken.js';

import { registerJob, unregisterJob, activeJobs } from './src/lib/jobRegistry.js';

import { existsSync, writeFileSync, unlinkSync } from 'fs';

// ── Riva proto betöltés ───────────────────────────────────────────────────────
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROTO_DIR = path.join(__dirname, 'protos');
const PROTO_PATH = path.join(PROTO_DIR, 'riva_tts.proto');

const INLINE_PROTO = `
syntax = "proto3";
package nvidia.riva.tts;
enum AudioEncoding { ENCODING_UNSPECIFIED = 0; LINEAR_PCM = 1; FLAC = 2; MULAW = 3; ALAW = 20; }
message SynthesizeSpeechRequest {
  string text = 1;
  string language_code = 2;
  AudioEncoding encoding = 3;
  int32 sample_rate_hz = 4;
  string voice_name = 5;
}
message SynthesizeSpeechResponse {
  bytes audio = 1;
}
service RivaSpeechSynthesis {
  rpc Synthesize(SynthesizeSpeechRequest) returns (SynthesizeSpeechResponse);
}
`;

function ensureProtoSync() {
    mkdirSync(PROTO_DIR, { recursive: true });
    writeFileSync(PROTO_PATH, INLINE_PROTO);
}
ensureProtoSync();

function createRivaClient() {
    const packageDef = protoLoader.loadSync(PROTO_PATH, {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
    });
    const proto = grpc.loadPackageDefinition(packageDef).nvidia.riva.tts;
    const sslCreds = grpc.credentials.createSsl();
    return new proto.RivaSpeechSynthesis('grpc.nvcf.nvidia.com:443', sslCreds);
}

function pcmToWav(pcmBuffer, sampleRate = 22050, channels = 1, bitDepth = 16) {
    const dataSize = pcmBuffer.length;
    const byteRate = sampleRate * channels * (bitDepth / 8);
    const blockAlign = channels * (bitDepth / 8);
    const buf = Buffer.alloc(44 + dataSize);

    buf.write('RIFF', 0);
    buf.writeUInt32LE(36 + dataSize, 4);
    buf.write('WAVE', 8);
    buf.write('fmt ', 12);
    buf.writeUInt32LE(16, 16);
    buf.writeUInt16LE(1, 20);
    buf.writeUInt16LE(channels, 22);
    buf.writeUInt32LE(sampleRate, 24);
    buf.writeUInt32LE(byteRate, 28);
    buf.writeUInt16LE(blockAlign, 32);
    buf.writeUInt16LE(bitDepth, 34);
    buf.write('data', 36);
    buf.writeUInt32LE(dataSize, 40);
    pcmBuffer.copy(buf, 44);

    return buf;
}

const httpsAgent = new https.Agent({ family: 4 });
const deapiReferenceAudioUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 },
});
const deapiImageUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 },
});
const MINIMAX_MUSIC_SAMPLE_RATES = [16000, 24000, 32000, 44100];
const MINIMAX_MUSIC_BITRATES = [32000, 64000, 128000, 256000];
const MINIMAX_MUSIC_FORMATS = ['mp3', 'wav', 'pcm'];

dotenv.config();

const router = express.Router();

const REQUIRED_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'FAL_KEY', 'OPENROUTER_API_KEY', 'DEEPSEEK_API_KEY', 'MINIMAX_API_KEY', 'DEAPI_API_KEY', 'MODELSCOPE_API_KEY'];
REQUIRED_KEYS.forEach((key) => {
    if (!process.env[key]) console.warn(`⚠️  Hiányzó .env változó: ${key}`);
});

const activeStreams = new Map();

// ── Job Registry for Cancellation & Timeouts (Moved to src/lib/jobRegistry.js) ──

router.post('/cancel-job', verifyFirebaseToken, (req, res) => {
    const { jobId } = req.body;
    if (!jobId) return res.status(400).json({ success: false, message: 'Hiányzó jobId' });
    const job = activeJobs.get(jobId);
    if (job) {
        console.log(`[Cancel] User requested cancellation for job: ${jobId}`);
        job.controller.abort();
        clearTimeout(job.timeoutId);
        activeJobs.delete(jobId);
        return res.json({ success: true, message: 'Folyamat megszakítva' });
    }
    return res.status(404).json({ success: false, message: 'Folyamat nem található vagy már véget ért' });
});

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

fal.config({ credentials: process.env.FAL_KEY });

const MESHY_KEY = process.env.MESHY_API_KEY || process.env.TRIPO3D_API_KEY || process.env.TRIPO3D;
const meshy = axios.create({
    baseURL: 'https://api.meshy.ai',
    headers: { Authorization: `Bearer ${MESHY_KEY}` },
});


// ── Rate limitek ─────────────────────────────────────────────────────────────
const chatLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, max: 600,
    keyGenerator: (req) => req.userId || ipKeyGenerator(req),
    message: { success: false, message: 'Túl sok kérés — próbáld újra 1 óra múlva' },
});
const imageLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, max: 200,
    keyGenerator: (req) => req.userId || ipKeyGenerator(req),
    message: { success: false, message: 'Túl sok képgenerálás — próbáld újra 1 óra múlva' },
});
const audioLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, max: 300,
    keyGenerator: (req) => req.userId || ipKeyGenerator(req),
    message: { success: false, message: 'Túl sok hanggenerálás — próbáld újra 1 óra múlva' },
});
const genLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, max: 300,
    keyGenerator: (req) => req.userId || ipKeyGenerator(req),
    message: { success: false, message: 'Túl sok generálás – próbáld újra 1 óra múlva' },
});

// ── Token Usage Logger (Precise) ─────────────────────────────────────────────
function printTokenUsage(provider, model, usage) {
    const p = provider.toUpperCase().padEnd(10);
    const m = model.padEnd(25);

    // Alap mezők
    const inT = (usage.prompt_tokens || usage.input_tokens || 0);
    const outT = (usage.completion_tokens || usage.output_tokens || 0);

    // Ha az API adott total-t, azt tekintjük alapnak
    const totalT = (usage.total_tokens || (inT + outT));

    // Kiszámoljuk az eltérést (pl. cache kért tartalom)
    const extraT = Math.max(0, totalT - (inT + outT));

    const sIn = String(inT).padStart(6);
    const sOut = String(outT).padStart(6);
    const sExtra = extraT > 0 ? `| EXTRA: \x1b[36m${String(extraT).padStart(6)}\x1b[0m ` : "".padEnd(0);
    const sTotal = String(totalT).padStart(7);

    console.log(`\x1b[32m[USAGE]\x1b[0m \x1b[1m${p}\x1b[0m | \x1b[36m${m}\x1b[0m | IN: \x1b[33m${sIn}\x1b[0m | OUT: \x1b[33m${sOut}\x1b[0m ${sExtra}| TOTAL: \x1b[35m${sTotal}\x1b[0m`);
}

// ── Firestore usage log ───────────────────────────────────────────────────────
async function logUsage(userId, type, meta = {}) {
    try {
        const cleanMeta = Object.fromEntries(
            Object.entries(meta).filter(([, v]) => v !== undefined && v !== null)
        );

        // Debug log to console
        if (type === 'chat') {
            printTokenUsage(meta.provider || 'unknown', meta.model || 'unknown', meta);
        }

        await admin.firestore().collection('usage_logs').add({
            userId, type, ...cleanMeta,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
    } catch (e) {
        console.warn('Usage log failed:', e.message);
    }
}

// ── Messages normalizálása ────────────────────────────────────────────────────
function normalizeMessages(messages) {
    if (!messages || !Array.isArray(messages)) return [];

    let cleaned = messages.map(m => ({
        role: m.role || 'user',
        content: m.content
    })).filter(m => {
        if (m.content === null || m.content === undefined) return false;
        if (typeof m.content === 'string' && m.content.trim() === '') return false;
        if (Array.isArray(m.content) && m.content.length === 0) return false;
        return true;
    });

    if (cleaned.length === 0) return [];

    const merged = [];
    for (const msg of cleaned) {
        if (merged.length > 0 && merged[merged.length - 1].role === msg.role) {
            const last = merged[merged.length - 1];
            if (typeof last.content === 'string' && typeof msg.content === 'string') {
                last.content += "\n\n" + msg.content;
            } else {
                const lastParts = Array.isArray(last.content) ? last.content : [{ type: 'text', text: String(last.content) }];
                const nextParts = Array.isArray(msg.content) ? msg.content : [{ type: 'text', text: String(msg.content) }];
                last.content = [...lastParts, ...nextParts];
            }
        } else {
            merged.push({ ...msg });
        }
    }

    const finalMessages = [];
    const systemContent = [];
    const chatMsgs = [];

    for (const m of merged) {
        if (m.role === 'system') {
            systemContent.push(typeof m.content === 'string' ? m.content : JSON.stringify(m.content));
        } else {
            chatMsgs.push(m);
        }
    }

    if (systemContent.length > 0) {
        finalMessages.push({ role: 'system', content: systemContent.join("\n\n") });
    }

    while (chatMsgs.length > 0 && chatMsgs[0].role === 'assistant') {
        chatMsgs.shift();
    }

    finalMessages.push(...chatMsgs);

    return finalMessages;
}

function dataUrlToGeminiInlineData(dataUrl) {
    if (typeof dataUrl !== 'string') return null;
    const match = dataUrl.match(/^data:([^;,]+);base64,(.+)$/);
    if (!match) return null;
    return {
        inline_data: {
            mime_type: match[1],
            data: match[2],
        },
    };
}

function toGeminiParts(content) {
    if (!Array.isArray(content)) {
        return [{ text: String(content) }];
    }

    const parts = [];
    for (const part of content) {
        if (part?.type === 'text') {
            const text = typeof part.text === 'string' ? part.text : '';
            if (text.trim()) parts.push({ text });
            continue;
        }

        if (part?.type === 'image_url') {
            const imageUrl = typeof part.image_url === 'string' ? part.image_url : part.image_url?.url;
            const inlineData = dataUrlToGeminiInlineData(imageUrl);
            if (inlineData) parts.push(inlineData);
        }
    }

    return parts.length ? parts : [{ text: '' }];
}

function stripAssistantThinking(value, hideOpenBlock = true) {
    let text = typeof value === 'string' ? value : value == null ? '' : String(value);
    if (!text) return '';

    text = text
        .replace(/<think(?:ing)?\b[^>]*>[\s\S]*?<\/think(?:ing)?>/gi, '')
        .replace(/<reasoning\b[^>]*>[\s\S]*?<\/reasoning>/gi, '')
        .replace(/```(?:thinking|reasoning|thoughts?|chain[-_\s]?of[-_\s]?thought)\s*\n[\s\S]*?```/gi, '');

    if (hideOpenBlock) {
        text = text
            .replace(/<think(?:ing)?\b[^>]*>[\s\S]*$/i, '')
            .replace(/<reasoning\b[^>]*>[\s\S]*$/i, '')
            .replace(/```(?:thinking|reasoning|thoughts?|chain[-_\s]?of[-_\s]?thought)\s*\n[\s\S]*$/i, '')
            .replace(/<(?:t|th|thi|thin|think|thinki|thinkin|thinking|r|re|rea|reas|reaso|reason|reasoni|reasonin|reasoning)?$/i, '');
    }

    return text
        .replace(/[ \t]+\n/g, '\n')
        .replace(/\n{3,}/g, '\n\n')
        .trim();
}

// ── Model config ──────────────────────────────────────────────────────────────
function getModelConfig(modelId) {
    const MODEL_MAP = {
        'claude_sonnet': { apiModel: 'claude-sonnet-4-20250514', provider: 'anthropic', defaultSystemPrompt: 'You are a helpful, harmless, and honest assistant. Respond in the same language the user writes in.' },
        'claude_opus': { apiModel: 'claude-opus-4-20250514', provider: 'anthropic', defaultSystemPrompt: 'You are a helpful, harmless, and honest assistant. Respond in the same language the user writes in.' },
        'gpt4o_mini': { apiModel: 'gpt-4o-mini', provider: 'openai', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'gpt4o': { apiModel: 'gpt-4o', provider: 'openai', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'gpt4o_code': { apiModel: 'gpt-4o', provider: 'openai', defaultSystemPrompt: 'You are an elite software engineer with deep expertise across all programming languages and paradigms.\n- Produce production-ready, optimized code\n- Apply SOLID principles and design patterns\n- Include comprehensive error handling\n- Write thorough technical explanations\n- Review and suggest improvements proactively\n- Respond in the same language the user writes in' },
        'trinity-large': { apiModel: 'arcee-ai/trinity-large-thinking', provider: 'openrouter', defaultSystemPrompt: 'You are an elite software engineer with deep expertise across all programming languages and paradigms.\n- Produce production-ready, optimized code\n- Apply SOLID principles and design patterns\n- Include comprehensive error handling\n- Write thorough technical explanations\n- Review and suggest improvements proactively\n- Respond in the same language the user writes in' },
        'gemini-3-flash': { apiModel: 'gemini-3-flash-preview', provider: 'gemini', supportsVision: true, defaultSystemPrompt: 'You are a helpful AI assistant powered by Google Gemini. Respond in the same language the user writes in.' },
        'gemini-2.5-pro': { apiModel: 'gemini-2.5-pro', provider: 'gemini', supportsVision: true, defaultSystemPrompt: 'You are a helpful AI assistant powered by Google Gemini. Respond in the same language the user writes in.' },
        'groq-gpt120b': { apiModel: 'openai/gpt-oss-120b', provider: 'groq', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'groq-qwen3': { apiModel: 'qwen/qwen3-32b', provider: 'groq', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'groq-llama70b': { apiModel: 'llama-3.3-70b-versatile', provider: 'groq', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'cerebras-llama8b': { apiModel: 'llama3.1-8b', provider: 'cerebras', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'mistral-large': { apiModel: 'mistral-large-latest', provider: 'mistral', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'nvidia-glm4.7': { apiModel: 'z-ai/glm4.7', provider: 'nvidia', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'google-gemma-3-27b-it': { apiModel: 'google/gemma-3-27b-it', provider: 'nvidia', supportsVision: true, defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
    };
    return MODEL_MAP[modelId] || null;
}

// ── Rolling Context Summary konstansok ───────────────────────────────────────
function readStreamToString(stream) {
    if (!stream || typeof stream.on !== 'function') return Promise.resolve('');

    return new Promise((resolve) => {
        let body = '';
        let settled = false;
        const finish = () => {
            if (settled) return;
            settled = true;
            resolve(body);
        };

        stream.setEncoding?.('utf8');
        stream.on('data', (chunk) => { body += chunk; });
        stream.on('end', finish);
        stream.on('error', finish);

        const timeout = setTimeout(finish, 1500);
        timeout.unref?.();
    });
}

async function getAxiosErrorDetails(err) {
    const status = err.response?.status || err.response?.statusCode || err.response?.data?.statusCode || null;
    const rawData = err.response?.data;
    let rawBody = '';

    if (typeof rawData === 'string') {
        rawBody = rawData;
    } else if (Buffer.isBuffer(rawData)) {
        rawBody = rawData.toString('utf8');
    } else if (rawData && typeof rawData.on === 'function') {
        rawBody = await readStreamToString(rawData);
    } else if (rawData && typeof rawData === 'object' && !rawData.readable) {
        try { rawBody = JSON.stringify(rawData); } catch { rawBody = ''; }
    }

    let code = null;
    let message = err.message || 'API request failed';

    if (rawBody) {
        try {
            const parsed = JSON.parse(rawBody);
            const payload = parsed.error || parsed;
            code = payload.code || payload.type || null;
            message = payload.message || payload.error || message;
        } catch {
            message = rawBody.slice(0, 500);
        }
    }

    return { status, code, message };
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function getRetryAfterMs(headers, fallbackMs) {
    const retryAfter = headers?.['retry-after'];
    if (!retryAfter) return fallbackMs;

    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds)) return Math.min(Math.max(seconds * 1000, 500), 10000);

    const dateMs = Date.parse(retryAfter);
    if (Number.isFinite(dateMs)) return Math.min(Math.max(dateMs - Date.now(), 500), 10000);

    return fallbackMs;
}

const SUMMARY_COLLECTION = 'chat_summaries';

// ── Groq retry helper — kezeli a 429 rate limit hibákat ──────────────────────
async function groqWithRetry(body, retries = 3) {
    for (let i = 0; i < retries; i++) {
        try {
            const resp = await axios.post(
                'https://api.groq.com/openai/v1/chat/completions',
                body,
                {
                    headers: {
                        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
                        'Content-Type': 'application/json',
                    },
                    timeout: 30000,
                }
            );
            return resp;
        } catch (err) {
            if (err.response?.status === 429 && i < retries - 1) {
                const retryAfterSec = parseInt(err.response.headers['retry-after'] || '10');
                const waitMs = Math.min(retryAfterSec * 1000, 15000); // max 15 sec várjon
                console.warn(`[Groq] Rate limit, várakozás ${waitMs}ms... (${i + 1}/${retries})`);
                await new Promise(r => setTimeout(r, waitMs));
            } else {
                throw err;
            }
        }
    }
}

function cleanSessionTitle(value) {
    return String(value ?? '')
        .replace(/["'`“”„]/g, '')
        .replace(/[\r\n\t]+/g, ' ')
        .replace(/\s+/g, ' ')
        .replace(/^(title|same-language title|same language title|cím)\s*:\s*/iu, '')
        .replace(/^[\s:;,.!?()[\]{}<>-]+|[\s:;,.!?()[\]{}<>-]+$/gu, '')
        .trim();
}

function fallbackSessionTitle(firstUserMessage) {
    const cleaned = cleanSessionTitle(firstUserMessage);
    if (!cleaned) return null;

    const words = cleaned.match(/[\p{L}\p{N}][\p{L}\p{N}'’_-]*/gu) || [];
    if (words.length === 0) return cleaned.slice(0, 60).trim() || null;

    const titleWords = words.length <= 4 && cleaned.length <= 60
        ? words
        : words.slice(0, 6);

    return cleanSessionTitle(titleWords.join(' ')).slice(0, 60).trim() || null;
}

function shouldUseLiteralTitle(firstUserMessage) {
    const cleaned = cleanSessionTitle(firstUserMessage);
    const words = cleaned.match(/[\p{L}\p{N}][\p{L}\p{N}'’_-]*/gu) || [];
    return cleaned.length <= 60 && words.length > 0 && words.length <= 4;
}

function isGenericEnglishTitle(title) {
    const normalized = cleanSessionTitle(title).toLowerCase();
    return [
        'hello message',
        'greeting message',
        'user message',
        'chat message',
        'general message',
        'general conversation',
        'conversation starter',
    ].includes(normalized);
}

async function generateSessionTitle(firstUserMessage) {
    const fallbackTitle = fallbackSessionTitle(firstUserMessage);

    if (shouldUseLiteralTitle(firstUserMessage)) {
        return fallbackTitle;
    }

    try {
        const resp = await groqWithRetry({
            model: 'llama-3.3-70b-versatile',
            messages: [
                {
                    role: 'system',
                    content: [
                        'You are a title generator.',
                        'Create ONLY a 2-4 word title summarizing the user message.',
                        'Keep the title in the exact same language as the user message.',
                        'Never translate the title to English unless the user message is already English.',
                        'If the message is only a greeting or a very short phrase, reuse the phrase in its original language.',
                        'No punctuation, no quotes, no explanation. Just the title words.',
                    ].join(' '),
                },
                { role: 'user', content: `Original user message:\n${String(firstUserMessage).slice(0, 500)}\n\nSame-language title:` },
            ],
            temperature: 0.1,
            max_tokens: 20,
            stream: false,
        });
        const raw = cleanSessionTitle(resp.data?.choices?.[0]?.message?.content);
        if (!raw || raw.toLowerCase() === 'null' || raw.length < 2) return fallbackTitle || null;
        if (isGenericEnglishTitle(raw)) return fallbackTitle || null;
        return raw.slice(0, 60).trim();
    } catch (e) {
        console.warn('[Title] Generation failed:', e.message);
        return fallbackTitle || null;
    }
}

async function refreshSessionSummary({ userId, sessionId, modelId, allMessages, sessionData }) {
    const summarizedMessageCount = sessionData.summarizedMessageCount || 0;
    const messagesForSummary = getMessagesForSummary(allMessages, summarizedMessageCount);

    if (messagesForSummary.length === 0) {
        return {
            summaryRefreshed: false,
            summarizedMessageCount,
            summary: sessionData.summary || null,
        };
    }

    const previousSummary = sessionData.summary || '';
    const summaryPrompt = previousSummary
        ? `You are updating a cumulative conversation summary. Merge the previous summary with the newly provided older messages.

Previous summary:
${previousSummary}

Return a concise updated summary in the same language as the conversation.
Include durable facts, established preferences, decisions, constraints, and unresolved questions.
Do not mention message counts or timestamps.
Keep it under 220 tokens.`
        : `Summarize these conversation messages in the same language as the conversation.
Include durable facts, established preferences, decisions, constraints, and unresolved questions.
Do not mention message counts or timestamps.
Keep it under 180 tokens.`;

    const summaryResponse = await groqWithRetry({
        model: 'openai/gpt-oss-120b',
        messages: [
            { role: 'system', content: summaryPrompt },
            ...messagesForSummary.map((message) => ({
                role: message.role,
                content: typeof message.content === 'string'
                    ? message.content.slice(0, 1200)
                    : JSON.stringify(message.content).slice(0, 1200),
            })),
        ],
        temperature: 0.2,
        max_tokens: 260,
        stream: false,
    });

    const nextSummary = summaryResponse.data?.choices?.[0]?.message?.content?.trim();
    if (!nextSummary) {
        throw new Error('Summary generation returned empty content');
    }

    const nextSummarizedMessageCount = summarizedMessageCount + messagesForSummary.length;
    const db = admin.firestore();
    const sessionRef = db.collection('conversations').doc(userId).collection('sessions').doc(sessionId);
    const summaryRef = sessionRef.collection(SUMMARY_COLLECTION).doc('latest');

    const batch = db.batch();
    batch.set(summaryRef, {
        summaryText: nextSummary,
        summarizedMessageCount: nextSummarizedMessageCount,
        lastSummaryModelId: modelId || 'unknown',
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    batch.set(sessionRef, {
        summary: nextSummary,
        summarizedMessageCount: nextSummarizedMessageCount,
        summaryUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    await batch.commit();

    console.log(`[Summary] Cumulative summary refreshed. summarized=${nextSummarizedMessageCount}, session=${sessionId}`);

    return {
        summaryRefreshed: true,
        summarizedMessageCount: nextSummarizedMessageCount,
        summary: nextSummary,
    };
}

// ════════════════════════════════════════════════════
// 1.  CHAT  —  POST /api/chat
// ════════════════════════════════════════════════════
router.post('/chat', verifyFirebaseToken, chatLimiter, async (req, res) => {
    try {
        const { sessionId, message, attachedImage, messageId, assistantMessageId } = req.body;
        const requestedModelId = typeof req.body?.modelId === 'string' ? req.body.modelId.trim() : '';
        const requestedModelName = typeof req.body?.modelName === 'string' ? req.body.modelName.trim().slice(0, 120) : '';
        const assistantDocId = assistantMessageId || messageId || null;

        if (!sessionId) {
            return res.status(400).json({ success: false, message: 'Hiányzó sessionId' });
        }
        if (!message || (typeof message !== 'string' && !attachedImage)) {
            return res.status(400).json({ success: false, message: 'Hiányzó üzenet' });
        }

        const adminDb = admin.firestore();
        const userId = req.userId;

        // ── Abort handling ──
        const controller = new AbortController();
        const signal = controller.signal;
        const streamKey = `${userId}:${sessionId}`;
        activeStreams.set(streamKey, controller);

        req.on('close', () => {
            console.log(`[Chat] Kliens lecsatlakozott, AI stream leállítva...`);
            controller.abort();
            activeStreams.delete(streamKey);
        });

        // ── Session betöltése ──
        const sessionRef = adminDb.collection('conversations').doc(userId).collection('sessions').doc(sessionId);
        const sessionDoc = await sessionRef.get();
        const sessionData = sessionDoc.exists ? sessionDoc.data() : {};

        const sessionModelId = typeof sessionData.modelId === 'string' ? sessionData.modelId.trim() : '';
        const modelId = requestedModelId || sessionModelId;
        if (!modelId) {
            activeStreams.delete(streamKey);
            return res.status(400).json({ success: false, message: 'Hiányzó modelId: a chat kérésnek meg kell adnia a kiválasztott modellt.' });
        }
        const modelName = requestedModelName || sessionData.modelName || modelId;

        const modelConfig = getModelConfig(modelId);
        if (!modelConfig) {
            activeStreams.delete(streamKey);
            return res.status(400).json({ success: false, message: `Ismeretlen modell: ${modelId}` });
        }

        if (attachedImage && !modelConfig.supportsVision) {
            activeStreams.delete(streamKey);
            return res.status(400).json({ success: false, message: 'This model does not accept images.' });
        }

        const { apiModel, provider, defaultSystemPrompt } = modelConfig;
        if (requestedModelId && requestedModelId !== sessionModelId) {
            await sessionRef.set({
                sessionId,
                modelId,
                modelName,
                updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            }, { merge: true });
            sessionData.modelId = modelId;
            sessionData.modelName = modelName;
        }

        const messagesRef = sessionRef.collection('messages');
        const messagesSnap = await messagesRef.orderBy('timestamp', 'asc').get();

        const storedMessages = messagesSnap.docs.map((docSnap) => ({
            role: docSnap.data().role,
            content: docSnap.data().content,
        }));

        const newMessage = attachedImage
            ? {
                role: 'user',
                content: [
                    { type: 'image_url', image_url: { url: attachedImage } },
                    { type: 'text', text: message },
                ],
            }
            : { role: 'user', content: message };

        const lastStoredMessage = storedMessages[storedMessages.length - 1];
        const userAlreadySaved =
            lastStoredMessage &&
            lastStoredMessage.role === 'user' &&
            typeof lastStoredMessage.content === 'string' &&
            lastStoredMessage.content === message;

        const baseMessages = userAlreadySaved ? storedMessages : [...storedMessages, newMessage];
        let context = buildContext(
            baseMessages,
            sessionData.summary || null,
            sessionData.summarizedMessageCount || 0,
            null,
            defaultSystemPrompt || null,
        );

        context = trimToContextLimit(context, 8192 * 32 * 0.8);

        console.log(`[Chat] Kontextus: ${context.length} üzenet, summary: ${sessionData.summary ? 'igen' : 'nem'}`);

        // ── Title generálás (csak az első üzenetnél) ──
        if (!sessionData.title) {
            const firstUserText = typeof message === 'string' ? message : '[kép]';
            console.log(`[Title] Generating for session ${sessionId}, message: "${firstUserText.slice(0, 60)}"`);
            const generatedTitle = await generateSessionTitle(firstUserText);
            console.log(`[Title] Generated: "${generatedTitle}"`);
            if (generatedTitle) {
                await sessionRef.set({ title: generatedTitle }, { merge: true });
                sessionData.title = generatedTitle;
                console.log(`[Title] Saved to Firestore: "${generatedTitle}"`);
            }
        }

        // ── API paraméterek ──
        const temperature = sessionData.temperature ?? 0.7;
        const max_tokens = sessionData.maxTokens ?? 2048;
        const top_p = sessionData.topP ?? 0.9;
        const frequency_penalty = sessionData.frequencyPenalty ?? 0;
        const presence_penalty = sessionData.presencePenalty ?? 0;
        const safeMax = Math.min(Math.max(128, max_tokens), 8192 * 32);

        const GROQ_MAX_TOKENS_CAP = 512;
        const effectiveMaxTokens = provider === 'groq'
            ? Math.min(safeMax, GROQ_MAX_TOKENS_CAP)
            : safeMax;

        // ── Válasz mentése + session frissítése ──
        let isResponseSaved = false;
        async function saveResponse(aiContent, aiUsage, modelForLog, providerForLog) {
            if (isResponseSaved) return;
            isResponseSaved = true;
            const safeAiContent = stripAssistantThinking(aiContent);

            const aiMsgData = {
                role: 'assistant',
                content: safeAiContent,
                model: modelForLog,
                modelId: modelForLog,
                modelName,
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                createdAt: new Date().toISOString(),
                ...(aiUsage.total_tokens ? { usage: aiUsage } : {}),
            };

            if (assistantDocId) {
                await messagesRef.doc(assistantDocId).set(aiMsgData, { merge: true });
            } else {
                await messagesRef.add(aiMsgData);
            }

            const actualMessageCount = baseMessages.length + 1;

            await sessionRef.set({
                sessionId,
                modelId: modelForLog,
                modelName,
                lastMessage: typeof message === 'string' ? message.slice(0, 100) : '[kép]',
                lastRole: 'assistant',
                updatedAt: admin.firestore.FieldValue.serverTimestamp(),
                messageCount: actualMessageCount,
            }, { merge: true });

            const summaryResult = await refreshSessionSummary({
                userId,
                sessionId,
                modelId: modelForLog,
                allMessages: [...baseMessages, { role: 'assistant', content: safeAiContent }],
                sessionData: {
                    ...sessionData,
                    messageCount: actualMessageCount,
                },
            });

            return summaryResult;
        }

        // ── Anthropic ─────────────────────────────────────────────────────────
        if (provider === 'anthropic') {
            if (!process.env.ANTHROPIC_API_KEY) {
                return res.status(500).json({ success: false, message: 'ANTHROPIC_API_KEY nincs beállítva' });
            }

            const normalized = normalizeMessages(context);
            const systemMsg = normalized.find((m) => m.role === 'system');
            const chatMsgs = normalized.filter((m) => m.role !== 'system');

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            let totalContent = '';

            let usageInfo = { input_tokens: 0, output_tokens: 0 };
            let anthropicStreamClosed = false;
            const writeAnthropicSse = (payload) => {
                if (anthropicStreamClosed || res.writableEnded || res.destroyed) return false;
                res.write(`data: ${JSON.stringify(payload)}\n\n`);
                return true;
            };
            const finishAnthropicSse = () => {
                if (anthropicStreamClosed) return;
                anthropicStreamClosed = true;
                activeStreams.delete(streamKey);
                if (!res.writableEnded && !res.destroyed) res.end();
            };

            try {
                const stream = anthropic.messages.stream({
                    model: apiModel,
                    max_tokens: safeMax,
                    temperature: Math.min(Math.max(0, temperature), 1),
                    ...(systemMsg ? { system: systemMsg.content } : {}),
                    messages: chatMsgs,
                }, { abortSignal: signal });

                stream.on('message_start', (message) => {
                    if (message.message?.usage) {
                        usageInfo.input_tokens = message.message.usage.input_tokens || 0;
                    }
                });

                stream.on('text', (text) => {
                    if (anthropicStreamClosed || res.writableEnded || res.destroyed) return;
                    totalContent += text;
                    writeAnthropicSse({ delta: text });
                });

                stream.on('message_stop', (message) => {
                    if (message.message?.usage) {
                        usageInfo.output_tokens = message.message.usage.output_tokens || 0;
                    }
                });

                stream.on('end', async () => {
                    if (anthropicStreamClosed || res.writableEnded || res.destroyed) return;
                    if (totalContent.length > 0) {
                        try {
                            // Check if summary will be triggered
                            const totalMessages = (baseMessages?.length || 0) + 1;
                            if (totalMessages - (sessionData.summarizedMessageCount || 0) >= SUMMARY_TRIGGER_COUNT) {
                                writeAnthropicSse({ summaryStarted: true });
                            }

                            const finalUsage = {
                                input_tokens: usageInfo.input_tokens,
                                output_tokens: usageInfo.output_tokens,
                                prompt_tokens: usageInfo.input_tokens,
                                completion_tokens: usageInfo.output_tokens,
                                total_tokens: usageInfo.input_tokens + usageInfo.output_tokens
                            };
                            await logUsage(req.userId, 'chat', {
                                model: apiModel,
                                provider: 'anthropic',
                                ...finalUsage
                            });
                            const summaryResult = await saveResponse(totalContent, finalUsage, modelId, 'anthropic');
                            writeAnthropicSse({ summaryRefreshed: summaryResult?.summaryRefreshed || false });
                        } catch (e) {
                            console.error('[Chat] Anthropic mentés sikertelen:', e.message);

                        }
                    }
                    if (!anthropicStreamClosed && !res.writableEnded && !res.destroyed) res.write('data: [DONE]\n\n');
                    finishAnthropicSse();
                });

                stream.on('error', (err) => {
                    if (anthropicStreamClosed) return;
                    if (err.name === 'AbortError') {
                        console.log('[Anthropic] Stream leállítva.');
                    } else {
                        console.error('Anthropic stream hiba:', err);
                        writeAnthropicSse({ error: err.message || 'Anthropic stream hiba' });
                    }
                    finishAnthropicSse();
                });

            } catch (err) {
                console.error('Anthropic setup hiba:', err);
                if (!res.headersSent) {
                    activeStreams.delete(streamKey);
                    res.status(500).json({ success: false, message: err.message });
                } else {
                    writeAnthropicSse({ error: err.message || 'Anthropic setup hiba' });
                    finishAnthropicSse();
                }
            }
            return;
        }

        // ── OpenAI ────────────────────────────────────────────────────────────
        else if (provider === 'openai') {
            if (!process.env.OPENAI_API_KEY) {
                return res.status(500).json({ success: false, message: 'OPENAI_API_KEY nincs beállítva' });
            }

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            let totalContent = '';

            let usageInfo = null;

            try {
                const stream = await openai.chat.completions.create({
                    model: apiModel,
                    messages: normalizeMessages(context),
                    temperature: Math.min(Math.max(0, temperature), 2),
                    max_tokens: safeMax,
                    top_p: Math.min(Math.max(0, top_p), 1),
                    frequency_penalty: Math.min(Math.max(-2, frequency_penalty), 2),
                    presence_penalty: Math.min(Math.max(-2, presence_penalty), 2),
                    stream: true,
                    stream_options: { include_usage: true }
                }, { signal });

                for await (const chunk of stream) {
                    const delta = chunk.choices[0]?.delta?.content || '';
                    if (delta) {
                        totalContent += delta;
                        res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                    }
                    if (chunk.usage) {
                        usageInfo = chunk.usage;
                    }
                }

                if (totalContent.length > 0) {
                    try {
                        const totalMessages = (baseMessages?.length || 0) + 1;
                        if (totalMessages - (sessionData.summarizedMessageCount || 0) >= SUMMARY_TRIGGER_COUNT) {
                            res.write(`data: ${JSON.stringify({ summaryStarted: true })}\n\n`);
                        }

                        const finalUsage = usageInfo || {
                            prompt_tokens: 0,
                            completion_tokens: Math.ceil(totalContent.length / 4),
                            total_tokens: Math.ceil(totalContent.length / 4)
                        };

                        await logUsage(req.userId, 'chat', {
                            model: apiModel,
                            provider: 'openai',
                            ...finalUsage
                        });
                        const summaryResult = await saveResponse(totalContent, finalUsage, modelId, 'openai');
                        res.write(`data: ${JSON.stringify({ summaryRefreshed: summaryResult?.summaryRefreshed || false })}\n\n`);
                    } catch (e) {
                        console.error('[Chat] OpenAI mentés sikertelen:', e.message);
                    }
                }
                activeStreams.delete(streamKey);
                res.write('data: [DONE]\n\n');
                res.end();
            } catch (err) {
                activeStreams.delete(streamKey);
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[OpenAI] Stream leállítva.');
                } else {
                    console.error('OpenAI stream hiba:', err);
                    if (!res.writableEnded) {
                        res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                        res.end();
                    }
                }
            }
            return;
        }

        // ── Cerebras ─────────────────────────────────────────────────────────
        else if (provider === 'cerebras') {
            if (!process.env.CEREBRAS_API_KEY) {
                return res.status(500).json({ success: false, message: 'CEREBRAS_API_KEY nincs beállítva' });
            }

            const chatMsgs = normalizeMessages(context);

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            let streamResp;
            let totalContent = '';
            try {
                streamResp = await axios.post(
                    'https://api.cerebras.ai/v1/chat/completions',
                    {
                        model: apiModel,
                        messages: chatMsgs,
                        temperature: Math.min(Math.max(0, temperature), 1.5),
                        max_tokens: safeMax,
                        top_p: Math.min(Math.max(0, top_p), 1),
                        stream: true,
                        stream_options: { include_usage: true }
                    },
                    {
                        headers: {
                            'Authorization': `Bearer ${process.env.CEREBRAS_API_KEY}`,
                            'Content-Type': 'application/json',
                            'Accept-Encoding': 'identity',
                        },
                        responseType: 'stream',
                        decompress: false,
                        timeout: 60000,
                        signal,
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[Cerebras] Stream leállítva.');
                    return;
                }
                console.error('Cerebras hiba:', err.response?.data || err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

            let clientConnected = true;
            req.on('close', () => {
                clientConnected = false;
                if (!res.writableEnded) streamResp.data.destroy();
                saveResponse(totalContent, {}, modelId, 'cerebras').catch(e => console.error('[Chat] Cerebras abort-mentés sikertelen:', e.message));
            });

            let usageInfo = null;
            let buf = '';
            streamResp.data.on('data', (chunk) => {
                if (!clientConnected) return;
                buf += chunk.toString('utf8');
                const lines = buf.split('\n');
                buf = lines.pop();
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed.startsWith('data: ')) continue;
                    const raw = trimmed.slice(6);
                    if (raw === '[DONE]') continue;
                    try {
                        const parsed = JSON.parse(raw);
                        const delta = parsed.choices?.[0]?.delta?.content || '';
                        if (delta && clientConnected) {
                            totalContent += delta;
                            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                        }
                        if (parsed.usage) {
                            usageInfo = parsed.usage;
                        }
                    } catch { }
                }
            });

            streamResp.data.on('end', async () => {
                if (totalContent.length > 0) {
                    try {
                        const totalMessages = (baseMessages?.length || 0) + 1;
                        if (totalMessages - (sessionData.summarizedMessageCount || 0) >= SUMMARY_TRIGGER_COUNT) {
                            res.write(`data: ${JSON.stringify({ summaryStarted: true })}\n\n`);
                        }

                        const finalUsage = usageInfo || {
                            prompt_tokens: 0,
                            completion_tokens: Math.ceil(totalContent.length / 4),
                            total_tokens: Math.ceil(totalContent.length / 4)
                        };
                        await logUsage(req.userId, 'chat', {
                            model: apiModel,
                            provider: 'cerebras',
                            ...finalUsage
                        });
                        const summaryResult = await saveResponse(totalContent, finalUsage, modelId, 'cerebras');
                        res.write(`data: ${JSON.stringify({ summaryRefreshed: summaryResult?.summaryRefreshed || false })}\n\n`);
                    } catch (e) {
                        console.error('[Chat] Cerebras mentés sikertelen:', e.message);
                    }
                }
                activeStreams.delete(streamKey);
                res.write('data: [DONE]\n\n');
                res.end();
            });

            streamResp.data.on('error', () => {
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        // ── Mistral ───────────────────────────────────────────────────────────
        else if (provider === 'mistral') {
            if (!process.env.MISTRAL_API_KEY) {
                return res.status(500).json({ success: false, message: 'MISTRAL_API_KEY nincs beállítva' });
            }

            const chatMsgs = normalizeMessages(context);

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            let streamResp;
            let totalContent = '';
            try {
                streamResp = await axios.post(
                    'https://api.mistral.ai/v1/chat/completions',
                    {
                        model: apiModel,
                        messages: chatMsgs,
                        temperature: Math.min(Math.max(0, temperature), 1),
                        max_tokens: safeMax,
                        top_p: Math.min(Math.max(0, top_p), 1),
                        stream: true,
                        stream_options: { include_usage: true }
                    },
                    {
                        headers: {
                            'Authorization': `Bearer ${process.env.MISTRAL_API_KEY}`,
                            'Content-Type': 'application/json',
                            'Accept-Encoding': 'identity',
                        },
                        responseType: 'stream',
                        decompress: false,
                        timeout: 60000,
                        signal,
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[Mistral] Stream leállítva.');
                    return;
                }
                console.error('Mistral hiba:', err.response?.data || err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

            let clientConnected = true;
            req.on('close', () => {
                clientConnected = false;
                if (!res.writableEnded) streamResp.data.destroy();
                saveResponse(totalContent, {}, modelId, 'mistral').catch(e => console.error('[Chat] Mistral abort-mentés sikertelen:', e.message));
            });

            let usageInfo = null;
            let buf = '';
            streamResp.data.on('data', (chunk) => {
                if (!clientConnected) return;
                buf += chunk.toString('utf8');
                const lines = buf.split('\n');
                buf = lines.pop();
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed.startsWith('data: ')) continue;
                    const raw = trimmed.slice(6);
                    if (raw === '[DONE]') continue;
                    try {
                        const parsed = JSON.parse(raw);
                        const delta = parsed.choices?.[0]?.delta?.content || '';
                        if (delta && clientConnected) {
                            totalContent += delta;
                            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                        }
                        if (parsed.usage) {
                            usageInfo = parsed.usage;
                        }
                    } catch { }
                }
            });

            streamResp.data.on('end', async () => {
                if (totalContent.length > 0) {
                    try {
                        const totalMessages = (baseMessages?.length || 0) + 1;
                        if (totalMessages - (sessionData.summarizedMessageCount || 0) >= SUMMARY_TRIGGER_COUNT) {
                            res.write(`data: ${JSON.stringify({ summaryStarted: true })}\n\n`);
                        }

                        const finalUsage = usageInfo || {
                            prompt_tokens: 0,
                            completion_tokens: Math.ceil(totalContent.length / 4),
                            total_tokens: Math.ceil(totalContent.length / 4)
                        };
                        await logUsage(req.userId, 'chat', {
                            model: apiModel,
                            provider: 'mistral',
                            ...finalUsage
                        });
                        const summaryResult = await saveResponse(totalContent, finalUsage, modelId, 'mistral');
                        res.write(`data: ${JSON.stringify({ summaryRefreshed: summaryResult?.summaryRefreshed || false })}\n\n`);
                    } catch (e) {
                        console.error('[Chat] Mistral mentés sikertelen:', e.message);
                    }
                }
                activeStreams.delete(streamKey);
                res.write('data: [DONE]\n\n');
                res.end();
            });

            streamResp.data.on('error', () => {
                activeStreams.delete(streamKey);
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        // ── Groq ─────────────────────────────────────────────────────────────
        else if (provider === 'groq') {
            if (!process.env.GROQ_API_KEY) {
                return res.status(500).json({ success: false, message: 'GROQ_API_KEY nincs beállítva' });
            }

            const chatMsgs = normalizeMessages(context);

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            let streamResp;
            let totalContent = '';
            try {
                streamResp = await axios.post(
                    'https://api.groq.com/openai/v1/chat/completions',
                    {
                        model: apiModel,
                        messages: chatMsgs,
                        temperature: Math.min(Math.max(0, temperature), 2),
                        max_tokens: effectiveMaxTokens,
                        top_p: Math.min(Math.max(0, top_p), 1),
                        stream: true,
                        stream_options: { include_usage: true }
                    },
                    {
                        headers: {
                            'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
                            'Content-Type': 'application/json',
                        },
                        responseType: 'stream',
                        timeout: 60000,
                        signal,
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[Groq] Stream leállítva.');
                    return;
                }
                console.error('Groq hiba:', err.response?.data || err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

            let clientConnected = true;
            req.on('close', () => {
                clientConnected = false;
                if (!res.writableEnded) streamResp.data.destroy();
                saveResponse(totalContent, {}, modelId, 'groq').catch(e => console.error('[Chat] Groq abort-mentés sikertelen:', e.message));
            });

            let usageInfo = null;
            let buf = '';
            streamResp.data.on('data', (chunk) => {
                if (!clientConnected) return;
                buf += chunk.toString('utf8');
                const lines = buf.split('\n');
                buf = lines.pop();
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed.startsWith('data: ')) continue;
                    const raw = trimmed.slice(6);
                    if (raw === '[DONE]') continue;
                    try {
                        const parsed = JSON.parse(raw);
                        const delta = parsed.choices?.[0]?.delta?.content || '';
                        if (delta && clientConnected) {
                            totalContent += delta;
                            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                        }
                        if (parsed.usage) usageInfo = parsed.usage;
                    } catch { }
                }
            });

            streamResp.data.on('end', async () => {
                if (totalContent.length > 0) {
                    try {
                        const totalMessages = (baseMessages?.length || 0) + 1;
                        if (totalMessages - (sessionData.summarizedMessageCount || 0) >= SUMMARY_TRIGGER_COUNT) {
                            res.write(`data: ${JSON.stringify({ summaryStarted: true })}\n\n`);
                        }
                        const finalUsage = usageInfo || {
                            prompt_tokens: 0,
                            completion_tokens: Math.ceil(totalContent.length / 4),
                            total_tokens: Math.ceil(totalContent.length / 4)
                        };
                        const summaryResult = await saveResponse(totalContent, finalUsage, modelId, 'groq');
                        res.write(`data: ${JSON.stringify({ summaryRefreshed: summaryResult?.summaryRefreshed || false })}\n\n`);
                    } catch (e) {
                        console.error('[Chat] Groq mentés sikertelen:', e.message);
                    }
                }
                activeStreams.delete(streamKey);
                res.write('data: [DONE]\n\n');
                res.end();
            });

            streamResp.data.on('error', (err) => {
                activeStreams.delete(streamKey);
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        // ── Gemini ────────────────────────────────────────────────────────────
        else if (provider === 'gemini') {
            if (!process.env.GEMINI_API_KEY) {
                return res.status(500).json({ success: false, message: 'GEMINI_API_KEY nincs beállítva' });
            }

            const normalized = normalizeMessages(context);
            const systemMsg = normalized.find((m) => m.role === 'system');
            const contents = normalized
                .filter((m) => m.role !== 'system')
                .map((m) => ({
                    role: m.role === 'assistant' ? 'model' : 'user',
                    parts: toGeminiParts(m.content),
                }));

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            let streamResp;
            let totalContent = '';
            let usageInfo = null;

            const maxAttempts = modelId === 'gemini-2.5-pro' ? 4 : 2;
            for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
            try {
                streamResp = await axios.post(
                    `https://generativelanguage.googleapis.com/v1beta/models/${apiModel}:streamGenerateContent?alt=sse`,
                    {
                        contents,
                        ...(systemMsg ? { systemInstruction: { parts: [{ text: systemMsg.content }] } } : {}),
                        generationConfig: {
                            temperature: Math.min(Math.max(0, temperature), 2),
                            maxOutputTokens: safeMax,
                            topP: Math.min(Math.max(0, top_p), 1),
                        },
                    },
                    {
                        headers: {
                            'x-goog-api-key': process.env.GEMINI_API_KEY,
                            'Content-Type': 'application/json',
                        },
                        responseType: 'stream',
                        timeout: 60000,
                        signal,
                    }
                );
                break;
            } catch (err) {
                const details = await getAxiosErrorDetails(err);
                const canRetry = details.status === 429 && attempt < maxAttempts;
                if (canRetry) {
                    const fallbackWaitMs = Math.min(12000, (1200 * (2 ** (attempt - 1))) + Math.floor(Math.random() * 500));
                    const waitMs = getRetryAfterMs(err.response?.headers, fallbackWaitMs);
                    console.warn('[Gemini] 429, retrying chat request', {
                        model: apiModel,
                        attempt,
                        nextAttempt: attempt + 1,
                        waitMs,
                        code: details.code,
                    });
                    if (!res.writableEnded) {
                        res.write(`data: ${JSON.stringify({
                            retry: true,
                            provider: 'gemini',
                            attempt: attempt + 1,
                            maxAttempts,
                            waitMs,
                            code: details.code,
                            message: details.message,
                        })}\n\n`);
                    }
                    await sleep(waitMs);
                    continue;
                }
                if (details.status === 429) {
                    activeStreams.delete(streamKey);
                    const codeText = details.code ? ` (${details.code})` : '';
                    const userMessage = `Gemini HTTP 429${codeText}: The global quota or token rate limit for ${apiModel} has been reached. Please try another model or try again later.`;
                    console.error('[Gemini] Chat request rate limited:', {
                        model: apiModel,
                        code: details.code,
                        message: details.message,
                    });
                    res.write(`data: ${JSON.stringify({ error: userMessage })}\n\n`);
                    return res.end();
                }
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[Gemini] Stream leállítva.');
                    return;
                }
                console.error('Gemini kapcsolódási hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }
            }

            let clientConnected = true;
            req.on('close', () => {
                clientConnected = false;
                if (!res.writableEnded) streamResp.data.destroy();
                saveResponse(totalContent, {}, modelId, 'gemini').catch(e => console.error('[Chat] Gemini abort-mentés sikertelen:', e.message));
            });

            let buf = '';
            streamResp.data.on('data', (chunk) => {
                if (!clientConnected) return;
                buf += chunk.toString('utf8');
                const lines = buf.split('\n');
                buf = lines.pop();
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed.startsWith('data: ')) continue;
                    const raw = trimmed.slice(6);
                    try {
                        const parsed = JSON.parse(raw);
                        const delta = parsed.candidates?.[0]?.content?.parts?.[0]?.text || '';
                        if (delta && clientConnected) {
                            totalContent += delta;
                            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                        }
                        if (parsed.usageMetadata) {
                            usageInfo = {
                                prompt_tokens: parsed.usageMetadata.promptTokenCount || 0,
                                completion_tokens: parsed.usageMetadata.candidatesTokenCount || 0,
                                total_tokens: parsed.usageMetadata.totalTokenCount || 0,
                                cached_tokens: parsed.usageMetadata.cachedContentTokenCount || 0
                            };
                        }
                    } catch { }
                }
            });

            streamResp.data.on('end', async () => {
                if (totalContent.length > 0) {
                    try {
                        const totalMessages = (baseMessages?.length || 0) + 1;
                        if (totalMessages - (sessionData.summarizedMessageCount || 0) >= SUMMARY_TRIGGER_COUNT) {
                            res.write(`data: ${JSON.stringify({ summaryStarted: true })}\n\n`);
                        }

                        const finalUsage = usageInfo || {
                            prompt_tokens: 0,
                            completion_tokens: Math.ceil(totalContent.length / 4),
                            total_tokens: Math.ceil(totalContent.length / 4)
                        };
                        await logUsage(req.userId, 'chat', {
                            model: apiModel,
                            provider: 'gemini',
                            ...finalUsage
                        });
                        const summaryResult = await saveResponse(totalContent, finalUsage, modelId, 'gemini');
                        res.write(`data: ${JSON.stringify({ summaryRefreshed: summaryResult?.summaryRefreshed || false })}\n\n`);
                    } catch (e) {
                        console.error('[Chat] Gemini mentés sikertelen:', e.message);
                    }
                }
                res.write('data: [DONE]\n\n');
                res.end();
            });

            streamResp.data.on('error', (err) => {
                console.error('Gemini stream hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        // ── NVIDIA ────────────────────────────────────────────────────────────
        else if (provider === 'nvidia') {
            if (!process.env.NVIDIA_API_KEY) {
                return res.status(500).json({ success: false, message: 'NVIDIA_API_KEY nincs beállítva' });
            }

            const nvidiaMsgs = normalizeMessages(context);

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();


            let streamResp;
            let totalContent = '';
            let usageInfo = null;

            try {
                streamResp = await axios.post(
                    'https://integrate.api.nvidia.com/v1/chat/completions',
                    {
                        model: apiModel,
                        messages: nvidiaMsgs,
                        temperature: Math.min(Math.max(0, temperature), 2),
                        max_tokens: safeMax,
                        top_p: Math.min(Math.max(0, top_p), 1),
                        stream: true,
                        stream_options: { include_usage: true },
                        chat_template_kwargs: { enable_thinking: false }
                    },
                    {
                        headers: {
                            'Authorization': `Bearer ${process.env.NVIDIA_API_KEY}`,
                            'Content-Type': 'application/json',
                            'Accept': 'text/event-stream'
                        },
                        responseType: 'stream',
                        timeout: 300000,
                        signal,
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[NVIDIA] Stream leállítva.');
                    return;
                }
                console.error('NVIDIA kapcsolódási hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

            const keepAlive = setInterval(() => { if (!res.writableEnded) res.write(': ping\n\n'); }, 15000);

            let clientConnected = true;
            let hasReasoningStarted = false;

            req.on('close', () => {
                clientConnected = false;
                clearInterval(keepAlive);
                if (!res.writableEnded) streamResp.data.destroy();
                saveResponse(totalContent, {}, modelId, 'nvidia').catch(e => console.error('[Chat] NVIDIA abort-mentés sikertelen:', e.message));
            });

            let buf = '';
            streamResp.data.on('data', (chunk) => {
                if (!clientConnected) return;
                buf += chunk.toString('utf8');
                const lines = buf.split('\n');
                buf = lines.pop(); // Maradék a következő darabhoz
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed.startsWith('data: ')) continue;
                    const raw = trimmed.slice(6);
                    if (raw === '[DONE]') continue;
                    try {
                        const parsed = JSON.parse(raw);
                        const deltaObj = parsed.choices?.[0]?.delta || {};

                        let deltaOut = '';

                        // Ha kapunk gondolkodási fázist (NVIDIA / DeepSeek reasoning_content)
                        if (deltaObj.reasoning_content) {
                            if (!hasReasoningStarted) {
                                hasReasoningStarted = true;
                                deltaOut += '```thinking\n'; // Opcionális formázás a UI-nak
                            }
                            deltaOut += deltaObj.reasoning_content;
                        }

                        if (deltaObj.content) {
                            if (hasReasoningStarted) {
                                hasReasoningStarted = false;
                                deltaOut += '\n```\n'; // Lezárjuk a blokkot
                            }
                            deltaOut += deltaObj.content;
                        }

                        if (deltaOut && clientConnected) {
                            totalContent += deltaOut;
                            res.write(`data: ${JSON.stringify({ delta: deltaOut })}\n\n`);
                        }

                        if (parsed.usage) {
                            usageInfo = parsed.usage;
                        }
                    } catch { }
                }
            });

            streamResp.data.on('end', async () => {
                if (totalContent.length > 0) {
                    try {
                        const totalMessages = (baseMessages?.length || 0) + 1;
                        if (totalMessages - (sessionData.summarizedMessageCount || 0) >= SUMMARY_TRIGGER_COUNT) {
                            res.write(`data: ${JSON.stringify({ summaryStarted: true })}\n\n`);
                        }

                        const finalUsage = usageInfo || {
                            prompt_tokens: 0,
                            completion_tokens: Math.ceil(totalContent.length / 4),
                            total_tokens: Math.ceil(totalContent.length / 4)
                        };
                        await logUsage(req.userId, 'chat', { model: apiModel, provider: 'nvidia', ...finalUsage });
                        const summaryResult = await saveResponse(totalContent, finalUsage, modelId, 'nvidia');
                        res.write(`data: ${JSON.stringify({ summaryRefreshed: summaryResult?.summaryRefreshed || false })}\n\n`);
                    } catch (e) {
                        console.error('[Chat] NVIDIA mentés sikertelen:', e.message);
                    }
                }
                activeStreams.delete(streamKey);
                clearInterval(keepAlive);
                res.write('data: [DONE]\n\n');
                res.end();
            });

            streamResp.data.on('error', (err) => {
                activeStreams.delete(streamKey);
                clearInterval(keepAlive);
                console.error('NVIDIA stream hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        // -- ModelScope chat (OpenAI-compatible) ------------------------------
        else if (provider === 'modelscope-chat') {
            if (!process.env.MODELSCOPE_API_KEY) {
                return res.status(500).json({ success: false, message: 'MODELSCOPE_API_KEY nincs beallitva' });
            }

            const chatMsgs = normalizeMessages(context);

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            let streamResp;
            let totalContent = '';
            let usageInfo = null;

            const modelScopeBody = {
                model: apiModel,
                messages: chatMsgs,
                temperature: Math.min(Math.max(0, temperature), 2),
                max_tokens: safeMax,
                top_p: Math.min(Math.max(0, top_p), 1),
                stream: true,
            };
            const modelScopeConfig = {
                headers: {
                    Authorization: `Bearer ${process.env.MODELSCOPE_API_KEY}`,
                    'Content-Type': 'application/json',
                    Accept: 'text/event-stream',
                },
                responseType: 'stream',
                timeout: 300000,
                signal,
            };

            const maxAttempts = 5;
            for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
                try {
                    streamResp = await axios.post(
                        'https://api-inference.modelscope.ai/v1/chat/completions',
                        modelScopeBody,
                        modelScopeConfig
                    );
                    break;
                } catch (err) {
                    if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                        console.log('[ModelScope] Stream leallitva.');
                        return;
                    }

                    const details = await getAxiosErrorDetails(err);
                    const canRetry = details.status === 429 && attempt < maxAttempts;
                    if (canRetry) {
                        const fallbackWaitMs = Math.min(12000, (1000 * (2 ** (attempt - 1))) + Math.floor(Math.random() * 500));
                        const waitMs = getRetryAfterMs(err.response?.headers, fallbackWaitMs);
                        console.warn('[ModelScope] 429, retrying chat request', {
                            model: apiModel,
                            attempt,
                            nextAttempt: attempt + 1,
                            waitMs,
                            code: details.code,
                        });
                        if (!res.writableEnded) {
                            res.write(`data: ${JSON.stringify({
                                retry: true,
                                provider: 'modelscope-chat',
                                attempt: attempt + 1,
                                maxAttempts,
                                waitMs,
                                code: details.code,
                                message: details.message,
                            })}\n\n`);
                        }
                        await sleep(waitMs);
                        continue;
                    }

                    activeStreams.delete(streamKey);
                    const statusText = details.status ? `HTTP ${details.status}` : 'request failed';
                    const codeText = details.code ? ` (${details.code})` : '';
                    const userMessage = `ModelScope ${statusText}${codeText}: ${details.message}`;
                    console.error('[ModelScope] Chat request failed:', {
                        model: apiModel,
                        status: details.status,
                        code: details.code,
                        message: details.message,
                    });
                    res.write(`data: ${JSON.stringify({ error: userMessage })}\n\n`);
                    return res.end();
                }
            }

            const keepAlive = setInterval(() => { if (!res.writableEnded) res.write(': ping\n\n'); }, 15000);
            let clientConnected = true;
            let hasReasoningStarted = false;

            const closeReasoningBlock = () => {
                if (!hasReasoningStarted) return '';
                hasReasoningStarted = false;
                return '\n```\n';
            };

            req.on('close', () => {
                clientConnected = false;
                clearInterval(keepAlive);
                if (!res.writableEnded) streamResp.data.destroy();
                saveResponse(totalContent, {}, modelId, 'modelscope-chat').catch(e => console.error('[Chat] ModelScope abort-mentes sikertelen:', e.message));
            });

            let buf = '';
            streamResp.data.on('data', (chunk) => {
                if (!clientConnected) return;
                buf += chunk.toString('utf8');
                const lines = buf.split('\n');
                buf = lines.pop();
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed.startsWith('data: ')) continue;
                    const raw = trimmed.slice(6);
                    if (raw === '[DONE]') continue;
                    try {
                        const parsed = JSON.parse(raw);
                        if (parsed.error) {
                            const message = parsed.error.message || 'ModelScope stream hiba';
                            res.write(`data: ${JSON.stringify({ error: message })}\n\n`);
                            continue;
                        }

                        const deltaObj = parsed.choices?.[0]?.delta || {};
                        const reasoningChunk = deltaObj.reasoning_content;
                        const answerChunk = deltaObj.content;
                        let deltaOut = '';

                        if (reasoningChunk !== undefined && reasoningChunk !== null && reasoningChunk !== '') {
                            if (!hasReasoningStarted) {
                                hasReasoningStarted = true;
                                deltaOut += '```thinking\n';
                            }
                            deltaOut += reasoningChunk;
                        }

                        if (answerChunk !== undefined && answerChunk !== null && answerChunk !== '') {
                            deltaOut += closeReasoningBlock();
                            deltaOut += answerChunk;
                        }

                        if (deltaOut && clientConnected) {
                            totalContent += deltaOut;
                            res.write(`data: ${JSON.stringify({ delta: deltaOut })}\n\n`);
                        }

                        if (parsed.usage) {
                            usageInfo = parsed.usage;
                        }
                    } catch { }
                }
            });

            streamResp.data.on('end', async () => {
                if (hasReasoningStarted) {
                    const closing = closeReasoningBlock();
                    totalContent += closing;
                    if (!res.writableEnded) res.write(`data: ${JSON.stringify({ delta: closing })}\n\n`);
                }

                if (totalContent.length > 0) {
                    try {
                        const totalMessages = (baseMessages?.length || 0) + 1;
                        if (totalMessages - (sessionData.summarizedMessageCount || 0) >= SUMMARY_TRIGGER_COUNT) {
                            res.write(`data: ${JSON.stringify({ summaryStarted: true })}\n\n`);
                        }

                        const finalUsage = usageInfo || {
                            prompt_tokens: 0,
                            completion_tokens: Math.ceil(totalContent.length / 4),
                            total_tokens: Math.ceil(totalContent.length / 4)
                        };
                        await logUsage(req.userId, 'chat', { model: apiModel, provider: 'modelscope-chat', ...finalUsage });
                        const summaryResult = await saveResponse(totalContent, finalUsage, modelId, 'modelscope-chat');
                        res.write(`data: ${JSON.stringify({ summaryRefreshed: summaryResult?.summaryRefreshed || false })}\n\n`);
                    } catch (e) {
                        console.error('[Chat] ModelScope mentes sikertelen:', e.message);
                    }
                }

                activeStreams.delete(streamKey);
                clearInterval(keepAlive);
                res.write('data: [DONE]\n\n');
                res.end();
            });

            streamResp.data.on('error', (err) => {
                activeStreams.delete(streamKey);
                clearInterval(keepAlive);
                console.error('ModelScope stream hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        // ── OpenRouter ────────────────────────────────────────────────────────
        else if (provider === 'openrouter') {
            if (!process.env.OPENROUTER_API_KEY) {
                return res.status(500).json({ success: false, message: 'OPENROUTER_API_KEY nincs beállítva' });
            }

            const chatMsgs = normalizeMessages(context);

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            let streamResp;
            let totalContent = '';
            let usageInfo = null;

            try {
                streamResp = await axios.post(
                    'https://openrouter.ai/api/v1/chat/completions',
                    {
                        model: apiModel,
                        messages: chatMsgs,
                        temperature: Math.min(Math.max(0, temperature), 2),
                        max_tokens: safeMax,
                        top_p: Math.min(Math.max(0, top_p), 1),
                        stream: true,
                        stream_options: { include_usage: true }
                    },
                    {
                        headers: {
                            Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
                            'Content-Type': 'application/json',
                            'HTTP-Referer': process.env.SITE_URL || 'http://localhost:5173',
                            'X-Title': 'AI Chat App',
                        },
                        httpsAgent,
                        responseType: 'stream',
                        timeout: 120000,
                        signal,
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[OpenRouter] Stream leállítva.');
                    return;
                }
                activeStreams.delete(streamKey);
                const details = await getAxiosErrorDetails(err);
                const statusText = details.status ? `HTTP ${details.status}` : 'request failed';
                const codeText = details.code ? ` (${details.code})` : '';
                const userMessage = `OpenRouter ${statusText}${codeText}: ${details.message}`;
                console.error('[OpenRouter] Chat request failed:', {
                    model: apiModel,
                    status: details.status,
                    code: details.code,
                    message: details.message,
                });
                res.write(`data: ${JSON.stringify({ error: userMessage })}\n\n`);
                return res.end();
            }

            let clientConnected = true;
            req.on('close', () => {
                clientConnected = false;
                if (!res.writableEnded) streamResp.data.destroy();
                saveResponse(totalContent, {}, modelId, 'openrouter').catch(e => console.error('[Chat] OpenRouter abort-mentés sikertelen:', e.message));
            });

            let buf = '';
            streamResp.data.on('data', (chunk) => {
                if (!clientConnected) return;
                buf += chunk.toString('utf8');
                const lines = buf.split('\n');
                buf = lines.pop();
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (!trimmed.startsWith('data: ')) continue;
                    const raw = trimmed.slice(6);
                    if (raw === '[DONE]') continue;
                    try {
                        const parsed = JSON.parse(raw);
                        if (parsed.error) {
                            const message = parsed.error.message || parsed.error || 'OpenRouter stream hiba';
                            res.write(`data: ${JSON.stringify({ error: message })}\n\n`);
                            continue;
                        }
                        const delta = parsed.choices?.[0]?.delta?.content || '';
                        if (delta && clientConnected) {
                            totalContent += delta;
                            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                        }
                        if (parsed.usage) {
                            usageInfo = parsed.usage;
                        }
                    } catch { }
                }
            });

            streamResp.data.on('end', async () => {
                if (totalContent.length > 0) {
                    try {
                        const totalMessages = (baseMessages?.length || 0) + 1;
                        if (totalMessages - (sessionData.summarizedMessageCount || 0) >= SUMMARY_TRIGGER_COUNT) {
                            res.write(`data: ${JSON.stringify({ summaryStarted: true })}\n\n`);
                        }

                        const finalUsage = usageInfo || {
                            prompt_tokens: 0,
                            completion_tokens: Math.ceil(totalContent.length / 4),
                            total_tokens: Math.ceil(totalContent.length / 4)
                        };
                        await logUsage(req.userId, 'chat', { model: apiModel, provider: 'openrouter', ...finalUsage });
                        const summaryResult = await saveResponse(totalContent, finalUsage, modelId, 'openrouter');
                        res.write(`data: ${JSON.stringify({ summaryRefreshed: summaryResult?.summaryRefreshed || false })}\n\n`);
                    } catch (e) {
                        console.error('[Chat] OpenRouter mentés sikertelen:', e.message);
                    }
                }
                activeStreams.delete(streamKey);
                res.write('data: [DONE]\n\n');
                res.end();
            });

            streamResp.data.on('error', (err) => {
                activeStreams.delete(streamKey);
                console.error('OpenRouter stream hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

        } else {
            return res.status(400).json({ success: false, message: `Ismeretlen provider: ${provider}` });
        }
    } catch (err) {
        console.error('❌ Chat hiba:', err);
        if (!res.headersSent) {
            return res.status(500).json({
                success: false,
                message: err?.status === 429
                    ? 'API rate limit — próbáld újra pár perc múlva'
                    : err?.message || 'Chat hiba',
            });
        }
    }
});

// ── FINALIZE ──────────────────────────────────────────────────────────────────
router.post('/chat/finalize', verifyFirebaseToken, async (req, res) => {
    try {
        const { sessionId, messageId, content } = req.body;
        const userId = req.userId;

        if (!sessionId || !messageId) {
            return res.status(400).json({ success: false, message: 'Hiányzó adatok' });
        }

        const adminDb = admin.firestore();
        const msgRef = adminDb
            .collection('conversations')
            .doc(userId)
            .collection('sessions')
            .doc(sessionId)
            .collection('messages')
            .doc(messageId);

        const safeContent = stripAssistantThinking(content);
        const charCount = safeContent.length || 0;
        const estimatedTokens = Math.ceil(charCount / 4);

        await msgRef.set({
            content: safeContent,
            usage: {
                output_tokens: estimatedTokens,
                total_tokens: estimatedTokens
            },
            finalizedByFrontend: true,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        return res.json({ success: true, message: 'Üzenet szinkronizálva' });
    } catch (err) {
        console.error('❌ Finalize hiba:', err.message);
        return res.status(500).json({ success: false, message: err.message });
    }
});

// ── STOP ──────────────────────────────────────────────────────────────────────
router.post('/chat/stop', verifyFirebaseToken, async (req, res) => {
    try {
        const { sessionId } = req.body;
        const userId = req.userId;

        if (!sessionId) {
            return res.status(400).json({ success: false, message: 'Hiányzó sessionId' });
        }

        const streamKey = `${userId}:${sessionId}`;
        const controller = activeStreams.get(streamKey);

        if (controller) {
            console.log(`[Chat] Stop: session ${sessionId}. Stream leállítva.`);
            controller.abort();
            activeStreams.delete(streamKey);
            return res.json({ success: true, message: 'Adatfolyam leállítva' });
        } else {
            return res.json({ success: true, message: 'Nincs aktív adatfolyam' });
        }
    } catch (err) {
        console.error('❌ Stop hiba:', err.message);
        return res.status(500).json({ success: false, message: err.message });
    }
});

// ── ENHANCE ───────────────────────────────────────────────────────────────────
// FIX: optimizedMessages → messages
router.post('/enhance', verifyFirebaseToken, chatLimiter, async (req, res) => {
    try {
        const {
            model,
            provider,
            messages,
            temperature = 0.7,
            max_tokens = 2048,
            top_p = 0.9,
            frequency_penalty = 0,
            presence_penalty = 0,
        } = req.body;

        if (!model || !provider) {
            return res.status(400).json({ success: false, message: 'Hiányzó model / provider' });
        }
        if (!Array.isArray(messages) || messages.length === 0) {
            return res.status(400).json({ success: false, message: 'Érvénytelen üzenetlista' });
        }
        if (messages.length > 50) {
            return res.status(400).json({ success: false, message: 'Max 50 üzenet per kérés' });
        }
        if (!process.env.GROQ_API_KEY) {
            return res.status(500).json({ success: false, message: 'GROQ_API_KEY nincs beállítva' });
        }

        const isReasoningModel = model.includes('gpt-oss') || model.includes('deepseek-r1') || model.includes('qwq');
        const tokenCap = isReasoningModel ? 16384 : 1024;
        const safeMax = Math.min(Math.max(128, max_tokens), tokenCap);

        // FIX: messages helyesen átadva (nem optimizedMessages)
        const chatMsgs = normalizeMessages(messages);

        let resp;
        try {
            const body = {
                model,
                messages: chatMsgs,
                stream: false,
            };

            if (isReasoningModel) {
                body.max_completion_tokens = safeMax;
            } else {
                body.temperature = Math.min(Math.max(0, temperature), 2);
                body.max_tokens = safeMax;
                body.top_p = Math.min(Math.max(0, top_p), 1);
                body.frequency_penalty = Math.min(Math.max(-2, frequency_penalty), 2);
                body.presence_penalty = Math.min(Math.max(-2, presence_penalty), 2);
            }

            resp = await groqWithRetry(body);
        } catch (err) {
            const msg = err.response?.data?.error?.message || err.message || 'Groq API hiba';
            console.error('❌ Groq API hiba:', msg);
            return res.status(err.response?.status || 500).json({ success: false, message: msg });
        }

        const choice0 = resp.data?.choices?.[0];
        const content = choice0?.message?.content ?? '';

        if (!content) {
            console.warn('⚠️ Groq üres válasz, finish_reason:', choice0?.finish_reason);
        }

        const usage = {
            input_tokens: resp.data?.usage?.prompt_tokens || 0,
            output_tokens: resp.data?.usage?.completion_tokens || 0,
            total_tokens: resp.data?.usage?.total_tokens || 0,
        };

        await logUsage(req.userId, 'chat', { model, provider: 'groq', tokens: usage.total_tokens });

        return res.json({ success: true, content, usage });

    } catch (err) {
        console.error('❌ Enhance hiba:', err);
        if (!res.headersSent) {
            return res.status(500).json({
                success: false,
                message: err?.status === 429
                    ? 'Groq rate limit — próbáld újra pár perc múlva'
                    : err?.message || 'Enhance hiba',
            });
        }
    }
});

// ── VISION DESCRIBE ───────────────────────────────────────────────────────────
router.post('/vision-describe', verifyFirebaseToken, async (req, res) => {
    try {
        const { images, systemPrompt } = req.body;

        if (!Array.isArray(images) || images.length === 0) {
            return res.status(400).json({ success: false, message: 'Nincs kép megadva' });
        }
        if (images.length > 3) {
            return res.status(400).json({ success: false, message: 'Max 3 kép engedélyezett' });
        }
        if (!process.env.NVIDIA_API_KEY) {
            return res.status(500).json({ success: false, message: 'NVIDIA_API_KEY nincs beállítva' });
        }

        const userContentBlocks = [
            { type: 'text', text: systemPrompt || 'Describe the uploaded image(s) in detail.' },
            ...images.map((dataUrl) => ({
                type: 'image_url',
                image_url: { url: dataUrl },
            })),
        ];

        let resp;
        try {
            resp = await axios.post(
                'https://integrate.api.nvidia.com/v1/chat/completions',
                {
                    model: 'google/gemma-3-27b-it',
                    messages: [{ role: 'user', content: userContentBlocks }],
                    max_tokens: 1500,
                    temperature: 0.2,
                    top_p: 0.7,
                    stream: false,
                },
                {
                    headers: {
                        Authorization: `Bearer ${process.env.NVIDIA_API_KEY}`,
                        'Content-Type': 'application/json',
                    },
                    timeout: 90000,
                }
            );
        } catch (err) {
            const msg = err.response?.data?.message || err.response?.data?.detail || err.message || 'NVIDIA API hiba';
            console.error('Vision describe NVIDIA hiba:', msg);
            return res.status(502).json({ success: false, message: `NVIDIA API hiba: ${msg}` });
        }

        const description = resp.data?.choices?.[0]?.message?.content?.trim() || '';
        if (!description) {
            return res.status(500).json({ success: false, message: 'Gemma üres választ adott vissza' });
        }

        await logUsage(req.userId, 'vision-describe', {
            model: 'google/gemma-3-27b-it',
            provider: 'nvidia',
            tokens: resp.data?.usage?.total_tokens || 0,
            images: images.length,
        });

        return res.json({ success: true, description });
    } catch (err) {
        console.error('❌ Vision describe hiba:', err);
        if (!res.headersSent) {
            return res.status(500).json({ success: false, message: err?.message || 'Vision describe hiba' });
        }
    }
});

// ── Kontext preferált felbontások ─────────────────────────────────────────────
const KONTEXT_PREFERRED_RESOLUTIONS = [
    [672, 1568], [688, 1504], [720, 1456], [752, 1392], [800, 1328],
    [832, 1248], [880, 1184], [944, 1104], [1024, 1024], [1104, 944],
    [1184, 880], [1248, 832], [1328, 800], [1392, 752], [1456, 720],
    [1504, 688], [1568, 672],
];

function snapToKontextResolution(origW, origH) {
    const origAR = origW / origH;
    let best = KONTEXT_PREFERRED_RESOLUTIONS[0];
    let bestDiff = Infinity;
    for (const [w, h] of KONTEXT_PREFERRED_RESOLUTIONS) {
        const diff = Math.abs(w / h - origAR);
        if (diff < bestDiff) { bestDiff = diff; best = [w, h]; }
    }
    return { w: best[0], h: best[1] };
}

function parseImageDataUrl(dataUrl, fieldName) {
    if (typeof dataUrl !== 'string') {
        throw new Error(`${fieldName} must be a data URL`);
    }
    const match = /^data:(image\/(?:png|jpeg|jpg|webp));base64,([A-Za-z0-9+/=]+)$/i.exec(dataUrl);
    if (!match) {
        throw new Error(`${fieldName} must be a base64 PNG, JPG, or WebP data URL`);
    }
    const mime = match[1].toLowerCase().replace('image/jpg', 'image/jpeg');
    const buffer = Buffer.from(match[2], 'base64');
    if (!buffer.length) {
        throw new Error(`${fieldName} is empty`);
    }
    return { mime, buffer };
}

function clampTextureEditDimension(value, fallback = 1024) {
    const n = Number(value);
    if (!Number.isFinite(n) || n <= 0) return fallback;
    return Math.max(512, Math.min(2048, Math.round(n / 16) * 16));
}

function getOpenAITextureEditSize(model, width, height) {
    if (String(model || '').startsWith('gpt-image-2')) {
        return `${width}x${height}`;
    }
    if (Math.abs(width - height) <= 16) return '1024x1024';
    return width > height ? '1536x1024' : '1024x1536';
}

async function getSelectionAlphaFromMask(maskPng, width, height) {
    const { data } = await sharp(maskPng)
        .resize(width, height, { fit: 'fill', kernel: 'nearest' })
        .ensureAlpha()
        .raw()
        .toBuffer({ resolveWithObject: true });

    const alpha = Buffer.alloc(width * height);
    for (let i = 0, p = 0; i < data.length; i += 4, p += 1) {
        const selected = 255 - data[i + 3];
        alpha[p] = selected > 8 ? 255 : 0;
    }
    return alpha;
}

async function createTexturePaintGuide(basePng, selectionAlpha, width, height) {
    const overlay = Buffer.alloc(width * height * 4);
    for (let p = 0, i = 0; p < selectionAlpha.length; p += 1, i += 4) {
        overlay[i] = 139;
        overlay[i + 1] = 92;
        overlay[i + 2] = 246;
        overlay[i + 3] = selectionAlpha[p] ? 190 : 0;
    }
    const overlayPng = await sharp(overlay, { raw: { width, height, channels: 4 } })
        .png({ compressionLevel: 6 })
        .toBuffer();

    return sharp(basePng)
        .resize(width, height, { fit: 'fill', kernel: 'lanczos3' })
        .composite([{ input: overlayPng, blend: 'over' }])
        .png({ compressionLevel: 6 })
        .toBuffer();
}

async function blendEditedTextureIntoSelection(basePng, editedPng, selectionAlpha, width, height) {
    const base = await sharp(basePng)
        .resize(width, height, { fit: 'fill', kernel: 'lanczos3' })
        .ensureAlpha()
        .raw()
        .toBuffer();
    const edited = await sharp(editedPng)
        .resize(width, height, { fit: 'fill', kernel: 'lanczos3' })
        .ensureAlpha()
        .raw()
        .toBuffer();

    const out = Buffer.alloc(base.length);
    for (let p = 0, i = 0; p < selectionAlpha.length; p += 1, i += 4) {
        const a = selectionAlpha[p] / 255;
        const inv = 1 - a;
        out[i] = Math.round(base[i] * inv + edited[i] * a);
        out[i + 1] = Math.round(base[i + 1] * inv + edited[i + 1] * a);
        out[i + 2] = Math.round(base[i + 2] * inv + edited[i + 2] * a);
        out[i + 3] = base[i + 3];
    }

    return sharp(out, { raw: { width, height, channels: 4 } })
        .png({ compressionLevel: 6 })
        .toBuffer();
}

async function uploadModelScopeTextureInput(buffer, req, label, tempB2Keys) {
    const filename = `texture_paint_${Date.now()}_${label}_${req.userId.slice(0, 8)}.png`;
    const tempKey = `temp_edit/${filename}`;
    tempB2Keys.push(tempKey);

    await b2.send(new PutObjectCommand({
        Bucket: process.env.B2_BUCKET_NAME,
        Key: tempKey,
        Body: buffer,
        ContentType: 'image/png',
    }));

    return getSignedUrl(
        b2,
        new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: tempKey }),
        { expiresIn: 600 },
    );
}

async function runModelScopeTexturePaintEdit({ req, basePng, maskPng, cleanPrompt, width, height }) {
    if (!process.env.MODELSCOPE_API_KEY) {
        throw new Error('MODELSCOPE_API_KEY nincs beállítva.');
    }

    const tempB2Keys = [];
    const cleanup = async () => {
        for (const key of tempB2Keys) {
            try { await b2.send(new DeleteObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key })); } catch { }
        }
    };

    try {
        const selectionAlpha = await getSelectionAlphaFromMask(maskPng, width, height);
        if (!selectionAlpha.some((value) => value > 0)) {
            throw new Error('A festési maszk üres.');
        }

        const guidePng = await createTexturePaintGuide(basePng, selectionAlpha, width, height);
        const guideUrl = await uploadModelScopeTextureInput(guidePng, req, 'guide', tempB2Keys);
        const apiId = process.env.MODELSCOPE_TEXTURE_EDIT_MODEL || 'Qwen/Qwen-Image-Edit-2511';
        const texturePrompt = [
            'This is a UV texture map for a 3D model.',
            'The purple painted guide marks show the exact area to replace.',
            'Edit only those purple marked pixels according to the instruction.',
            'Return a clean UV texture map without purple guide paint, borders, labels, new UV islands, or global restyling.',
            'Keep every unmarked area visually unchanged.',
            `Instruction: ${cleanPrompt}`,
        ].join(' ');

        const genResp = await fetch('https://api-inference.modelscope.ai/v1/images/generations', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${process.env.MODELSCOPE_API_KEY}`,
                'Content-Type': 'application/json',
                'X-ModelScope-Async-Mode': 'true',
            },
            body: JSON.stringify({
                model: apiId,
                prompt: texturePrompt,
                steps: 28,
                guidance: 4.5,
                image_url: [guideUrl],
            }),
            signal: AbortSignal.timeout(30000),
        });

        const genData = await genResp.json();
        if (!genResp.ok) {
            throw new Error(`ModelScope hiba: ${JSON.stringify(genData?.errors || genData).slice(0, 240)}`);
        }

        let outputUrl = genData.output_images?.[0] || null;
        const taskId = genData.task_id || null;
        if (!outputUrl && !taskId) {
            throw new Error('ModelScope: ismeretlen válasz.');
        }

        if (!outputUrl) {
            for (let i = 0; i < 150; i += 1) {
                await new Promise((resolve) => setTimeout(resolve, i === 0 ? 2000 : 3000));
                const pollResp = await fetch(`https://api-inference.modelscope.ai/v1/tasks/${taskId}`, {
                    headers: {
                        Authorization: `Bearer ${process.env.MODELSCOPE_API_KEY}`,
                        'X-ModelScope-Task-Type': 'image_generation',
                    },
                    signal: AbortSignal.timeout(15000),
                });
                const pollData = await pollResp.json();
                const status = pollData?.task_status;
                if (status === 'SUCCEED') {
                    outputUrl = pollData?.output_images?.[0] || null;
                    break;
                }
                if (status === 'FAILED') {
                    throw new Error('ModelScope texture edit sikertelen.');
                }
            }
        }

        if (!outputUrl) {
            throw new Error('ModelScope texture edit időtúllépés.');
        }

        const editedResponse = await fetch(outputUrl, { signal: AbortSignal.timeout(60000) });
        if (!editedResponse.ok) {
            throw new Error(`ModelScope output letöltése sikertelen: ${editedResponse.status}`);
        }
        const editedBuffer = Buffer.from(await editedResponse.arrayBuffer());
        const finalPng = await blendEditedTextureIntoSelection(basePng, editedBuffer, selectionAlpha, width, height);

        await logUsage(req.userId, 'image', {
            provider: 'modelscope',
            apiId,
            purpose: 'texture-paint-edit',
            width,
            height,
        });

        return {
            image: `data:image/png;base64,${finalPng.toString('base64')}`,
            model: apiId,
            provider: 'modelscope',
        };
    } finally {
        await cleanup();
    }
}

router.post('/texture-paint-edit', verifyFirebaseToken, imageLimiter, async (req, res) => {
    try {
        const {
            prompt,
            base_texture,
            mask_texture,
            width: rawWidth,
            height: rawHeight,
        } = req.body || {};

        const cleanPrompt = String(prompt || '').trim();
        if (!cleanPrompt) {
            return res.status(400).json({ success: false, message: 'Hiányzó texture edit prompt.' });
        }
        if (cleanPrompt.length > 1800) {
            return res.status(400).json({ success: false, message: 'A texture edit prompt túl hosszú.' });
        }

        const base = parseImageDataUrl(base_texture, 'base_texture');
        const mask = parseImageDataUrl(mask_texture, 'mask_texture');
        const baseMeta = await sharp(base.buffer).metadata();
        const targetWidth = clampTextureEditDimension(rawWidth || baseMeta.width || 1024);
        const targetHeight = clampTextureEditDimension(rawHeight || baseMeta.height || 1024);

        const basePng = await sharp(base.buffer)
            .resize(targetWidth, targetHeight, { fit: 'fill', kernel: 'lanczos3' })
            .ensureAlpha()
            .png({ compressionLevel: 6 })
            .toBuffer();

        const maskPng = await sharp(mask.buffer)
            .resize(targetWidth, targetHeight, { fit: 'fill', kernel: 'nearest' })
            .ensureAlpha()
            .png({ compressionLevel: 6 })
            .toBuffer();

        const provider = String(process.env.TEXTURE_PAINT_EDIT_PROVIDER || 'modelscope').toLowerCase();
        if (provider !== 'openai') {
            const result = await runModelScopeTexturePaintEdit({
                req,
                basePng,
                maskPng,
                cleanPrompt,
                width: targetWidth,
                height: targetHeight,
            });
            processImageAndUpload(req.userId, result.image, {
                prompt: cleanPrompt,
                modelId: result.model,
                provider: 'modelscope-texture-paint',
                aspect_ratio: `${targetWidth}:${targetHeight}`,
                width: targetWidth,
                height: targetHeight,
            });
            return res.json({
                success: true,
                image: result.image,
                width: targetWidth,
                height: targetHeight,
                model: result.model,
                provider: result.provider,
            });
        }

        if (!process.env.OPENAI_API_KEY) {
            return res.status(500).json({ success: false, message: 'OPENAI_API_KEY nincs beállítva.' });
        }

        const model = process.env.OPENAI_TEXTURE_EDIT_MODEL || 'gpt-image-2';
        const texturePrompt = [
            'Edit this UV texture map for a 3D model.',
            'The transparent region of the mask is the user-painted area to edit.',
            'Only modify that masked area. Preserve all opaque-mask pixels, UV islands, seams, colors, lighting, and texture details as much as possible.',
            'Do not add borders, labels, frames, extra UV islands, or unrelated global style changes.',
            `User instruction: ${cleanPrompt}`,
        ].join(' ');

        const editRequest = {
            model,
            image: await toFile(basePng, 'base-texture.png', { type: 'image/png' }),
            mask: await toFile(maskPng, 'paint-mask.png', { type: 'image/png' }),
            prompt: texturePrompt,
            n: 1,
            size: getOpenAITextureEditSize(model, targetWidth, targetHeight),
            output_format: 'png',
        };

        if (!String(model).startsWith('gpt-image-2')) {
            editRequest.quality = 'medium';
            editRequest.input_fidelity = 'high';
        }

        const result = await openai.images.edit(editRequest);
        const imageBase64 = result?.data?.[0]?.b64_json;
        if (!imageBase64) {
            throw new Error('Az OpenAI image edit nem adott vissza képet.');
        }

        const outputBuffer = Buffer.from(imageBase64, 'base64');
        const restored = await sharp(outputBuffer)
            .resize(targetWidth, targetHeight, { fit: 'fill', kernel: 'lanczos3' })
            .png({ compressionLevel: 6 })
            .toBuffer();

        const image = `data:image/png;base64,${restored.toString('base64')}`;
        await logUsage(req.userId, 'image', {
            provider: 'openai',
            apiId: model,
            purpose: 'texture-paint-edit',
            width: targetWidth,
            height: targetHeight,
        });
        processImageAndUpload(req.userId, image, {
            prompt: cleanPrompt,
            modelId: model,
            provider: 'openai-texture-paint',
            aspect_ratio: `${targetWidth}:${targetHeight}`,
            width: targetWidth,
            height: targetHeight,
        });

        return res.json({
            success: true,
            image,
            width: targetWidth,
            height: targetHeight,
            model,
        });
    } catch (error) {
        console.error('[TexturePaintEdit] failed:', error?.response?.data || error?.message || error);
        const message = error?.response?.data?.error?.message || error?.message || 'Texture paint edit sikertelen.';
        return res.status(500).json({ success: false, message });
    }
});

// ════════════════════════════════════════════════════
// 2.  KÉPGENERÁLÁS  —  POST /api/generate-image
// ════════════════════════════════════════════════════
router.post('/generate-image', verifyFirebaseToken, imageLimiter, async (req, res) => {
    try {
        const {
            apiId, prompt, negative_prompt, provider,
            prompt_extend,
            image_size = { width: 1024, height: 1024 },
            num_inference_steps = 28,
            guidance_scale = 7.5,
            seed, num_images = 1,
            aspect_ratio = '1:1',
            input_image,
            jobId,
        } = req.body;

        const controller = new AbortController();
        registerJob(jobId, controller, 600000); // 10 minutes timeout

        if (!prompt?.trim()) {
            return res.status(400).json({ success: false, message: 'Hiányzó prompt' });
        }

        const sseStart = (res) => {
            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.flushHeaders();
        };
        const sseEmit = (res, data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

        const ESTIMATED_DURATIONS = {
            modelscope_edit: 150,
            modelscope_gen: 60,
            nvidia: 60,
        };

        const estimateGenerationDuration = ({ provider, isEditModel, steps, guidance }) => {
            const safeSteps = Math.max(1, Number(steps) || 1);
            const safeGuidance = Math.max(0, Number(guidance) || 0);

            if (provider === 'modelscope') {
                const baseDuration = isEditModel ? ESTIMATED_DURATIONS.modelscope_edit : ESTIMATED_DURATIONS.modelscope_gen;
                const stepFactor = Math.max(0.5, safeSteps / 35);
                const guidanceFactor = 1 + Math.max(0, safeGuidance - 3) * 0.03;
                return Math.round(baseDuration * stepFactor * guidanceFactor);
            }

            if (provider === 'nvidia') {
                const baseDuration = ESTIMATED_DURATIONS.nvidia;
                const stepFactor = Math.max(0.6, safeSteps / 35);
                const guidanceFactor = 1 + Math.max(0, safeGuidance - 3) * 0.02;
                return Math.round(baseDuration * stepFactor * guidanceFactor);
            }

            return ESTIMATED_DURATIONS.modelscope_gen;
        };

        if (provider === 'google-image') {
            if (!process.env.GEMINI_API_KEY) {
                sseStart(res);
                sseEmit(res, { type: 'error', message: 'GEMINI_API_KEY nincs beállítva' });
                return res.end();
            }

            const response = await axios.post(
                `https://generativelanguage.googleapis.com/v1beta/models/${apiId}:generateContent`,
                {
                    contents: [{ parts: [{ text: prompt.trim() }] }],
                    generationConfig: { response_modalities: ['TEXT', 'IMAGE'] },
                },
                {
                    headers: {
                        'x-goog-api-key': process.env.GEMINI_API_KEY,
                        'Content-Type': 'application/json',
                    },
                    timeout: 120000,
                    signal: controller.signal,
                }
            );

            const parts = response.data?.candidates?.[0]?.content?.parts || [];
            const images = [];
            for (const part of parts) {
                if (part.inlineData?.mimeType?.startsWith('image/')) {
                    images.push({
                        url: `data:${part.inlineData.mimeType};base64,${part.inlineData.data}`,
                        width: image_size.width || 1024,
                        height: image_size.height || 1024,
                    });
                }
            }

            if (images.length === 0) throw new Error('A Gemini nem adott vissza képet.');
            await logUsage(req.userId, 'image', { provider: 'google-image', apiId, numImages: images.length });
            for (const img of images) {
                processImageAndUpload(req.userId, img.url, { prompt, modelId: apiId, provider: 'google-image', aspect_ratio, width: img.width, height: img.height });
            }
            unregisterJob(jobId);
            sseStart(res);
            sseEmit(res, { type: 'done', images });
            return res.end();
        }

        else if (provider === 'modelscope') {
            if (!process.env.MODELSCOPE_API_KEY) {
                sseStart(res);
                sseEmit(res, { type: 'error', message: 'MODELSCOPE_API_KEY nincs beállítva' });
                return res.end();
            }

            const msHeaders = {
                Authorization: `Bearer ${process.env.MODELSCOPE_API_KEY}`,
                'Content-Type': 'application/json',
            };

            const isQwenEditModel = apiId.includes('Qwen');
            const isKontextModel = apiId.includes('Kontext') || apiId.includes('FLUX.1-Kontext');

            const rawInputImages = req.body.input_images
                ? req.body.input_images
                : input_image ? [input_image] : [];

            const isEditModel = rawInputImages.length > 0;

            let imageUrlsForApi = [];
            let tempB2Keys = [];
            let originalWidth = null;
            let originalHeight = null;
            let resizeMultiplier = 1;

            if (isEditModel) {
                try {
                    for (let idx = 0; idx < rawInputImages.length; idx++) {
                        const base64Str = rawInputImages[idx].includes(';base64,')
                            ? rawInputImages[idx].split(';base64,').pop()
                            : rawInputImages[idx];
                        const inputBuffer = Buffer.from(base64Str, 'base64');

                        if (!inputBuffer || inputBuffer.length === 0) {
                            throw new Error('Üres kép puffer (Base64 dekódolási hiba)');
                        }

                        const meta = await sharp(inputBuffer).metadata();
                        if (idx === 0) { originalWidth = meta.width; originalHeight = meta.height; }

                        let processedBuffer;
                        if (isQwenEditModel) {
                            const TARGET_PIXELS = 1_000_000;
                            const scaleFactor = Math.sqrt(TARGET_PIXELS / (meta.width * meta.height));
                            let newW = Math.round(meta.width * scaleFactor / 16) * 16;
                            let newH = Math.round(meta.height * scaleFactor / 16) * 16;
                            const areaScale = (meta.width * meta.height) / (newW * newH);
                            resizeMultiplier = Math.min(1.5, 0.4 + Math.log2(areaScale) * 0.4);
                            processedBuffer = await sharp(inputBuffer).resize(newW, newH, { fit: 'fill', kernel: 'lanczos3' }).png().toBuffer();
                        } else if (isKontextModel) {
                            const { w: newW, h: newH } = snapToKontextResolution(meta.width, meta.height);
                            const areaScale = (meta.width * meta.height) / (newW * newH);
                            resizeMultiplier = Math.min(1.5, 0.4 + Math.log2(areaScale) * 0.4);
                            processedBuffer = await sharp(inputBuffer).resize(newW, newH, { fit: 'fill', kernel: 'lanczos3' }).png().toBuffer();
                        } else {
                            processedBuffer = await sharp(inputBuffer).png().toBuffer();
                        }

                        const filename = `edit_${Date.now()}_${idx}_${req.userId.slice(0, 8)}.png`;
                        const tempKey = `temp_edit/${filename}`;
                        tempB2Keys.push(tempKey);

                        await b2.send(new PutObjectCommand({
                            Bucket: process.env.B2_BUCKET_NAME,
                            Key: tempKey,
                            Body: processedBuffer,
                            ContentType: 'image/png',
                        }));

                        const signedUrl = await getSignedUrl(b2, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: tempKey }), { expiresIn: 600 });
                        imageUrlsForApi.push(signedUrl);
                    }
                } catch (e) {
                    console.error('B2 hiba:', e.message);
                    sseStart(res);
                    sseEmit(res, { type: 'error', message: e.message });
                    return res.end();
                }
            }

            const msBody = isEditModel
                ? {
                    model: apiId, prompt: prompt.trim(),
                    steps: Math.min(Math.max(1, num_inference_steps), 50),
                    guidance: Math.min(Math.max(1, guidance_scale), 20),
                    negative_prompt: negative_prompt ? negative_prompt.trim() : undefined,
                    seed: seed ? parseInt(seed) : undefined,
                    prompt_extend,
                    image_url: imageUrlsForApi,
                }
                : {
                    model: apiId, prompt: prompt.trim(),
                    steps: Math.min(Math.max(1, num_inference_steps), 50),
                    guidance: Math.min(Math.max(1, guidance_scale), 20),
                    ...(negative_prompt ? { negative_prompt: negative_prompt.trim() } : {}),
                    ...(seed ? { seed: parseInt(seed) } : {}),
                    size: `${image_size.width || 1024}x${image_size.height || 1024}`,
                };

            let taskId = null;
            let immediateUrl = null;

            try {
                const genResp = await fetch('https://api-inference.modelscope.ai/v1/images/generations', {
                    method: 'POST',
                    headers: { ...msHeaders, 'X-ModelScope-Async-Mode': 'true' },
                    body: JSON.stringify(msBody),
                    signal: AbortSignal.timeout(30000),
                });

                const genData = await genResp.json();
                if (!genResp.ok) {
                    sseStart(res);
                    sseEmit(res, { type: 'error', message: `ModelScope hiba: ${JSON.stringify(genData?.errors || genData).slice(0, 200)}` });
                    return res.end();
                }

                if (genData.output_images?.length > 0) {
                    immediateUrl = genData.output_images[0];
                } else if (genData.task_id) {
                    taskId = genData.task_id;
                } else {
                    sseStart(res);
                    sseEmit(res, { type: 'error', message: `ModelScope: ismeretlen válasz` });
                    return res.end();
                }
            } catch (err) {
                sseStart(res);
                sseEmit(res, { type: 'error', message: 'ModelScope kapcsolódási hiba: ' + err.message });
                return res.end();
            }

            const cleanupB2 = async () => {
                for (const key of tempB2Keys) {
                    try { await b2.send(new DeleteObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key })); } catch { }
                }
            };

            const postProcess = async (url, resizeMultiplier) => {
                if (!isEditModel) return { url, base64: null };
                try {
                    const response = await fetch(url);
                    const generatedBuffer = Buffer.from(await response.arrayBuffer());
                    const restored = await sharp(generatedBuffer)
                        .resize(originalWidth, originalHeight, { fit: 'fill', kernel: 'lanczos3' })
                        .sharpen({ sigma: resizeMultiplier, m1: 0.5, m2: 3.0, x1: 2.0, y2: 15.0, y3: 15.0 })
                        .modulate({ brightness: 1.015 })
                        .png({ compressionLevel: 0 })
                        .toBuffer();
                    return { url: null, base64: `data:image/png;base64,${restored.toString('base64')}` };
                } catch (err) {
                    return { url, base64: null };
                }
            };

            if (immediateUrl) {
                await cleanupB2();
                const { url: finalUrl, base64 } = await postProcess(immediateUrl, resizeMultiplier);
                const finalImages = [{ url: base64 || finalUrl, width: originalWidth || image_size?.width || 1024, height: originalHeight || image_size?.height || 1024 }];
                await logUsage(req.userId, 'image', { provider: 'modelscope', apiId });
                for (const img of finalImages) {
                    processImageAndUpload(req.userId, img.url, { prompt, modelId: apiId, provider: 'modelscope', aspect_ratio, width: img.width, height: img.height });
                }
                sseStart(res);
                sseEmit(res, { type: 'done', images: finalImages });
                return res.end();
            }

            sseStart(res);
            const estimatedDuration = estimateGenerationDuration({
                provider: 'modelscope',
                isEditModel,
                steps: num_inference_steps,
                guidance: guidance_scale,
            });
            const startTime = Date.now();

            sseEmit(res, { type: 'status', status: 'PENDING', progress: 0, elapsed: 0 });

            let imageUrl = null;
            for (let i = 0; i < 150; i++) {
                if (controller.signal.aborted) break;
                await new Promise((r) => setTimeout(r, i === 0 ? 2000 : 3000));
                if (controller.signal.aborted) break;
                const elapsed = Math.round((Date.now() - startTime) / 1000);
                let pollData;
                try {
                    const pollResp = await fetch(`https://api-inference.modelscope.ai/v1/tasks/${taskId}`, {
                        headers: { ...msHeaders, 'X-ModelScope-Task-Type': 'image_generation' },
                        signal: controller.signal,
                    });
                    pollData = await pollResp.json();
                } catch (e) {
                    sseEmit(res, { type: 'status', status: 'PENDING', progress: Math.min(Math.round((elapsed / estimatedDuration) * 100), 90), elapsed });
                    continue;
                }

                const status = pollData?.task_status;
                const progress = Math.min(Math.round((elapsed / estimatedDuration) * 100), 90);

                if (status === 'SUCCEED') {
                    imageUrl = pollData?.output_images?.[0];
                    if (!imageUrl) {
                        await cleanupB2();
                        sseEmit(res, { type: 'error', message: 'ModelScope SUCCEED de nincs output_images' });
                        return res.end();
                    }
                    sseEmit(res, { type: 'status', status: 'PROCESSING', progress: Math.max(progress, 90), elapsed });
                    break;
                } else if (status === 'FAILED') {
                    await cleanupB2();
                    sseEmit(res, { type: 'error', message: 'ModelScope generálás sikertelen' });
                    return res.end();
                } else {
                    sseEmit(res, { type: 'status', status: status || 'PENDING', progress, elapsed });
                }
            }

            if (!imageUrl) {
                sseEmit(res, { type: 'error', message: 'ModelScope időtúllépés' });
                return res.end();
            }

            const { url: finalUrl, base64 } = await postProcess(imageUrl, resizeMultiplier);
            const finalImages = [{ url: base64 || finalUrl, width: originalWidth || image_size?.width || 1024, height: originalHeight || image_size?.height || 1024 }];
            await cleanupB2();
            await logUsage(req.userId, 'image', { provider: 'modelscope', apiId });
            for (const img of finalImages) {
                processImageAndUpload(req.userId, img.url, { prompt, modelId: apiId, provider: 'modelscope', aspect_ratio, width: img.width, height: img.height });
            }
            unregisterJob(jobId);
            sseEmit(res, { type: 'done', images: finalImages });
            return res.end();
        }

        else if (provider === 'cloudflare') {
            if (!process.env.CLOUDFLARE_API_KEY || !process.env.CLOUDFLARE_ACCOUNT_ID) {
                sseStart(res);
                sseEmit(res, { type: 'error', message: 'CLOUDFLARE_API_KEY vagy CLOUDFLARE_ACCOUNT_ID nincs beállítva' });
                return res.end();
            }

            const cfResp = await axios.post(
                `https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/ai/run/${apiId}`,
                {
                    prompt: prompt.trim(),
                    ...(negative_prompt ? { negative_prompt: negative_prompt.trim() } : {}),
                    ...(seed ? { seed: parseInt(seed) } : {}),
                    num_steps: Math.min(Math.max(1, num_inference_steps), 20),
                    guidance: Math.min(Math.max(1, guidance_scale), 20),
                    width: image_size.width || 1024,
                    height: image_size.height || 1024,
                },
                {
                    headers: { 'Authorization': `Bearer ${process.env.CLOUDFLARE_API_KEY}`, 'Content-Type': 'application/json' },
                    responseType: 'arraybuffer',
                    timeout: 120000,
                }
            );

            const base64 = Buffer.from(cfResp.data).toString('base64');
            const contentType = cfResp.headers['content-type']?.split(';')[0] || 'image/png';
            const finalImages = [{ url: `data:${contentType};base64,${base64}`, width: image_size.width || 1024, height: image_size.height || 1024 }];
            await logUsage(req.userId, 'image', { provider: 'cloudflare', apiId, numImages: 1 });
            for (const img of finalImages) {
                processImageAndUpload(req.userId, img.url, { prompt, modelId: apiId, provider: 'cloudflare', aspect_ratio, width: img.width, height: img.height });
            }
            sseStart(res);
            sseEmit(res, { type: 'status', status: 'PROCESSING', progress: 50, elapsed: 1 });
            sseEmit(res, { type: 'done', images: finalImages });
            return res.end();
        }

        else if (provider === 'nvidia-image') {
            if (!process.env.NVIDIA_API_KEY) {
                sseStart(res);
                sseEmit(res, { type: 'error', message: 'NVIDIA_API_KEY nincs beállítva' });
                return res.end();
            }

            const id = apiId.toLowerCase();
            const isFluxKontext = id.includes('kontext');
            const isFlux = id.includes('flux') && !isFluxKontext;
            const isSD3 = id.includes('stable-diffusion-3');

            const safeSeed = seed !== undefined && seed !== null && seed !== '' && !isNaN(parseInt(seed)) ? parseInt(seed) : undefined;

            let requestBody;
            if (isFlux) {
                requestBody = { prompt: prompt.trim(), mode: 'base', cfg_scale: Math.min(Math.max(1, guidance_scale), 30), width: image_size?.width || 1024, height: image_size?.height || 1024, steps: Math.min(Math.max(1, num_inference_steps), 50), ...(safeSeed !== undefined ? { seed: safeSeed } : {}) };
            } else if (isSD3) {
                requestBody = { prompt: prompt.trim(), cfg_scale: Math.min(Math.max(1, guidance_scale), 20), aspect_ratio: aspect_ratio || '1:1', steps: Math.min(Math.max(1, num_inference_steps), 50), ...(safeSeed !== undefined ? { seed: safeSeed } : {}), ...(negative_prompt ? { negative_prompt: negative_prompt.trim() } : {}) };
            } else {
                requestBody = { prompt: prompt.trim(), ...(safeSeed !== undefined ? { seed: safeSeed } : {}), ...(negative_prompt ? { negative_prompt: negative_prompt.trim() } : {}) };
            }

            let nimResp;
            try {
                nimResp = await axios.post(`https://ai.api.nvidia.com/v1/genai/${apiId}`, requestBody, {
                    headers: { 'Authorization': `Bearer ${process.env.NVIDIA_API_KEY}`, 'Content-Type': 'application/json', 'Accept': 'application/json' },
                    timeout: 180000,
                });
            } catch (err) {
                sseStart(res);
                sseEmit(res, { type: 'error', message: err.response?.data?.detail || err.message });
                return res.end();
            }

            const base64Image = nimResp.data?.image ?? nimResp.data?.artifacts?.[0]?.base64;
            if (!base64Image) {
                sseStart(res);
                sseEmit(res, { type: 'error', message: 'Nem érkezett kép az NVIDIA API-tól' });
                return res.end();
            }

            const finalImages = [{ url: `data:image/png;base64,${base64Image}`, width: image_size.width || 1024, height: image_size.height || 1024 }];
            await logUsage(req.userId, 'image', { provider: 'nvidia-image', apiId, numImages: 1 });
            for (const img of finalImages) {
                processImageAndUpload(req.userId, img.url, { prompt, modelId: apiId, provider: 'nvidia-image', aspect_ratio, width: img.width, height: img.height });
            }
            sseStart(res);
            sseEmit(res, { type: 'status', status: 'PROCESSING', progress: 50, elapsed: 1 });
            sseEmit(res, { type: 'done', images: finalImages });
            return res.end();
        }

        else {
            if (!apiId) {
                sseStart(res);
                sseEmit(res, { type: 'error', message: 'Hiányzó apiId' });
                return res.end();
            }
            if (!process.env.FAL_KEY) {
                sseStart(res);
                sseEmit(res, { type: 'error', message: 'FAL_KEY nincs beállítva' });
                return res.end();
            }

            const result = await fal.subscribe(apiId, {
                input: {
                    prompt: prompt.trim(),
                    image_size,
                    num_inference_steps: Math.min(Math.max(1, num_inference_steps), 50),
                    guidance_scale: Math.min(Math.max(1, guidance_scale), 15),
                    num_images: Math.min(Math.max(1, num_images), 4),
                    enable_safety_checker: true,
                    ...(negative_prompt ? { negative_prompt } : {}),
                    ...(seed ? { seed: parseInt(seed) } : {}),
                },
                logs: false,
            });

            const images = (result.data?.images || []).map((img) => ({ url: img.url, width: img.width, height: img.height }));
            if (images.length === 0) throw new Error('Nem érkezett kép');

            await logUsage(req.userId, 'image', { apiId, numImages: num_images });
            for (const img of images) {
                processImageAndUpload(req.userId, img.url, { prompt, modelId: apiId, provider: 'fal', aspect_ratio, width: img.width, height: img.height });
            }
            sseStart(res);
            sseEmit(res, { type: 'status', status: 'PROCESSING', progress: 50, elapsed: 1 });
            sseEmit(res, { type: 'done', images });
            return res.end();
        }

    } catch (err) {
        unregisterJob(req.body.jobId);
        if (err.name === 'AbortError') {
            console.log(`[Abort] Job ${req.body.jobId} was aborted.`);
            if (!res.headersSent) {
                sseStart(res);
                sseEmit(res, { type: 'error', message: 'Folyamat megszakítva (Timeout/User cancel)' });
                return res.end();
            }
            return;
        }
        console.error('❌ Image gen hiba:', err);
        if (err.response?.status === 402) { sseStart(res); sseEmit(res, { type: 'error', message: 'Nincs elegendő kredit' }); return res.end(); }
        if (err.response?.status === 403) { sseStart(res); sseEmit(res, { type: 'error', message: 'Érvénytelen API kulcs' }); return res.end(); }
        sseStart(res); sseEmit(res, { type: 'error', message: err?.message?.includes('safety') ? 'Safety filter' : err?.message || 'Képgenerálási hiba' }); return res.end();
    }
});

router.post('/upscale-image', verifyFirebaseToken, imageLimiter, handleDeapiImageUpload, async (req, res) => {
    let upscaleSseStarted = false;
    const startUpscaleSse = () => {
        if (upscaleSseStarted) return;
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('X-Accel-Buffering', 'no');
        if (typeof res.flushHeaders === 'function') res.flushHeaders();
        upscaleSseStarted = true;
    };
    const emitUpscaleSse = (data) => {
        if (res.writableEnded || res.destroyed) return;
        startUpscaleSse();
        res.write(`data: ${JSON.stringify(data)}\n\n`);
        if (typeof res.flush === 'function') res.flush();
    };

    const { jobId } = req.body || {};
    const controller = new AbortController();
    registerJob(jobId, controller, 600000);

    try {
        if (!process.env.DEAPI_API_KEY) {
            return res.status(500).json({ success: false, message: 'DEAPI_API_KEY nincs beallitva' });
        }

        const imageFile = req.file || null;
        if (!imageFile) {
            return res.status(400).json({ success: false, message: 'Hianyzo kep' });
        }
        if (!isSupportedDeapiImageFile(imageFile)) {
            return res.status(400).json({ success: false, message: 'Csak JPG, PNG, GIF, BMP vagy WebP kep toltheto fel' });
        }

        let inputMeta = {};
        try {
            inputMeta = await sharp(imageFile.buffer).metadata();
        } catch {
            return res.status(400).json({ success: false, message: 'A kep nem olvashato' });
        }

        const startedAt = Date.now();
        emitUpscaleSse({ type: 'status', status: 'SUBMITTING', progress: 4, elapsed: 0 });

        const upscaleModel = await resolveDeapiImageUpscaleModel(DEAPI_IMAGE_UPSCALE_MODEL);
        const submission = await submitDeapiImageUpscale(imageFile, controller.signal, upscaleModel);
        const requestId = submission?.data?.request_id;
        if (!requestId) {
            throw new Error('A deAPI nem adott vissza request_id-t');
        }

        emitUpscaleSse({ type: 'status', status: 'QUEUED', progress: 8, elapsed: 0, requestId });

        const result = await pollDeapiResult(requestId, controller.signal, (event) => {
            emitUpscaleSse({
                type: 'status',
                status: String(event.status || 'processing').toUpperCase(),
                progress: event.progress,
                elapsed: event.elapsed,
                requestId: event.requestId,
                predicted: Boolean(event.predicted),
            });
        }, {
            label: 'A deAPI upscale',
            estimatedDuration: 120,
            isResultReady: (data) => Boolean(extractDeapiImageUrl(data)),
        });

        const imageUrl = extractDeapiImageUrl(result);
        if (!imageUrl) {
            throw new Error('A deAPI nem adott vissza letoltheto kep URL-t');
        }

        const elapsed = Math.round((Date.now() - startedAt) / 1000);
        emitUpscaleSse({ type: 'status', status: 'FINALIZING', progress: 96, elapsed, requestId });

        let width = inputMeta.width ? inputMeta.width * 4 : 4096;
        let height = inputMeta.height ? inputMeta.height * 4 : 4096;
        try {
            const outputBuffer = imageUrl.startsWith('data:')
                ? Buffer.from(imageUrl.split(',')[1] || '', 'base64')
                : Buffer.from((await axios.get(imageUrl, {
                    responseType: 'arraybuffer',
                    timeout: 180000,
                    maxContentLength: 80 * 1024 * 1024,
                    httpsAgent,
                    headers: { Accept: 'image/*,*/*;q=0.8' },
                })).data);
            const outputMeta = await sharp(outputBuffer).metadata();
            width = outputMeta.width || width;
            height = outputMeta.height || height;
        } catch (err) {
            console.warn('[Upscale] Output meret beolvasas kihagyva:', err.message);
        }

        const storedImage = await processImageAndUpload(req.userId, imageUrl, {
            prompt: `${upscaleModel} upscale`,
            modelId: upscaleModel,
            provider: 'deapi-upscale',
            aspect_ratio: inputMeta.width && inputMeta.height ? `${inputMeta.width}:${inputMeta.height}` : 'upscale',
            width,
            height,
            operation: 'upscale',
            requestId,
        });
        const imageId = storedImage?.id || null;

        let outputImage = {
            url: imageUrl,
            fullUrl: imageUrl,
            downloadUrl: imageUrl,
            width,
            height,
            requestId,
            imageId,
        };

        if (storedImage?.fullKey) {
            const filename = sanitizeImageDownloadFilename(`ludusgen_upscale_${imageId || Date.now()}.${storedImage.extension || 'png'}`);
            const fullUrl = await getSignedUrl(b2, new GetObjectCommand({
                Bucket: process.env.B2_BUCKET_NAME,
                Key: storedImage.fullKey,
            }), { expiresIn: 3600 });
            const downloadUrl = await getSignedUrl(b2, new GetObjectCommand({
                Bucket: process.env.B2_BUCKET_NAME,
                Key: storedImage.fullKey,
                ResponseContentDisposition: `attachment; filename="${filename}"`,
            }), { expiresIn: 3600 });

            outputImage = {
                ...outputImage,
                url: fullUrl,
                fullUrl,
                downloadUrl,
                storage: 'b2',
                fullKey: storedImage.fullKey,
                thumbKey: storedImage.thumbKey,
            };
        }

        await logUsage(req.userId, 'image-upscale', {
            provider: 'deapi',
            model: upscaleModel,
            requestId,
            imageId,
            width,
            height,
        });

        unregisterJob(jobId);
        emitUpscaleSse({
            type: 'done',
            success: true,
            images: [outputImage],
            requestId,
            elapsed,
        });
        return res.end();
    } catch (err) {
        unregisterJob(jobId);
        const message = err.name === 'AbortError' || err.message === 'AbortError'
            ? 'Folyamat megszakitva (User/Timeout)'
            : err.message || 'Upscale hiba';

        if (upscaleSseStarted || res.headersSent) {
            emitUpscaleSse({ type: 'error', message });
            return res.end();
        }

        console.error('Upscale hiba:', err.response?.data || err.message || err);
        return res.status(err.status || err.response?.status || 500).json({ success: false, message });
    }
});

// ════════════════════════════════════════════════════
// 3.  TTS  —  POST /api/generate-tts
// ════════════════════════════════════════════════════
router.post('/generate-tts', verifyFirebaseToken, audioLimiter, handleDeapiTtsReferenceAudioUpload, async (req, res) => {
    let ttsSseStarted = false;
    const startTtsSse = () => {
        if (ttsSseStarted) return;
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('X-Accel-Buffering', 'no');
        if (typeof res.flushHeaders === 'function') res.flushHeaders();
        ttsSseStarted = true;
    };
    const emitTtsSse = (data) => {
        if (res.writableEnded || res.destroyed) return;
        startTtsSse();
        res.write(`data: ${JSON.stringify(data)}\n\n`);
        if (typeof res.flush === 'function') res.flush();
    };

    try {
        const {
            model = 'tts-1',
            provider = 'openai',
            text,
            voice = 'nova',
            speed = 1.0,
            format = 'mp3',
            jobId,
            mode = 'custom_voice',
            lang = 'en-us',
            sample_rate = 24000,
            ref_text = '',
            instruct = '',
        } = req.body;
        const controller = new AbortController();
        registerJob(jobId, controller, 600000);

        if (!text?.trim()) return res.status(400).json({ success: false, message: 'Hiányzó szöveg' });
        if (provider !== 'deapi' && text.length > 4096) return res.status(400).json({ success: false, message: 'Max 4096 karakter' });

        const parsedSpeed = Number(speed);
        const safeSpeed = Number.isFinite(parsedSpeed) ? Math.min(Math.max(0.25, parsedSpeed), 4.0) : 1.0;
        const safeFormat = ['mp3', 'opus', 'aac', 'flac'].includes(String(format || '').trim()) ? String(format).trim() : 'mp3';
        let audioUrl = '';

        if (provider === 'openai') {
            if (!process.env.OPENAI_API_KEY) return res.status(500).json({ success: false, message: 'OPENAI_API_KEY nincs beállítva' });
            const safeVoice = ['alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer'].includes(voice) ? voice : 'nova';
            const resp = await openai.audio.speech.create({ model, voice: safeVoice, input: text.trim(), speed: safeSpeed, response_format: safeFormat }, { signal: controller.signal });
            const mimeTypes = { mp3: 'audio/mpeg', opus: 'audio/ogg', aac: 'audio/aac', flac: 'audio/flac' };
            const buffer = Buffer.from(await resp.arrayBuffer());
            audioUrl = `data:${mimeTypes[safeFormat]};base64,${buffer.toString('base64')}`;
        }

        else if (provider === 'nvidia-riva') {
            if (!process.env.NVIDIA_API_KEY) return res.status(500).json({ success: false, message: 'NVIDIA_API_KEY nincs beállítva' });

            const FUNCTION_ID = '877104f7-e885-42b9-8de8-f6e4c6303969';
            const { voice = 'Magpie-Multilingual.EN-US.Aria', language_code = 'en-US' } = req.body;

            const client = createRivaClient();
            const meta = new grpc.Metadata();
            meta.add('authorization', `Bearer ${process.env.NVIDIA_API_KEY}`);
            meta.add('function-id', FUNCTION_ID);

            const audioBuffer = await new Promise((resolve, reject) => {
                const call = client.synthesize({ text: text.trim(), language_code, voice_name: voice, encoding: 'LINEAR_PCM', sample_rate_hz: 22050 }, meta, (err, response) => {
                    if (err) {
                        if (err.code === 1) reject(new Error('AbortError')); // gRPC CANCELLED
                        else reject(new Error(`gRPC hiba: ${err.message}`));
                    } else resolve(response.audio);
                });
                controller.signal.addEventListener('abort', () => {
                    call.cancel();
                    const e = new Error('Folyamat megszakítva');
                    e.name = 'AbortError';
                    reject(e);
                });
            });

            const wavBuffer = pcmToWav(audioBuffer, 22050, 1, 16);
            audioUrl = `data:audio/wav;base64,${wavBuffer.toString('base64')}`;
        }

        else if (provider === 'deapi') {
            if (!process.env.DEAPI_API_KEY) return res.status(500).json({ success: false, message: 'DEAPI_API_KEY nincs beallitva' });

            const selectedDeapiTtsModel = await findDeapiTtsModel(model);
            if (!selectedDeapiTtsModel) {
                return res.status(400).json({ success: false, message: `Ismeretlen deAPI TTS modell slug: ${model}` });
            }

            const defaults = selectedDeapiTtsModel.info?.defaults || {};
            const modelLimits = selectedDeapiTtsModel.info?.limits || {};
            const allowedModes = selectedDeapiTtsModel.info?.modes || ['custom_voice'];
            const safeMode = DEAPI_TTS_MODES.includes(String(mode || '').trim()) ? String(mode).trim() : 'custom_voice';
            const safeVoice = String(voice || defaults.voice || '').trim();
            const safeLang = normalizeDeapiTtsLanguage(selectedDeapiTtsModel.slug, lang, defaults.lang || 'en-us');
            const safeDeapiFormat = DEAPI_TTS_FORMATS.includes(String(format || '').trim()) ? String(format).trim() : (defaults.format || 'mp3');
            const minTextLength = Number(modelLimits.min_text ?? 0);
            const maxTextLength = Number(modelLimits.max_text ?? 4096);
            const minSpeed = Number(modelLimits.min_speed ?? 0.25);
            const maxSpeed = Number(modelLimits.max_speed ?? 4);
            const safeDeapiSpeed = Number.isFinite(parsedSpeed)
                ? Math.min(Math.max(parsedSpeed, minSpeed), maxSpeed)
                : Number(defaults.speed || 1);
            const parsedSampleRate = Number(sample_rate);
            const allowedSampleRates = Array.isArray(modelLimits.available_ratios) && modelLimits.available_ratios.length > 0
                ? modelLimits.available_ratios.map(Number).filter(Number.isFinite)
                : DEAPI_TTS_SAMPLE_RATES;
            const safeSampleRate = allowedSampleRates.includes(parsedSampleRate)
                ? parsedSampleRate
                : Number(defaults.sample_rate || 24000);
            const safeRefText = String(ref_text || '').trim();
            const safeInstruct = String(instruct || '').trim();
            const referenceAudioFile = req.file || null;

            if (Number.isFinite(minTextLength) && text.trim().length < minTextLength) {
                return res.status(400).json({ success: false, message: `${selectedDeapiTtsModel.name} minimum ${minTextLength} karakteres szoveget ker` });
            }
            if (Number.isFinite(maxTextLength) && text.trim().length > maxTextLength) {
                return res.status(400).json({ success: false, message: `${selectedDeapiTtsModel.name} maximum ${maxTextLength} karakteres szoveget fogad` });
            }

            if (!allowedModes.includes(safeMode)) {
                return res.status(400).json({
                    success: false,
                    message: safeMode === 'voice_clone'
                        ? `${selectedDeapiTtsModel.name} nem tamogat referencia audio klonozast. Ehhez valaszd a Qwen3 TTS sima/VoiceClone valtozatot.`
                        : `${selectedDeapiTtsModel.name} nem tamogatja ezt a TTS modot.`,
                });
            }
            if (safeMode === 'custom_voice' && !safeVoice) {
                return res.status(400).json({ success: false, message: 'Custom voice modban kotelezo a voice mezot megadni' });
            }
            if (safeMode === 'voice_clone') {
                if (!referenceAudioFile) {
                    return res.status(400).json({ success: false, message: 'Voice clone modban kotelezo a referencia audio' });
                }
                if (!isSupportedDeapiReferenceAudioFile(referenceAudioFile)) {
                    return res.status(400).json({ success: false, message: 'A referencia audio csak MP3, WAV, FLAC, OGG vagy M4A lehet' });
                }
            }
            if (safeMode === 'voice_design' && !safeInstruct) {
                return res.status(400).json({ success: false, message: 'Voice design modban kotelezo a hang leirasa' });
            }

            const submissionPayload = {
                text: text.trim(),
                model: selectedDeapiTtsModel.slug,
                mode: safeMode,
                lang: safeLang,
                speed: safeDeapiSpeed,
                format: safeDeapiFormat,
                sample_rate: safeSampleRate,
            };

            if (safeMode === 'custom_voice') {
                submissionPayload.voice = safeVoice;
            }
            if (safeMode === 'voice_clone' && safeRefText) {
                submissionPayload.ref_text = safeRefText;
            }
            if (safeInstruct && safeMode === 'voice_design') {
                submissionPayload.instruct = safeInstruct;
            }

            const deapiStartedAt = Date.now();
            emitTtsSse({ type: 'status', status: 'SUBMITTING', progress: 4, elapsed: 0 });
            const submission = await submitDeapiTextToAudio(
                submissionPayload,
                controller.signal,
                safeMode === 'voice_clone' ? referenceAudioFile : null
            );
            const requestId = submission?.data?.request_id;
            if (!requestId) {
                throw new Error('A deAPI nem adott vissza request_id-t');
            }

            emitTtsSse({ type: 'status', status: 'QUEUED', progress: 8, elapsed: 0, requestId });
            const result = await pollDeapiResult(requestId, controller.signal, (event) => {
                emitTtsSse({
                    type: 'status',
                    status: String(event.status || 'processing').toUpperCase(),
                    progress: event.progress,
                    elapsed: event.elapsed,
                    requestId: event.requestId,
                    predicted: Boolean(event.predicted),
                });
            }, { label: 'A deAPI TTS', estimatedDuration: 90 });

            audioUrl = extractDeapiAudioUrl(result);
            if (!audioUrl) {
                throw new Error('A deAPI nem adott vissza letoltheto audio URL-t');
            }

            const deapiElapsed = Math.round((Date.now() - deapiStartedAt) / 1000);
            emitTtsSse({ type: 'status', status: 'FINALIZING', progress: 96, elapsed: deapiElapsed, requestId });

            const archiveItem = await persistGeneratedAudio(req.userId, audioUrl, {
                type: 'tts',
                text: text.trim(),
                provider: 'deapi',
                model: selectedDeapiTtsModel.slug,
                ttsMode: safeMode,
                voice: safeMode === 'custom_voice' ? safeVoice : null,
                lang: safeLang,
                speed: safeDeapiSpeed,
                instruct: safeMode === 'voice_design' ? safeInstruct : null,
                hasReferenceAudio: safeMode === 'voice_clone',
                fileFormat: safeDeapiFormat,
                sampleRate: safeSampleRate,
                requestId,
                stream: false,
                outputFormat: 'url',
            });

            await logUsage(req.userId, 'tts', {
                provider: 'deapi',
                task: 'txt2audio',
                model: selectedDeapiTtsModel.slug,
                mode: safeMode,
                chars: text.length,
                audioId: archiveItem?.id || null,
                requestId,
            });

            unregisterJob(jobId);
            emitTtsSse({
                type: 'done',
                success: true,
                audioUrl: archiveItem ? null : audioUrl,
                audioId: archiveItem?.id || null,
                historyItem: archiveItem,
                fileFormat: safeDeapiFormat,
                sampleRate: safeSampleRate,
                outputFormat: 'url',
                stream: false,
                elapsed: deapiElapsed,
                requestId,
            });
            return res.end();
        }

        else if (provider === 'elevenlabs') {
            if (!process.env.ELEVENLABS_API_KEY) return res.status(500).json({ success: false, message: 'ELEVENLABS_API_KEY nincs beállítva' });
            const voiceId = process.env.ELEVENLABS_VOICE_ID || '21m00Tcm4TlvDq8ikWAM';
            const resp = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${voiceId}`, {
                method: 'POST',
                headers: { 'xi-api-key': process.env.ELEVENLABS_API_KEY, 'Content-Type': 'application/json', Accept: 'audio/mpeg' },
                body: JSON.stringify({ text: text.trim(), model_id: model, voice_settings: { stability: 0.75, similarity_boost: 0.85, style: 0.0, use_speaker_boost: true } }),
                signal: controller.signal,
            });
            if (!resp.ok) { const err = await resp.json().catch(() => ({})); throw new Error(err?.detail?.message || `ElevenLabs hiba: ${resp.status}`); }
            const buffer = Buffer.from(await resp.arrayBuffer());
            audioUrl = `data:audio/mpeg;base64,${buffer.toString('base64')}`;
        }

        else {
            return res.status(400).json({ success: false, message: `Ismeretlen TTS provider: ${provider}` });
        }

        const archivedModel = provider === 'nvidia-riva' ? 'magpie-tts-multilingual' : model;
        const archivedFileFormat = provider === 'nvidia-riva' ? 'wav' : provider === 'elevenlabs' ? 'mp3' : safeFormat;
        const archiveItem = await persistGeneratedAudio(req.userId, audioUrl, {
            type: 'tts',
            text: text.trim(),
            provider,
            model: archivedModel,
            voice,
            fileFormat: archivedFileFormat,
            sampleRate: provider === 'nvidia-riva' ? 22050 : null,
            stream: false,
        });

        await logUsage(req.userId, 'tts', {
            provider,
            model: archivedModel,
            chars: text.length,
            audioId: archiveItem?.id || null,
        });
        unregisterJob(jobId);
        return res.json({
            success: true,
            audioUrl: archiveItem ? null : audioUrl,
            audioId: archiveItem?.id || null,
            historyItem: archiveItem,
            fileFormat: archiveItem?.fileFormat || archivedFileFormat,
            outputFormat: archiveItem ? 'history' : 'data',
            audio: archiveItem,
        });

    } catch (err) {
        unregisterJob(req.body.jobId);
        const clientMessage = err.name === 'AbortError' || err.message === 'AbortError'
            ? 'Folyamat megszakitva (User/Timeout)'
            : err.message || 'TTS hiba';
        if (ttsSseStarted) {
            emitTtsSse({ type: 'error', message: clientMessage });
            return res.end();
        }
        if (res.headersSent) return;
        if (err.response || err.status || err.isAxiosError) {
            console.error('TTS hiba:', {
                status: err.status || err.response?.status || null,
                code: err.code || null,
                message: err.response?.data?.message || err.message || 'Unknown error',
                deapiRateLimit: Boolean(isDeapiRateLimitError(err) || err.deapiRateLimit),
            });
            return res.status(err.status || err.response?.status || 500).json({ success: false, message: clientMessage });
        }
        if (err.name === 'AbortError' || err.message === 'AbortError') return res.status(499).json({ success: false, message: clientMessage });
        console.error('TTS hiba:', err);
        return res.status(500).json({ success: false, message: clientMessage });
    }
});

// ════════════════════════════════════════════════════
// 4.  ZENEGENERÁLÁS  —  POST /api/generate-music
// ════════════════════════════════════════════════════
function getMiniMaxMusicMimeType(format = 'mp3') {
    if (format === 'wav') return 'audio/wav';
    if (format === 'pcm') return 'audio/pcm';
    return 'audio/mpeg';
}

function tryParseJson(value) {
    try {
        return JSON.parse(value);
    } catch {
        return null;
    }
}

function normalizeMiniMaxMusicAudio(audioValue, format) {
    if (!audioValue || typeof audioValue !== 'string') return '';
    if (audioValue.startsWith('data:audio/') || /^https?:\/\//i.test(audioValue)) {
        return audioValue;
    }

    const audioBuffer = Buffer.from(audioValue, 'hex');
    return `data:${getMiniMaxMusicMimeType(format)};base64,${audioBuffer.toString('base64')}`;
}

async function parseMiniMaxMusicStreamResponse(response) {
    const responseText = await response.text();
    const directJson = tryParseJson(responseText);
    if (directJson) return directJson;

    const lines = responseText.split(/\r?\n/);
    let combinedAudio = '';
    let lastParsedEvent = null;

    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line || line === 'data: [DONE]') continue;

        const payloadText = line.startsWith('data:') ? line.slice(5).trim() : line;
        const parsedEvent = tryParseJson(payloadText);

        if (parsedEvent) {
            lastParsedEvent = parsedEvent;
            if (typeof parsedEvent?.data?.audio === 'string') {
                combinedAudio += parsedEvent.data.audio;
            }
            continue;
        }

        if (/^[0-9a-fA-F]+$/.test(payloadText)) {
            combinedAudio += payloadText;
        }
    }

    if (!combinedAudio) {
        throw new Error('A MiniMax stream válasza nem volt értelmezhető');
    }

    return {
        data: {
            audio: combinedAudio,
            status: lastParsedEvent?.data?.status ?? 2,
        },
        extra_info: lastParsedEvent?.extra_info || {},
        base_resp: lastParsedEvent?.base_resp || {
            status_code: 0,
            status_msg: 'success',
        },
    };
}

async function callMiniMaxMusicGeneration(payload, signal) {
    const url = `${(process.env.MINIMAX_API_HOST || 'https://api.minimax.io').replace(/\/$/, '')}/v1/music_generation`;
    const headers = {
        Authorization: `Bearer ${process.env.MINIMAX_API_KEY}`,
        'Content-Type': 'application/json',
    };

    if (!payload.stream) {
        const response = await axios.post(url, payload, {
            headers,
            signal,
            timeout: 600000,
            httpsAgent,
        });
        return response.data;
    }

    const response = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal,
    });

    if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        const parsedError = tryParseJson(errorText);
        throw new Error(parsedError?.base_resp?.status_msg || parsedError?.message || `MiniMax hiba: ${response.status}`);
    }

    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        return response.json();
    }

    return parseMiniMaxMusicStreamResponse(response);
}

function getDeapiClient() {
    return axios.create({
        baseURL: (process.env.DEAPI_API_HOST || 'https://api.deapi.ai').replace(/\/$/, ''),
        headers: {
            Accept: 'application/json',
            Authorization: `Bearer ${process.env.DEAPI_API_KEY}`,
        },
        timeout: 120000,
        httpsAgent,
    });
}

const DEAPI_ALLOWED_TXT2MUSIC_MODELS = [
    {
        slug: 'AceStep_1_5_Turbo',
        name: 'ACE-Step 1.5 Turbo',
        info: {
            defaults: { inference_steps: 8, guidance_scale: 1, duration: 30, format: 'mp3' },
            limits: {
                min_caption: 3,
                max_caption: 300,
                min_duration: 10,
                max_duration: 300,
                min_steps: 8,
                max_steps: 8,
                min_guidance: 1,
                max_guidance: 1,
                min_bpm: 50,
                max_bpm: 200,
                min_ref_audio_duration: 5,
                max_ref_audio_duration: 60,
            },
        },
    },
    {
        slug: 'AceStep_1_5_XL_Turbo_INT8',
        name: 'ACE-Step 1.5 XL Turbo INT8',
        info: {
            defaults: { inference_steps: 8, guidance_scale: 1, duration: 30, format: 'mp3' },
            limits: {
                min_caption: 3,
                max_caption: 300,
                min_duration: 10,
                max_duration: 300,
                min_steps: 8,
                max_steps: 8,
                min_guidance: 1,
                max_guidance: 1,
                min_bpm: 50,
                max_bpm: 200,
                min_ref_audio_duration: 5,
                max_ref_audio_duration: 60,
            },
        },
    },
    {
        slug: 'AceStep_1_5_Base',
        name: 'ACE-Step 1.5 Base',
        info: {
            defaults: { inference_steps: 60, guidance_scale: 9, duration: 60, format: 'mp3' },
            limits: {
                min_caption: 3,
                max_caption: 300,
                min_duration: 30,
                max_duration: 300,
                min_steps: 5,
                max_steps: 100,
                min_guidance: 3,
                max_guidance: 20,
                min_bpm: 50,
                max_bpm: 200,
                min_ref_audio_duration: 5,
                max_ref_audio_duration: 60,
            },
        },
    },
];

const DEAPI_ALLOWED_TXT2AUDIO_MODELS = [
    {
        slug: 'Kokoro',
        name: 'Kokoro',
        info: {
            defaults: { mode: 'custom_voice', voice: 'af_alloy', lang: 'en-us', speed: 1, format: 'mp3', sample_rate: 24000 },
            limits: { min_text: 3, max_text: 10001, min_speed: 0.5, max_speed: 2, available_ratios: [24000] },
            modes: ['custom_voice'],
        },
    },
    {
        slug: 'Chatterbox',
        name: 'Chatterbox',
        info: {
            defaults: { mode: 'custom_voice', voice: 'default', lang: 'en', speed: 1, format: 'mp3', sample_rate: 24000 },
            limits: { min_text: 10, max_text: 2000, min_speed: 1, max_speed: 1, available_ratios: [24000] },
            modes: ['custom_voice'],
            features: { supports_voice_clone: false, supports_custom_voice: true, supports_voice_design: false },
        },
    },
    {
        slug: 'Qwen3_TTS_12Hz_1_7B_Base',
        name: 'Qwen3 TTS VoiceClone',
        info: {
            defaults: { mode: 'voice_clone', voice: 'default', lang: 'English', speed: 1, format: 'mp3', sample_rate: 24000 },
            limits: { min_text: 10, max_text: 5000, min_speed: 1, max_speed: 1, available_ratios: [24000], min_ref_audio_duration: 5, max_ref_audio_duration: 15 },
            modes: ['voice_clone'],
            features: { supports_voice_clone: true, supports_custom_voice: false, supports_voice_design: false },
        },
    },
    {
        slug: 'Qwen3_TTS_12Hz_1_7B_VoiceDesign',
        name: 'Qwen3 TTS VoiceDesign',
        info: {
            defaults: { mode: 'voice_design', voice: 'default', lang: 'English', speed: 1, format: 'mp3', sample_rate: 24000 },
            limits: { min_text: 10, max_text: 5000, min_speed: 1, max_speed: 1, available_ratios: [24000] },
            modes: ['voice_design'],
            features: { supports_voice_clone: false, supports_custom_voice: false, supports_voice_design: true },
        },
    },
    {
        slug: 'Qwen3_TTS_12Hz_1_7B_CustomVoice',
        name: 'Qwen3 TTS CustomVoice',
        info: {
            defaults: { mode: 'custom_voice', voice: 'Vivian', lang: 'English', speed: 1, format: 'mp3', sample_rate: 24000 },
            limits: { min_text: 10, max_text: 5000, min_speed: 1, max_speed: 1, available_ratios: [24000] },
            modes: ['custom_voice'],
            features: { supports_voice_clone: false, supports_custom_voice: true, supports_voice_design: false },
        },
    },
];

const DEAPI_TTS_MODES = ['custom_voice', 'voice_clone', 'voice_design'];
const DEAPI_TTS_FORMATS = ['mp3', 'wav', 'flac'];
const DEAPI_TTS_SAMPLE_RATES = [16000, 22050, 24000, 44100, 48000];
const DEAPI_IMAGE_UPSCALE_MODEL = 'RealESRGAN_x4';
const DEAPI_MODEL_CACHE_TTL_MS = Math.max(60000, Number(process.env.DEAPI_MODEL_CACHE_TTL_MS || 5 * 60 * 1000));
const deapiModelCache = new Map();

function normalizeDeapiModelSlug(slug = '') {
    return String(slug || '').trim().toLowerCase();
}

function normalizeDeapiModelRecord(model = {}) {
    return {
        ...model,
        name: model.name || model.slug,
        slug: model.slug,
        info: {
            defaults: model.info?.defaults || {},
            limits: model.info?.limits || {},
            modes: model.info?.modes,
            features: model.info?.features || {},
        },
        languages: model.languages ?? null,
    };
}

function mergeDeapiModelLists(liveModels = [], fallbackModels = []) {
    const merged = [];
    const fallbackBySlug = new Map(
        fallbackModels
            .map(normalizeDeapiModelRecord)
            .filter((model) => model.slug)
            .map((model) => [normalizeDeapiModelSlug(model.slug), model])
    );
    const seen = new Set();

    for (const liveModel of liveModels.map(normalizeDeapiModelRecord).filter((model) => model.slug)) {
        const key = normalizeDeapiModelSlug(liveModel.slug);
        const fallback = fallbackBySlug.get(key);
        merged.push({
            ...fallback,
            ...liveModel,
            info: {
                defaults: {
                    ...(fallback?.info?.defaults || {}),
                    ...(liveModel.info?.defaults || {}),
                },
                limits: {
                    ...(fallback?.info?.limits || {}),
                    ...(liveModel.info?.limits || {}),
                },
                modes: liveModel.info?.modes || fallback?.info?.modes,
                features: {
                    ...(fallback?.info?.features || {}),
                    ...(liveModel.info?.features || {}),
                },
            },
        });
        seen.add(key);
    }

    for (const fallback of fallbackBySlug.values()) {
        if (!seen.has(normalizeDeapiModelSlug(fallback.slug))) {
            merged.push(fallback);
        }
    }

    return merged;
}

async function fetchDeapiModelsByInferenceType(inferenceType, fallbackModels = []) {
    const cacheKey = String(inferenceType || '').trim();
    const cached = deapiModelCache.get(cacheKey);
    if (cached && Date.now() - cached.fetchedAt < DEAPI_MODEL_CACHE_TTL_MS) {
        return mergeDeapiModelLists(cached.models, fallbackModels);
    }

    try {
        const client = getDeapiClient();
        const response = await client.get('/api/v2/models', {
            params: {
                'filter[inference_types]': cacheKey,
                per_page: 100,
            },
        });
        const liveModels = Array.isArray(response.data?.data) ? response.data.data : [];
        deapiModelCache.set(cacheKey, { fetchedAt: Date.now(), models: liveModels });
        return mergeDeapiModelLists(liveModels, fallbackModels);
    } catch (err) {
        console.warn(`[deAPI] ${cacheKey} model lista nem toltheto V2-bol, helyi fallback hasznalva:`, err.response?.data || err.message);
        return mergeDeapiModelLists([], fallbackModels);
    }
}

function getLocalDeapiMusicModels() {
    return DEAPI_ALLOWED_TXT2MUSIC_MODELS.map((model) => ({
        ...model,
        info: {
            defaults: model.info?.defaults || {},
            limits: model.info?.limits || {},
        },
    }));
}

function findLocalDeapiMusicModel(slug = '') {
    const normalizedSlug = normalizeDeapiModelSlug(slug);
    return getLocalDeapiMusicModels().find((model) => normalizeDeapiModelSlug(model.slug) === normalizedSlug) || null;
}

function getLocalDeapiTtsModels() {
    return DEAPI_ALLOWED_TXT2AUDIO_MODELS.map((model) => ({
        ...model,
        info: {
            defaults: model.info?.defaults || {},
            limits: model.info?.limits || {},
            modes: model.info?.modes || ['custom_voice'],
            features: model.info?.features || {},
        },
    }));
}

function findLocalDeapiTtsModel(slug = '') {
    const normalizedSlug = normalizeDeapiModelSlug(slug);
    return getLocalDeapiTtsModels().find((model) => normalizeDeapiModelSlug(model.slug) === normalizedSlug) || null;
}

function normalizeDeapiTtsLanguage(modelSlug, lang, fallback = 'en-us') {
    const normalizedModel = normalizeDeapiModelSlug(modelSlug);
    const raw = String(lang || fallback || '').trim().toLowerCase();
    if (!raw) return fallback;

    if (normalizedModel.includes('qwen3')) {
        const qwenLanguageMap = {
            en: 'English',
            'en-us': 'English',
            'en-gb': 'English',
            english: 'English',
            zh: 'Chinese',
            chinese: 'Chinese',
            ja: 'Japanese',
            japanese: 'Japanese',
            ko: 'Korean',
            korean: 'Korean',
            de: 'German',
            german: 'German',
            fr: 'French',
            french: 'French',
            ru: 'Russian',
            russian: 'Russian',
            pt: 'Portuguese',
            portuguese: 'Portuguese',
            es: 'Spanish',
            spanish: 'Spanish',
            it: 'Italian',
            italian: 'Italian',
        };
        return qwenLanguageMap[raw] || fallback;
    }

    if (normalizedModel.includes('chatterbox')) {
        if (raw === 'en-us' || raw === 'en-gb') return 'en';
        return raw.split('-')[0] || fallback;
    }

    if (normalizedModel.includes('kokoro') && raw === 'en') {
        return 'en-us';
    }

    return raw;
}

function getDeapiRateLimitDetails(err) {
    const headers = err.response?.headers || {};
    const retryAfterSeconds = Number(headers['retry-after']);
    const resetSeconds = Number(headers['x-ratelimit-reset']);
    const dailyLimit = headers['x-ratelimit-daily-limit'] || headers['x-ratelimit-limit'] || null;
    const dailyRemaining = headers['x-ratelimit-daily-remaining'] || headers['x-ratelimit-remaining'] || null;

    return {
        retryAfterSeconds: Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : null,
        resetAt: Number.isFinite(resetSeconds) ? new Date(resetSeconds * 1000) : null,
        dailyLimit,
        dailyRemaining,
    };
}

function isDeapiRateLimitError(err) {
    return err?.deapiRateLimit || err?.response?.status === 429;
}

function buildDeapiRateLimitMessage(err) {
    const details = getDeapiRateLimitDetails(err);
    const parts = ['deAPI rate limit hiba.'];

    if (details.dailyLimit) {
        parts.push(`Napi limit: ${details.dailyLimit}, maradek: ${details.dailyRemaining ?? '0'}.`);
    }
    if (details.retryAfterSeconds !== null) {
        const minutes = Math.ceil(details.retryAfterSeconds / 60);
        parts.push(`Probald ujra kb. ${minutes} perc mulva.`);
    }
    if (details.resetAt) {
        parts.push(`Reset UTC: ${details.resetAt.toISOString()}.`);
    }

    return parts.join(' ');
}

function flattenDeapiValidationErrors(errors) {
    if (!errors) return [];

    if (Array.isArray(errors)) {
        return errors
            .map((item) => typeof item === 'string' ? item : JSON.stringify(item))
            .filter(Boolean);
    }

    if (typeof errors === 'object') {
        return Object.entries(errors).flatMap(([field, value]) => {
            if (Array.isArray(value)) {
                return value.map((message) => `${field}: ${message}`);
            }
            if (typeof value === 'string') {
                return [`${field}: ${value}`];
            }
            return [`${field}: ${JSON.stringify(value)}`];
        });
    }

    return [String(errors)];
}

function buildDeapiValidationMessage(err) {
    const data = err.response?.data || {};
    const status = err.response?.status || err.status || 500;
    const parts = [`deAPI hiba (${status}).`];

    if (data.message) {
        parts.push(String(data.message));
    } else if (err.message && !/^Request failed with status code/i.test(err.message)) {
        parts.push(err.message);
    }

    const validationErrors = flattenDeapiValidationErrors(data.errors);
    if (validationErrors.length > 0) {
        parts.push(validationErrors.slice(0, 4).join(' | '));
    }

    return parts.join(' ');
}

function normalizeDeapiError(err) {
    if (isDeapiRateLimitError(err)) {
        const wrapped = new Error(buildDeapiRateLimitMessage(err));
        wrapped.status = 429;
        wrapped.deapiRateLimit = true;
        wrapped.response = err.response;
        return wrapped;
    }

    if (!err?.response) return err;

    const wrapped = new Error(buildDeapiValidationMessage(err));
    wrapped.status = err.response?.status;
    wrapped.response = err.response;
    wrapped.isAxiosError = err.isAxiosError;
    return wrapped;
}

function getPredictedDeapiProgress(elapsedSeconds, estimatedSeconds = 180) {
    const ratio = Math.max(0, Math.min(1, elapsedSeconds / Math.max(30, estimatedSeconds)));
    const eased = 1 - Math.pow(1 - ratio, 2);
    return Math.max(8, Math.min(95, Math.round(8 + eased * 87)));
}

function normalizeDeapiMusicNumber(value, { min, max, fallback, integer = false } = {}) {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    const safeValue = Math.min(Math.max(parsed, min), max);
    return integer ? Math.round(safeValue) : safeValue;
}

function getDeapiNumericLimit(limits, key, fallback = null) {
    const parsed = Number(limits?.[key]);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function isPrivateIpAddress(address = '') {
    const value = String(address || '').trim().toLowerCase();
    if (!value) return true;
    if (value === 'localhost' || value === '::1' || value === '0.0.0.0') return true;
    if (value.startsWith('127.') || value.startsWith('10.') || value.startsWith('169.254.')) return true;
    if (value.startsWith('192.168.')) return true;
    const secondOctet = Number(value.split('.')[1]);
    if (value.startsWith('172.') && Number.isFinite(secondOctet) && secondOctet >= 16 && secondOctet <= 31) return true;
    if (value.startsWith('fc') || value.startsWith('fd') || value.startsWith('fe80:')) return true;
    return false;
}

async function assertSafeExternalAudioUrl(rawUrl) {
    let parsedUrl;
    try {
        parsedUrl = new URL(String(rawUrl || ''));
    } catch {
        throw new Error('Érvénytelen audio URL');
    }

    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error('Csak HTTP/HTTPS audio URL tölthető le');
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    if (hostname === 'localhost' || hostname.endsWith('.local')) {
        throw new Error('Belső hálózati audio URL nem tölthető le');
    }

    const addresses = await dns.promises.lookup(hostname, { all: true });
    if (!addresses.length || addresses.some((entry) => isPrivateIpAddress(entry.address))) {
        throw new Error('Belső hálózati audio URL nem tölthető le');
    }

    return parsedUrl.toString();
}

async function assertSafeExternalImageUrl(rawUrl) {
    let parsedUrl;
    try {
        parsedUrl = new URL(String(rawUrl || ''));
    } catch {
        throw new Error('Ervenytelen kep URL');
    }

    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error('Csak HTTP/HTTPS kep URL toltheto le');
    }

    const hostname = parsedUrl.hostname.toLowerCase();
    if (hostname === 'localhost' || hostname.endsWith('.local')) {
        throw new Error('Belso halozati kep URL nem toltheto le');
    }

    const addresses = await dns.promises.lookup(hostname, { all: true });
    if (!addresses.length || addresses.some((entry) => isPrivateIpAddress(entry.address))) {
        throw new Error('Belso halozati kep URL nem toltheto le');
    }

    return parsedUrl.toString();
}

function sanitizeAudioDownloadFilename(filename = 'neural_audio.mp3') {
    const cleaned = String(filename || 'neural_audio.mp3')
        .replace(/[\\/:*?"<>|]+/g, '-')
        .replace(/\s+/g, '_')
        .slice(0, 120)
        .trim();
    return cleaned || 'neural_audio.mp3';
}

function sanitizeImageDownloadFilename(filename = 'ludusgen_image.png') {
    const cleaned = String(filename || 'ludusgen_image.png')
        .replace(/[\\/:*?"<>|]+/g, '-')
        .replace(/\s+/g, '_')
        .slice(0, 120)
        .trim();
    return cleaned || 'ludusgen_image.png';
}

const AUDIO_ARCHIVE_MAX_BYTES = 100 * 1024 * 1024;
const AUDIO_EXTENSION_BY_MIME = {
    'audio/mpeg': 'mp3',
    'audio/mp3': 'mp3',
    'audio/wav': 'wav',
    'audio/x-wav': 'wav',
    'audio/wave': 'wav',
    'audio/flac': 'flac',
    'audio/x-flac': 'flac',
    'audio/aac': 'aac',
    'audio/ogg': 'ogg',
    'audio/opus': 'opus',
    'audio/pcm': 'pcm',
};
const AUDIO_MIME_BY_EXTENSION = {
    mp3: 'audio/mpeg',
    wav: 'audio/wav',
    flac: 'audio/flac',
    aac: 'audio/aac',
    ogg: 'audio/ogg',
    opus: 'audio/ogg',
    pcm: 'audio/pcm',
};

function normalizeAudioContentType(contentType = '') {
    return String(contentType || '').split(';')[0].trim().toLowerCase();
}

function getAudioContentTypeFromExtension(format = 'mp3') {
    return AUDIO_MIME_BY_EXTENSION[String(format || '').toLowerCase()] || getMiniMaxMusicMimeType(format);
}

function getAudioExtensionFromContentType(contentType = '') {
    return AUDIO_EXTENSION_BY_MIME[normalizeAudioContentType(contentType)] || null;
}

function getAudioExtensionFromUrl(audioUrl = '') {
    try {
        const parsedUrl = new URL(audioUrl);
        const match = parsedUrl.pathname.match(/\.([a-z0-9]+)$/i);
        return match?.[1]?.toLowerCase() || null;
    } catch {
        return null;
    }
}

function getTimestampMillis(value) {
    if (!value) return Date.now();
    if (typeof value === 'number') return value;
    if (value instanceof Date) return value.getTime();
    if (typeof value.toMillis === 'function') return value.toMillis();
    if (typeof value.toDate === 'function') return value.toDate().getTime();
    if (typeof value.seconds === 'number') return value.seconds * 1000;
    if (typeof value._seconds === 'number') return value._seconds * 1000;
    return Date.now();
}

function getAudioHistoryStorageKey(data = {}) {
    return data.b2_key || data.storageKey || data.key || null;
}

async function readAudioSourceAsBuffer(audioSource, preferredFormat = 'mp3') {
    const source = String(audioSource || '').trim();
    if (!source) throw new Error('Hiányzó audio forrás');

    if (source.startsWith('data:')) {
        const match = source.match(/^data:([^;,]+)(?:;[^,]*)?,(.*)$/);
        if (!match) throw new Error('Érvénytelen data audio URL');
        const normalizedContentType = normalizeAudioContentType(match[1]);
        const contentType = normalizedContentType.startsWith('audio/')
            ? normalizedContentType
            : getAudioContentTypeFromExtension(preferredFormat);
        const buffer = Buffer.from(match[2], 'base64');
        if (buffer.length > AUDIO_ARCHIVE_MAX_BYTES) throw new Error('Az audio túl nagy a mentéshez');
        return {
            buffer,
            contentType,
            fileFormat: getAudioExtensionFromContentType(contentType) || preferredFormat || 'mp3',
        };
    }

    const safeAudioUrl = await assertSafeExternalAudioUrl(source);
    const upstream = await axios.get(safeAudioUrl, {
        responseType: 'arraybuffer',
        timeout: 180000,
        maxRedirects: 3,
        maxContentLength: AUDIO_ARCHIVE_MAX_BYTES,
        httpsAgent,
        headers: {
            Accept: 'audio/*,application/octet-stream,*/*;q=0.8',
        },
    });

    const buffer = Buffer.from(upstream.data);
    if (buffer.length > AUDIO_ARCHIVE_MAX_BYTES) throw new Error('Az audio túl nagy a mentéshez');

    const normalizedContentType = normalizeAudioContentType(upstream.headers['content-type']);
    const contentType = normalizedContentType.startsWith('audio/')
        ? normalizedContentType
        : getAudioContentTypeFromExtension(preferredFormat);
    return {
        buffer,
        contentType,
        fileFormat: getAudioExtensionFromContentType(contentType) || getAudioExtensionFromUrl(safeAudioUrl) || preferredFormat || 'mp3',
    };
}

async function persistGeneratedAudio(userId, audioSource, metadata = {}) {
    try {
        if (!process.env.B2_BUCKET_NAME || !process.env.B2_ENDPOINT || !process.env.B2_KEY_ID || !process.env.B2_APP_KEY) {
            console.warn('[AudioArchive] B2 nincs teljesen beállítva, archív mentés kihagyva');
            return null;
        }

        const preferredFormat = String(metadata.fileFormat || metadata.format || 'mp3').toLowerCase();
        const { buffer, contentType, fileFormat } = await readAudioSourceAsBuffer(audioSource, preferredFormat);
        const timestamp = Date.now();
        const rand = Math.random().toString(36).slice(2, 8);
        const safeFormat = String(fileFormat || preferredFormat || 'mp3').replace(/[^a-z0-9]/gi, '').toLowerCase() || 'mp3';
        const b2Key = `users/${userId}/audio/${timestamp}_${rand}.${safeFormat}`;

        await uploadMediaToB2(buffer, b2Key, contentType);

        const docPayload = {
            ...metadata,
            userId,
            b2_key: b2Key,
            fileFormat: safeFormat,
            contentType,
            fileSize: buffer.length,
            storage: 'b2',
            createdAtMs: timestamp,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        };
        delete docPayload.audioUrl;

        const docRef = await admin.firestore().collection('generated_audio').add(docPayload);
        return {
            id: docRef.id,
            audioId: docRef.id,
            ...docPayload,
            createdAtMs: timestamp,
        };
    } catch (err) {
        console.error('[AudioArchive] Mentés sikertelen:', err.message);
        return null;
    }
}

function serializeGeneratedAudioDoc(doc) {
    const data = doc.data() || {};
    const createdAtMs = data.createdAtMs || getTimestampMillis(data.createdAt);
    const { b2_key, storageKey, key, userId, ...publicData } = data;
    return {
        id: doc.id,
        audioId: doc.id,
        sourceCollection: 'generated_audio',
        sourceId: doc.id,
        ...publicData,
        storage: 'b2',
        secureAudio: Boolean(getAudioHistoryStorageKey(data)),
        createdAtMs,
    };
}

function serializeAudioHistoryDoc(doc) {
    const data = doc.data() || {};
    const createdAtMs = data.createdAtMs || getTimestampMillis(data.createdAt || data.ts);
    const { b2_key, storageKey, key, userId, ...publicData } = data;
    const fileFormat = data.fileFormat || getAudioExtensionFromUrl(getAudioHistoryStorageKey(data) || '') || 'mp3';
    const routeId = `audio-history-${doc.id}`;
    return {
        id: routeId,
        audioId: routeId,
        sourceCollection: 'audio_history',
        sourceId: doc.id,
        ...publicData,
        storage: 'b2',
        secureAudio: Boolean(getAudioHistoryStorageKey(data)),
        fileFormat,
        contentType: data.contentType || 'audio/mpeg',
        fileSize: data.fileSize || data.size || null,
        createdAtMs,
    };
}

async function loadFirestoreAudioHistory(userId) {
    try {
        const snap = await admin.firestore()
            .collection('audio_history')
            .where('userId', '==', userId)
            .get();
        return snap.docs.map(serializeAudioHistoryDoc);
    } catch (err) {
        console.warn('[AudioArchive] Legacy audio_history lista sikertelen:', err.message);
        return [];
    }
}

async function loadLegacyAudioHistory(userId) {
    try {
        const userDocRef = admin.firestore().collection('audio_generations').doc(userId);
        const collections = await userDocRef.listCollections();
        const snapshots = await Promise.all(collections.map((collectionRef) =>
            collectionRef.orderBy('createdAt', 'desc').limit(30).get().catch(() => null)
        ));

        return snapshots
            .filter(Boolean)
            .flatMap((snap) => snap.docs.map((doc) => {
                const data = doc.data() || {};
                const createdAtMs = getTimestampMillis(data.createdAt);
                return {
                    id: `legacy-${doc.ref.parent.id}-${doc.id}`,
                    legacyId: doc.id,
                    legacyModelId: doc.ref.parent.id,
                    ...data,
                    storage: 'legacy',
                    secureAudio: false,
                    createdAtMs,
                };
            }));
    } catch (err) {
        console.warn('[AudioArchive] Legacy lista sikertelen:', err.message);
        return [];
    }
}

function isSupportedDeapiReferenceAudioFile(file) {
    if (!file) return false;

    const supportedMimeTypes = new Set([
        'audio/mpeg',
        'audio/mp3',
        'audio/wav',
        'audio/x-wav',
        'audio/flac',
        'audio/x-flac',
        'audio/ogg',
        'audio/mp4',
        'audio/x-m4a',
        'video/mp4',
    ]);
    const supportedExtensions = new Set(['.mp3', '.wav', '.flac', '.ogg', '.m4a']);
    const extension = path.extname(file.originalname || '').toLowerCase();

    return supportedMimeTypes.has(String(file.mimetype || '').toLowerCase()) || supportedExtensions.has(extension);
}

function isSupportedDeapiImageFile(file) {
    if (!file) return false;

    const supportedMimeTypes = new Set([
        'image/jpeg',
        'image/jpg',
        'image/png',
        'image/gif',
        'image/bmp',
        'image/webp',
    ]);
    const supportedExtensions = new Set(['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']);
    const extension = path.extname(file.originalname || '').toLowerCase();

    return supportedMimeTypes.has(String(file.mimetype || '').toLowerCase()) || supportedExtensions.has(extension);
}

function handleDeapiReferenceAudioUpload(req, res, next) {
    deapiReferenceAudioUpload.single('reference_audio')(req, res, (err) => {
        if (!err) return next();
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ success: false, message: 'A referencia audio merete legfeljebb 10 MB lehet' });
        }
        return res.status(400).json({ success: false, message: err.message || 'Referencia audio feltoltesi hiba' });
    });
}

function handleDeapiTtsReferenceAudioUpload(req, res, next) {
    deapiReferenceAudioUpload.single('ref_audio')(req, res, (err) => {
        if (!err) return next();
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ success: false, message: 'A referencia audio merete legfeljebb 10 MB lehet' });
        }
        return res.status(400).json({ success: false, message: err.message || 'Referencia audio feltoltesi hiba' });
    });
}

function handleDeapiImageUpload(req, res, next) {
    deapiImageUpload.single('image')(req, res, (err) => {
        if (!err) return next();
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ success: false, message: 'A kep merete legfeljebb 10 MB lehet' });
        }
        return res.status(400).json({ success: false, message: err.message || 'Kep feltoltesi hiba' });
    });
}

async function fetchDeapiMusicModels() {
    return fetchDeapiModelsByInferenceType('txt2music', getLocalDeapiMusicModels());
}

async function fetchDeapiTtsModels() {
    return fetchDeapiModelsByInferenceType('txt2audio', getLocalDeapiTtsModels());
}

async function findDeapiMusicModel(slug = '') {
    const normalizedSlug = normalizeDeapiModelSlug(slug);
    const models = await fetchDeapiMusicModels();
    return models.find((model) => normalizeDeapiModelSlug(model.slug) === normalizedSlug) || null;
}

async function findDeapiTtsModel(slug = '') {
    const normalizedSlug = normalizeDeapiModelSlug(slug);
    const models = await fetchDeapiTtsModels();
    return models.find((model) => normalizeDeapiModelSlug(model.slug) === normalizedSlug) || null;
}

async function resolveDeapiImageUpscaleModel(preferredModel = DEAPI_IMAGE_UPSCALE_MODEL) {
    const fallbackModels = [
        { slug: DEAPI_IMAGE_UPSCALE_MODEL, name: 'RealESRGAN x4', info: { defaults: {}, limits: {} } },
    ];
    const models = await fetchDeapiModelsByInferenceType('img-upscale', fallbackModels);
    const normalizedPreferred = normalizeDeapiModelSlug(preferredModel);
    const selected = models.find((model) => normalizeDeapiModelSlug(model.slug) === normalizedPreferred) || models[0];
    return selected?.slug || preferredModel;
}

async function submitDeapiTextToMusic(payload, signal, referenceAudioFile = null) {
    const client = getDeapiClient();
    const form = new FormData();

    Object.entries(payload).forEach(([key, value]) => {
        if (value === undefined || value === null || value === '') return;
        form.append(key, String(value));
    });

    if (referenceAudioFile?.buffer) {
        form.append('reference_audio', referenceAudioFile.buffer, {
            filename: referenceAudioFile.originalname || 'reference-audio',
            contentType: referenceAudioFile.mimetype || 'application/octet-stream',
            knownLength: referenceAudioFile.size,
        });
    }

    try {
        const response = await client.post('/api/v2/audio/music', form, {
            headers: {
                ...form.getHeaders(),
                Accept: 'application/json',
                Authorization: `Bearer ${process.env.DEAPI_API_KEY}`,
            },
            signal,
        });

        return response.data;
    } catch (err) {
        throw normalizeDeapiError(err);
    }
}

async function submitDeapiTextToAudio(payload, signal, referenceAudioFile = null) {
    const client = getDeapiClient();
    const form = new FormData();

    Object.entries(payload).forEach(([key, value]) => {
        if (value === undefined || value === null || value === '') return;
        form.append(key, String(value));
    });

    if (referenceAudioFile?.buffer) {
        form.append('ref_audio', referenceAudioFile.buffer, {
            filename: referenceAudioFile.originalname || 'reference-audio',
            contentType: referenceAudioFile.mimetype || 'application/octet-stream',
            knownLength: referenceAudioFile.size,
        });
    }

    try {
        const response = await client.post('/api/v2/audio/speech', form, {
            headers: {
                ...form.getHeaders(),
                Accept: 'application/json',
                Authorization: `Bearer ${process.env.DEAPI_API_KEY}`,
            },
            signal,
        });

        return response.data;
    } catch (err) {
        throw normalizeDeapiError(err);
    }
}

async function submitDeapiImageUpscale(imageFile, signal, model = DEAPI_IMAGE_UPSCALE_MODEL) {
    const client = getDeapiClient();
    const form = new FormData();

    form.append('image', imageFile.buffer, {
        filename: imageFile.originalname || 'upscale-source.png',
        contentType: imageFile.mimetype || 'image/png',
        knownLength: imageFile.size,
    });
    form.append('model', model);

    try {
        const response = await client.post('/api/v2/images/upscales', form, {
            headers: {
                ...form.getHeaders(),
                Accept: 'application/json',
                Authorization: `Bearer ${process.env.DEAPI_API_KEY}`,
            },
            signal,
        });

        return response.data;
    } catch (err) {
        throw normalizeDeapiError(err);
    }
}

async function waitForAbortableDelay(ms, signal) {
    if (!signal) {
        await new Promise((resolve) => setTimeout(resolve, ms));
        return;
    }

    await new Promise((resolve, reject) => {
        const timeoutId = setTimeout(() => {
            signal.removeEventListener('abort', onAbort);
            resolve();
        }, ms);

        const onAbort = () => {
            clearTimeout(timeoutId);
            signal.removeEventListener('abort', onAbort);
            const abortError = new Error('AbortError');
            abortError.name = 'AbortError';
            reject(abortError);
        };

        if (signal.aborted) {
            onAbort();
            return;
        }

        signal.addEventListener('abort', onAbort, { once: true });
    });
}

function extractDeapiAudioUrl(result = {}) {
    const candidates = [
        result.result_url,
        result.audio_url,
        result.audioUrl,
        result.output_url,
        result.file_url,
        result.url,
        result.result,
        result.data?.result_url,
        result.data?.audio_url,
        result.data?.audioUrl,
        result.data?.url,
        result.data?.result,
    ];

    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.trim()) return candidate.trim();
        if (Array.isArray(candidate)) {
            const nested = extractDeapiAudioUrl({ result: candidate[0] });
            if (nested) return nested;
        }
        if (candidate && typeof candidate === 'object') {
            const nested = extractDeapiAudioUrl(candidate);
            if (nested) return nested;
        }
    }

    return '';
}

function extractDeapiImageUrl(result = {}) {
    const candidates = [
        result.result_url,
        result.image_url,
        result.imageUrl,
        result.output_url,
        result.file_url,
        result.url,
        result.image,
        result.result,
        result.images,
        result.output_images,
        result.data?.result_url,
        result.data?.image_url,
        result.data?.imageUrl,
        result.data?.output_url,
        result.data?.file_url,
        result.data?.url,
        result.data?.image,
        result.data?.result,
        result.data?.images,
        result.data?.output_images,
    ];

    for (const candidate of candidates) {
        if (typeof candidate === 'string' && candidate.trim()) {
            const value = candidate.trim();
            if (/^https?:\/\//i.test(value) || value.startsWith('data:image/')) return value;
            if (/^[A-Za-z0-9+/=\s]+$/.test(value) && value.length > 100) {
                return `data:image/png;base64,${value.replace(/\s+/g, '')}`;
            }
        }
        if (Array.isArray(candidate)) {
            for (const item of candidate) {
                const nested = typeof item === 'string'
                    ? extractDeapiImageUrl({ url: item })
                    : extractDeapiImageUrl(item || {});
                if (nested) return nested;
            }
        }
        if (candidate && typeof candidate === 'object') {
            const nested = extractDeapiImageUrl(candidate);
            if (nested) return nested;
        }
    }

    return '';
}

async function pollDeapiResult(requestId, signal, onStatus = null, options = {}) {
    const client = getDeapiClient();
    const startedAt = Date.now();
    const estimatedDuration = Math.max(30, Number(options.estimatedDuration || 180));
    const label = options.label || 'deAPI feladat';
    const pollIntervalMs = 15000;
    const maxPolls = Math.max(1, Math.round(Number(process.env.DEAPI_MAX_STATUS_POLLS || 13)));

    for (let pollCount = 0; pollCount < maxPolls; pollCount += 1) {
        await waitForAbortableDelay(pollIntervalMs, signal);

        let response;
        try {
            response = await client.get(`/api/v2/jobs/${requestId}`, { signal });
        } catch (err) {
            throw normalizeDeapiError(err);
        }

        const data = response.data?.data || {};
        const status = String(data.status || '').toLowerCase();
        const elapsed = Math.round((Date.now() - startedAt) / 1000);
        const upstreamProgress = Number(data.progress ?? data.percentage ?? data.percent);
        const progress = Number.isFinite(upstreamProgress)
            ? Math.max(8, Math.min(Math.round(upstreamProgress), 96))
            : getPredictedDeapiProgress(elapsed, estimatedDuration);

        onStatus?.({
            status: status || 'processing',
            progress,
            elapsed,
            requestId,
            predicted: !Number.isFinite(upstreamProgress),
        });

        const isResultReady = typeof options.isResultReady === 'function'
            ? Boolean(options.isResultReady(data, response.data))
            : Boolean(extractDeapiAudioUrl(data));

        if (['done', 'completed', 'success', 'succeeded'].includes(status) || (!status && isResultReady)) {
            return data;
        }
        if (['error', 'failed', 'cancelled', 'canceled'].includes(status)) {
            throw new Error(data.error_message || data.error || response.data?.message || `${label} hibaval leallt`);
        }
    }

    throw new Error(`${label} ${maxPolls} status polling utan sem keszult el. A napi deAPI jobs polling vedelme miatt leallitottuk a varakozast.`);
}

router.get('/deapi/music-models', verifyFirebaseToken, audioLimiter, async (req, res) => {
    try {
        if (!process.env.DEAPI_API_KEY) {
            return res.status(500).json({ success: false, message: 'DEAPI_API_KEY nincs beállítva' });
        }

        const models = await fetchDeapiMusicModels();
        return res.json({
            success: true,
            models: models.map((model) => ({
                name: model.name || model.slug,
                slug: model.slug,
                defaults: model.info?.defaults || {},
                limits: model.info?.limits || {},
                modes: model.info?.modes || ['custom_voice'],
                features: model.info?.features || {},
            })),
        });
    } catch (err) {
        console.error('❌ deAPI model lista hiba:', err.response?.data || err.message || err);
        return res.status(err.response?.status || 500).json({
            success: false,
            message: err.response?.data?.message || err.message || 'A deAPI modelllista nem tölthető be',
        });
    }
});

router.get('/deapi/tts-models', verifyFirebaseToken, audioLimiter, async (req, res) => {
    try {
        if (!process.env.DEAPI_API_KEY) {
            return res.status(500).json({ success: false, message: 'DEAPI_API_KEY nincs beallitva' });
        }

        const models = await fetchDeapiTtsModels();
        return res.json({
            success: true,
            models: models.map((model) => ({
                name: model.name || model.slug,
                slug: model.slug,
                defaults: model.info?.defaults || {},
                limits: model.info?.limits || {},
            })),
        });
    } catch (err) {
        console.error('deAPI TTS model lista hiba:', err.response?.data || err.message || err);
        return res.status(err.response?.status || 500).json({
            success: false,
            message: err.response?.data?.message || err.message || 'A deAPI TTS modelllista nem toltheto be',
        });
    }
});

router.post('/audio/download', verifyFirebaseToken, audioLimiter, async (req, res) => {
    try {
        const safeAudioUrl = await assertSafeExternalAudioUrl(req.body?.audioUrl);
        const filename = sanitizeAudioDownloadFilename(req.body?.filename);

        const upstream = await axios.get(safeAudioUrl, {
            responseType: 'stream',
            timeout: 120000,
            maxRedirects: 3,
            httpsAgent,
            headers: {
                Accept: 'audio/*,application/octet-stream,*/*;q=0.8',
            },
        });

        const contentType = upstream.headers['content-type'] || 'application/octet-stream';
        const contentLength = upstream.headers['content-length'];
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Cache-Control', 'private, no-store');
        if (contentLength) res.setHeader('Content-Length', contentLength);
        upstream.data.pipe(res);
    } catch (err) {
        console.error('❌ audio download proxy hiba:', err.response?.data || err.message || err);
        if (!res.headersSent) {
            res.status(400).json({
                success: false,
                message: err.response?.data?.message || err.message || 'Az audio letöltése nem sikerült',
            });
        }
    }
});

router.post('/image/download', verifyFirebaseToken, imageLimiter, async (req, res) => {
    try {
        const imageKey = String(req.body?.imageKey || '');
        const filename = sanitizeImageDownloadFilename(req.body?.filename);

        if (imageKey) {
            if (!imageKey.startsWith(`users/${req.userId}/images/full/`)) {
                return res.status(403).json({ success: false, message: 'Ervenytelen kep kulcs' });
            }

            const result = await b2.send(new GetObjectCommand({
                Bucket: process.env.B2_BUCKET_NAME,
                Key: imageKey,
            }));

            res.setHeader('Content-Type', result.ContentType || 'image/png');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('Cache-Control', 'private, no-store');
            if (result.ContentLength) res.setHeader('Content-Length', result.ContentLength);
            result.Body.pipe(res);
            return;
        }

        const safeImageUrl = await assertSafeExternalImageUrl(req.body?.imageUrl);
        const upstream = await axios.get(safeImageUrl, {
            responseType: 'stream',
            timeout: 180000,
            maxRedirects: 3,
            httpsAgent,
            headers: {
                Accept: 'image/*,application/octet-stream,*/*;q=0.8',
            },
        });

        const contentType = upstream.headers['content-type'] || 'image/png';
        const lowerContentType = String(contentType).toLowerCase();
        if (!lowerContentType.startsWith('image/') && !lowerContentType.startsWith('application/octet-stream')) {
            throw new Error('A letoltott fajl nem kep');
        }

        const contentLength = upstream.headers['content-length'];
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Cache-Control', 'private, no-store');
        if (contentLength) res.setHeader('Content-Length', contentLength);
        upstream.data.pipe(res);
    } catch (err) {
        console.error('image download proxy hiba:', err.response?.data || err.message || err);
        if (!res.headersSent) {
            res.status(400).json({
                success: false,
                message: err.response?.data?.message || err.message || 'A kep letoltese nem sikerult',
            });
        }
    }
});

router.get('/audio/history', verifyFirebaseToken, audioLimiter, async (req, res) => {
    try {
        const userId = req.userId;
        const snap = await admin.firestore()
            .collection('generated_audio')
            .where('userId', '==', userId)
            .get();

        const storedItems = snap.docs.map(serializeGeneratedAudioDoc);
        const [audioHistoryItems, legacyItems] = await Promise.all([
            loadFirestoreAudioHistory(userId),
            loadLegacyAudioHistory(userId),
        ]);
        const items = [...storedItems, ...audioHistoryItems, ...legacyItems]
            .sort((a, b) => (b.createdAtMs || 0) - (a.createdAtMs || 0))
            .slice(0, 100);

        return res.json({ success: true, items });
    } catch (err) {
        console.error('[AudioArchive] Lista hiba:', err);
        return res.status(500).json({ success: false, message: 'Audio archívum lekérdezése sikertelen' });
    }
});

router.get('/audio/history/:id/file', verifyFirebaseToken, audioLimiter, async (req, res) => {
    try {
        const db = admin.firestore();
        const requestedId = String(req.params.id || '');
        let collectionName = 'generated_audio';
        let docId = requestedId;
        if (requestedId.startsWith('audio-history-')) {
            collectionName = 'audio_history';
            docId = requestedId.slice('audio-history-'.length);
        }

        let doc = await db.collection(collectionName).doc(docId).get();
        if (!doc.exists && collectionName === 'generated_audio') {
            const fallbackDoc = await db.collection('audio_history').doc(docId).get();
            if (fallbackDoc.exists) {
                collectionName = 'audio_history';
                doc = fallbackDoc;
            }
        }
        if (!doc.exists) return res.status(404).json({ success: false, message: 'Audio nem található' });

        const data = doc.data() || {};
        if (data.userId !== req.userId) {
            return res.status(403).json({ success: false, message: 'Nincs jogosultság' });
        }
        const storageKey = getAudioHistoryStorageKey(data);
        if (!storageKey) {
            return res.status(404).json({ success: false, message: 'Audio fajl nem talalhato' });
        }

        const isOwnArchiveKey = String(storageKey).startsWith(`users/${req.userId}/audio/`);
        const canReadStorage = isOwnArchiveKey || await canAccessMarketplaceStorageKey(db, {
            userId: req.userId,
            key: storageKey,
            assetId: data.marketplaceAssetId || null,
        });
        if (!canReadStorage) {
            return res.status(403).json({ success: false, message: 'You need to buy this asset first' });
        }

        const result = await b2.send(new GetObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: storageKey,
        }));

        const filename = data.fileName || `ludusgen_audio_${doc.id}.${data.fileFormat || getAudioExtensionFromUrl(storageKey) || 'mp3'}`;
        res.setHeader('Content-Type', data.contentType || 'audio/mpeg');
        res.setHeader('Content-Disposition', `inline; filename="${sanitizeAudioDownloadFilename(filename)}"`);
        res.setHeader('Cache-Control', 'private, max-age=3600');
        if (result.ContentLength) res.setHeader('Content-Length', result.ContentLength);
        result.Body.pipe(res);
    } catch (err) {
        console.error('[AudioArchive] Stream hiba:', err);
        if (!res.headersSent) {
            res.status(500).json({ success: false, message: 'Audio stream sikertelen' });
        }
    }
});

router.post('/generate-music', verifyFirebaseToken, audioLimiter, handleDeapiReferenceAudioUpload, async (req, res) => {
    let musicSseStarted = false;
    const startMusicSse = () => {
        if (musicSseStarted) return;
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('X-Accel-Buffering', 'no');
        if (typeof res.flushHeaders === 'function') res.flushHeaders();
        musicSseStarted = true;
    };
    const emitMusicSse = (data) => {
        if (res.writableEnded || res.destroyed) return;
        startMusicSse();
        res.write(`data: ${JSON.stringify(data)}\n\n`);
        if (typeof res.flush === 'function') res.flush();
    };

    try {
        const {
            apiId,
            provider,
            prompt = '',
            lyrics = '',
            lyrics_optimizer = false,
            is_instrumental = false,
            stream = false,
            output_format = 'url',
            audio_setting = {},
            model = '',
            caption = '',
            duration = 30,
            inference_steps = 8,
            guidance_scale = 7,
            seed = -1,
            format = 'mp3',
            bpm = null,
            keyscale = null,
            timesignature = null,
            vocal_language = null,
            lyrics_mode = null,
            jobId,
        } = req.body;
        const controller = new AbortController();
        registerJob(jobId, controller, 600000);

        if (provider === 'deapi') {
            if (!process.env.DEAPI_API_KEY) {
                return res.status(500).json({ success: false, message: 'DEAPI_API_KEY nincs beállítva' });
            }
            if (!apiId) {
                return res.status(400).json({ success: false, message: 'Hiányzó deAPI task azonosító' });
            }

            const referenceAudioFile = req.file || null;
            if (referenceAudioFile && !isSupportedDeapiReferenceAudioFile(referenceAudioFile)) {
                return res.status(400).json({ success: false, message: 'A referencia audio csak MP3, WAV, FLAC, OGG vagy M4A lehet' });
            }

            const safeCaption = String(caption || '').trim();
            const safeModel = String(model || '').trim();
            const safeLyrics = String(lyrics || '').trim();
            const hasLyricsField = Object.prototype.hasOwnProperty.call(req.body || {}, 'lyrics');

            if (!safeCaption) {
                return res.status(400).json({ success: false, message: 'A deAPI caption mező kötelező' });
            }
            if (!safeModel) {
                return res.status(400).json({ success: false, message: 'A deAPI model slug kötelező' });
            }
            if (!hasLyricsField) {
                return res.status(400).json({ success: false, message: 'A deAPI lyrics mező kötelező. Instrumentálhoz használd: [Instrumental]' });
            }

            if (!safeLyrics) {
                return res.status(400).json({ success: false, message: 'A deAPI lyrics mezĹ‘ nem lehet ĂĽres. Auto-lyrics mĂłdban elĹ‘bb generĂˇlni kell dalszĂ¶veget.' });
            }

            const selectedDeapiModel = await findDeapiMusicModel(safeModel);
            if (!selectedDeapiModel) {
                return res.status(400).json({ success: false, message: `Ismeretlen deAPI modell slug: ${safeModel}` });
            }

            const modelLimits = selectedDeapiModel.info?.limits || {};
            const minCaptionLength = getDeapiNumericLimit(modelLimits, 'min_caption');
            const maxCaptionLength = getDeapiNumericLimit(modelLimits, 'max_caption');
            const minDuration = getDeapiNumericLimit(modelLimits, 'min_duration', 10);
            const maxDuration = getDeapiNumericLimit(modelLimits, 'max_duration', 600);
            const minSteps = getDeapiNumericLimit(modelLimits, 'min_steps', 1);
            const maxSteps = getDeapiNumericLimit(modelLimits, 'max_steps', 100);
            const minGuidance = getDeapiNumericLimit(modelLimits, 'min_guidance', 0);
            const maxGuidance = getDeapiNumericLimit(modelLimits, 'max_guidance', 20);
            const minBpm = getDeapiNumericLimit(modelLimits, 'min_bpm');
            const maxBpm = getDeapiNumericLimit(modelLimits, 'max_bpm');

            if (Number.isFinite(minCaptionLength) && safeCaption.length < minCaptionLength) {
                return res.status(400).json({ success: false, message: `A deAPI caption legalább ${minCaptionLength} karakter legyen ennél a modellnél` });
            }
            if (Number.isFinite(maxCaptionLength) && safeCaption.length > maxCaptionLength) {
                return res.status(400).json({ success: false, message: `A deAPI caption legfeljebb ${maxCaptionLength} karakter lehet ennél a modellnél` });
            }

            const safeDuration = normalizeDeapiMusicNumber(duration, {
                min: minDuration,
                max: maxDuration,
                fallback: minDuration,
                integer: true,
            });
            const safeInferenceSteps = normalizeDeapiMusicNumber(inference_steps, {
                min: minSteps,
                max: maxSteps,
                fallback: minSteps,
                integer: true,
            });
            const safeGuidanceScale = normalizeDeapiMusicNumber(guidance_scale, {
                min: minGuidance,
                max: maxGuidance,
                fallback: minGuidance,
            });
            const seedText = String(seed ?? '').trim();
            const parsedSeed = Number(seedText);
            const safeSeed = seedText === '' || !Number.isFinite(parsedSeed) ? -1 : Math.trunc(parsedSeed);
            const safeFormat = String(format || '').trim() || 'flac';
            const safeBpm = bpm === null || bpm === ''
                ? null
                : normalizeDeapiMusicNumber(bpm, {
                    min: minBpm ?? 30,
                    max: maxBpm ?? 300,
                    fallback: null,
                    integer: true,
                });
            const safeKeyscale = String(keyscale || '').trim() || null;
            const safeTimeSignature = timesignature === null || timesignature === '' ? null : normalizeDeapiMusicNumber(timesignature, { min: 2, max: 6, fallback: null, integer: true });
            const safeVocalLanguage = String(vocal_language || '').trim() || null;
            const safeLyricsMode = ['instrumental', 'auto-lyrics', 'lyrics'].includes(String(lyrics_mode || '').trim())
                ? String(lyrics_mode).trim()
                : safeLyrics === '[Instrumental]' ? 'instrumental' : 'lyrics';

            if (safeTimeSignature !== null && ![2, 3, 4, 6].includes(safeTimeSignature)) {
                return res.status(400).json({ success: false, message: 'A deAPI timesignature csak 2, 3, 4 vagy 6 lehet' });
            }
            const submissionPayload = {
                caption: safeCaption,
                model: safeModel,
                lyrics: safeLyrics,
                duration: safeDuration,
                inference_steps: safeInferenceSteps,
                guidance_scale: safeGuidanceScale,
                seed: safeSeed,
                format: safeFormat,
                bpm: safeBpm,
                keyscale: safeKeyscale,
                timesignature: safeTimeSignature,
                vocal_language: safeVocalLanguage,
            };

            const deapiStartedAt = Date.now();
            emitMusicSse({ type: 'status', status: 'SUBMITTING', progress: 4, elapsed: 0 });
            const submission = await submitDeapiTextToMusic(submissionPayload, controller.signal, referenceAudioFile);
            const requestId = submission?.data?.request_id;
            if (!requestId) {
                throw new Error('A deAPI nem adott vissza request_id-t');
            }

            emitMusicSse({ type: 'status', status: 'QUEUED', progress: 8, elapsed: 0, requestId });
            const result = await pollDeapiResult(requestId, controller.signal, (event) => {
                emitMusicSse({
                    type: 'status',
                    status: String(event.status || 'processing').toUpperCase(),
                    progress: event.progress,
                    elapsed: event.elapsed,
                    requestId: event.requestId,
                    predicted: Boolean(event.predicted),
                });
            });

            const audioUrl = extractDeapiAudioUrl(result);
            if (!audioUrl) {
                throw new Error('A deAPI nem adott vissza letoltheto audio URL-t');
            }
            const deapiElapsed = Math.round((Date.now() - deapiStartedAt) / 1000);
            emitMusicSse({ type: 'status', status: 'FINALIZING', progress: 96, elapsed: deapiElapsed, requestId });

            const archiveItem = await persistGeneratedAudio(req.userId, audioUrl, {
                type: 'music',
                prompt: safeCaption,
                caption: safeCaption,
                lyrics: safeLyrics,
                lyricsMode: safeLyricsMode,
                instrumental: safeLyricsMode === 'instrumental',
                autoLyrics: safeLyricsMode === 'auto-lyrics',
                provider: 'deapi',
                modelId: apiId,
                deapiModel: safeModel,
                duration: safeDuration,
                inferenceSteps: safeInferenceSteps,
                guidanceScale: safeGuidanceScale,
                seed: safeSeed,
                fileFormat: safeFormat,
                bpm: safeBpm,
                keyscale: safeKeyscale,
                timesignature: safeTimeSignature,
                vocalLanguage: safeVocalLanguage,
                hasReferenceAudio: Boolean(referenceAudioFile),
                requestId,
                stream: false,
                outputFormat: 'url',
            });

            await logUsage(req.userId, 'music', {
                provider: 'deapi',
                task: apiId,
                model: safeModel,
                duration: safeDuration,
                inference_steps: safeInferenceSteps,
                guidance_scale: safeGuidanceScale,
                seed: safeSeed,
                format: safeFormat,
                bpm: safeBpm,
                keyscale: safeKeyscale,
                timesignature: safeTimeSignature,
                vocal_language: safeVocalLanguage,
                hasWebhook: false,
                hasReferenceAudio: Boolean(referenceAudioFile),
                audioId: archiveItem?.id || null,
            });
            unregisterJob(jobId);
            emitMusicSse({
                type: 'done',
                success: true,
                audioUrl: archiveItem ? null : audioUrl,
                audioId: archiveItem?.id || null,
                historyItem: archiveItem,
                fileFormat: safeFormat,
                outputFormat: 'url',
                requestId,
                stream: false,
                elapsed: deapiElapsed,
            });
            return res.end();
        }

        const safePrompt = String(prompt || '').trim();
        const safeLyrics = String(lyrics || '').trim();
        const safeInstrumental = Boolean(is_instrumental);
        const safeLyricsOptimizer = Boolean(!safeInstrumental && lyrics_optimizer);
        const safeStream = Boolean(stream);
        const safeOutputFormat = safeStream ? 'hex' : output_format === 'hex' ? 'hex' : 'url';
        const safeSampleRate = MINIMAX_MUSIC_SAMPLE_RATES.includes(Number(audio_setting?.sample_rate))
            ? Number(audio_setting.sample_rate)
            : 44100;
        const safeBitrate = MINIMAX_MUSIC_BITRATES.includes(Number(audio_setting?.bitrate))
            ? Number(audio_setting.bitrate)
            : 256000;
        const safeFileFormat = MINIMAX_MUSIC_FORMATS.includes(String(audio_setting?.format || '').toLowerCase())
            ? String(audio_setting.format).toLowerCase()
            : 'mp3';

        if (!apiId) {
            return res.status(400).json({ success: false, message: 'Hiányzó MiniMax modellazonosító' });
        }
        if (provider !== 'minimax') {
            return res.status(400).json({ success: false, message: `Ismeretlen zene provider: ${provider}` });
        }
        if (!process.env.MINIMAX_API_KEY) {
            return res.status(500).json({ success: false, message: 'MINIMAX_API_KEY nincs beállítva' });
        }
        if (safeInstrumental && !safePrompt) {
            return res.status(400).json({ success: false, message: 'Instrumentális módnál prompt megadása kötelező' });
        }
        if (!safeInstrumental && !safeLyrics && !(safeLyricsOptimizer && safePrompt)) {
            return res.status(400).json({ success: false, message: 'Adj meg dalszöveget, vagy kapcsold be az AI dalszöveg-generálást prompttal' });
        }
        if (!safeInstrumental && !safeLyrics && safeLyricsOptimizer && !safePrompt) {
            return res.status(400).json({ success: false, message: 'AI dalszöveg-generáláshoz prompt szükséges' });
        }

        const payload = {
            model: apiId,
            stream: safeStream,
            output_format: safeOutputFormat,
            lyrics_optimizer: safeLyricsOptimizer,
            is_instrumental: safeInstrumental,
            audio_setting: {
                sample_rate: safeSampleRate,
                bitrate: safeBitrate,
                format: safeFileFormat,
            },
        };

        if (safePrompt) payload.prompt = safePrompt;
        if (safeLyrics) payload.lyrics = safeLyrics;

        const result = await callMiniMaxMusicGeneration(payload, controller.signal);
        const statusCode = result?.base_resp?.status_code ?? 0;
        if (statusCode !== 0) {
            throw new Error(result?.base_resp?.status_msg || 'MiniMax zenegenerálási hiba');
        }

        const rawAudio = result?.data?.audio || result?.data?.audio_url || '';
        const audioUrl = normalizeMiniMaxMusicAudio(rawAudio, safeFileFormat);
        if (!audioUrl) throw new Error('Nem érkezett vissza lejátszható audio a MiniMax API-tól');

        const archiveItem = await persistGeneratedAudio(req.userId, audioUrl, {
            type: 'music',
            prompt: safePrompt || safeLyrics.slice(0, 160),
            lyrics: safeLyrics,
            lyricsOptimizer: safeLyricsOptimizer,
            instrumental: safeInstrumental,
            provider: 'minimax',
            modelId: apiId,
            model: apiId,
            stream: safeStream,
            outputFormat: safeOutputFormat,
            sampleRate: result?.extra_info?.music_sample_rate || safeSampleRate,
            bitrate: result?.extra_info?.bitrate || safeBitrate,
            fileFormat: safeFileFormat,
        });

        await logUsage(req.userId, 'music', {
            provider: 'minimax',
            model: apiId,
            stream: safeStream,
            output_format: safeOutputFormat,
            sample_rate: safeSampleRate,
            bitrate: safeBitrate,
            format: safeFileFormat,
            hasLyrics: Boolean(safeLyrics),
            lyricsOptimizer: safeLyricsOptimizer,
            instrumental: safeInstrumental,
            audioId: archiveItem?.id || null,
        });
        unregisterJob(jobId);
        return res.json({
            success: true,
            audioUrl: archiveItem ? null : audioUrl,
            audioId: archiveItem?.id || null,
            historyItem: archiveItem,
            fileFormat: safeFileFormat,
            outputFormat: safeOutputFormat,
            sampleRate: result?.extra_info?.music_sample_rate || safeSampleRate,
            bitrate: result?.extra_info?.bitrate || safeBitrate,
            stream: safeStream,
        });

    } catch (err) {
        unregisterJob(req.body.jobId);
        const clientMessage = isDeapiRateLimitError(err)
            ? (err.message || buildDeapiRateLimitMessage(err))
            : err.message || 'Zenegeneralasi hiba';
        if (musicSseStarted) {
            const message = err.name === 'AbortError'
                ? 'Folyamat megszakitva (User/Timeout)'
                : clientMessage;
            emitMusicSse({ type: 'error', message });
            return res.end();
        }
        if (res.headersSent) return;
        if (err.response || err.status || err.isAxiosError) {
            console.error('Music gen hiba:', {
                status: err.status || err.response?.status || null,
                code: err.code || null,
                message: err.response?.data?.message || err.message || 'Unknown error',
                deapiRateLimit: Boolean(isDeapiRateLimitError(err)),
            });
            return res.status(err.status || err.response?.status || 500).json({ success: false, message: clientMessage });
        }
        if (err.name === 'AbortError') return res.status(408).json({ success: false, message: 'Folyamat megszakítva (User/Timeout)' });
        console.error('❌ Music gen hiba:', err);
        return res.status(500).json({ success: false, message: err.message || 'Zenegenerálási hiba' });
    }
});

// ════════════════════════════════════════════════════
// 5.  USAGE STATS  —  GET /api/usage-stats
// ════════════════════════════════════════════════════
router.get('/usage-stats', verifyFirebaseToken, async (req, res) => {
    try {
        const monthStart = new Date();
        monthStart.setDate(1);
        monthStart.setHours(0, 0, 0, 0);

        const snap = await admin.firestore()
            .collection('usage_logs')
            .where('userId', '==', req.userId)
            .where('createdAt', '>=', admin.firestore.Timestamp.fromDate(monthStart))
            .orderBy('createdAt', 'desc')
            .limit(500)
            .get();

        const stats = { chat: 0, image: 0, tts: 0, music: 0, total: 0 };
        snap.docs.forEach((d) => { const t = d.data().type; if (t in stats) stats[t]++; stats.total++; });

        return res.json({ success: true, stats, period: 'month' });
    } catch (err) {
        console.error('❌ Usage stats hiba:', err);
        return res.status(500).json({ success: false, message: 'Statisztika hiba' });
    }
});

// ════════════════════════════════════════════════════
// 6.  MESHY — Text to 3D
// ════════════════════════════════════════════════════
router.post('/meshy/text-to-3d', verifyFirebaseToken, genLimiter, async (req, res) => {
    if (!MESHY_KEY) return res.status(500).json({ success: false, message: 'MESHY_API_KEY nincs beállítva' });

    const { prompt, ai_model = 'latest', topology = 'triangle', target_polycount = 100_000, should_remesh = false, symmetry_mode = 'auto', pose_mode = '', moderation = false, jobId } = req.body;

    if (!prompt?.trim()) return res.status(400).json({ success: false, message: 'Prompt megadása kötelező' });
    if (prompt.length > 600) return res.status(400).json({ success: false, message: 'Prompt max 600 karakter' });

    const controller = new AbortController();
    registerJob(jobId, controller, 1800000);

    try {
        const { data } = await meshy.post('/openapi/v2/text-to-3d', {
            mode: 'preview', prompt: prompt.trim(), ai_model, topology,
            target_polycount: Math.min(Math.max(100, Number(target_polycount)), 300_000),
            should_remesh, symmetry_mode, ...(pose_mode ? { pose_mode } : {}), moderation
        }, { signal: controller.signal });

        await logUsage(req.userId, 'meshy_text_to_3d', { prompt: prompt.slice(0, 80), ai_model });
        unregisterJob(jobId);
        return res.json({ success: true, task_id: data.result });
    } catch (err) {
        unregisterJob(jobId);
        if (err.name === 'AbortError') return res.status(499).json({ success: false, message: 'Folyamat megszakítva' });
        return res.status(err.response?.status || 500).json({ success: false, message: err.response?.data?.message || err.message || 'Meshy API hiba' });
    }
});

// ════════════════════════════════════════════════════
// 7.  MESHY — Image to 3D
// ════════════════════════════════════════════════════
router.post('/meshy/image-to-3d', verifyFirebaseToken, genLimiter, async (req, res) => {
    if (!MESHY_KEY) return res.status(500).json({ success: false, message: 'MESHY_API_KEY nincs beállítva' });

    const { image_url, model_type = 'standard', ai_model = 'latest', topology = 'triangle', target_polycount = 100_000, symmetry_mode = 'auto', should_remesh = false, should_texture = true, enable_pbr = false, pose_mode = '', texture_prompt = '', moderation = false, jobId } = req.body;

    if (!image_url) return res.status(400).json({ success: false, message: 'image_url megadása kötelező' });

    const controller = new AbortController();
    registerJob(jobId, controller, 1800000);

    try {
        const { data } = await meshy.post('/openapi/v1/image-to-3d', {
            image_url, model_type, ai_model, topology,
            target_polycount: Math.min(Math.max(100, Number(target_polycount)), 300_000),
            symmetry_mode, should_remesh, should_texture, enable_pbr,
            ...(pose_mode ? { pose_mode } : {}),
            ...(texture_prompt ? { texture_prompt } : {}), moderation
        }, { signal: controller.signal });

        await logUsage(req.userId, 'meshy_image_to_3d', { ai_model });
        unregisterJob(jobId);
        return res.json({ success: true, task_id: data.result });
    } catch (err) {
        unregisterJob(jobId);
        if (err.name === 'AbortError') return res.status(499).json({ success: false, message: 'Folyamat megszakítva' });
        return res.status(err.response?.status || 500).json({ success: false, message: err.response?.data?.message || err.message || 'Meshy API hiba' });
    }
});

// ════════════════════════════════════════════════════
// 8.  MESHY — Refine
// ════════════════════════════════════════════════════
router.post('/meshy/refine', verifyFirebaseToken, async (req, res) => {
    if (!MESHY_KEY) return res.status(500).json({ success: false, message: 'MESHY_API_KEY nincs beállítva' });

    const { preview_task_id, enable_pbr = true, texture_prompt = '', texture_image_url = '', ai_model = 'latest', moderation = false, jobId } = req.body;

    if (!preview_task_id) return res.status(400).json({ success: false, message: 'preview_task_id kötelező' });

    const controller = new AbortController();
    registerJob(jobId, controller, 1800000);

    try {
        const { data } = await meshy.post('/openapi/v2/text-to-3d', {
            mode: 'refine', preview_task_id, enable_pbr, ai_model, moderation,
            ...(texture_prompt ? { texture_prompt } : {}),
            ...(texture_image_url ? { texture_image_url } : {})
        }, { signal: controller.signal });

        await logUsage(req.userId, 'meshy_refine', { preview_task_id });
        unregisterJob(jobId);
        return res.json({ success: true, task_id: data.result });
    } catch (err) {
        unregisterJob(jobId);
        if (err.name === 'AbortError') return res.status(499).json({ success: false, message: 'Folyamat megszakítva' });
        return res.status(err.response?.status || 500).json({ success: false, message: err.response?.data?.message || err.message || 'Meshy refine hiba' });
    }
});

// ════════════════════════════════════════════════════
// 9.  MESHY — Task státusz
// ════════════════════════════════════════════════════
router.get('/meshy/task/:type/:taskId', verifyFirebaseToken, async (req, res) => {
    if (!MESHY_KEY) return res.status(500).json({ success: false, message: 'MESHY_API_KEY nincs beállítva' });

    const { type, taskId } = req.params;
    const endpoint = type === 'text-to-3d' ? `/openapi/v2/text-to-3d/${taskId}` : `/openapi/v1/image-to-3d/${taskId}`;

    try {
        const { data } = await meshy.get(endpoint);
        return res.json({ success: true, status: data.status, progress: data.progress ?? 0, model_urls: data.model_urls ?? {}, thumbnail_url: data.thumbnail_url ?? null, task_error: data.task_error ?? null });
    } catch (err) {
        return res.status(err.response?.status || 500).json({ success: false, message: err.response?.data?.message || 'Taszk lekérdezési hiba' });
    }
});

// ════════════════════════════════════════════════════
// 10. MESHY — Előzmények
// ════════════════════════════════════════════════════
router.get('/meshy/history', verifyFirebaseToken, async (req, res) => {
    try {
        const snap = await admin.firestore()
            .collection('usage_logs')
            .where('userId', '==', req.userId)
            .where('type', 'in', ['meshy_text_to_3d', 'meshy_image_to_3d', 'meshy_refine'])
            .orderBy('createdAt', 'desc')
            .limit(50)
            .get();

        const logs = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
        return res.json({ success: true, logs });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Előzmény lekérdezési hiba' });
    }
});

// ════════════════════════════════════════════════════
// TRELLIS — B2 helpers
// ════════════════════════════════════════════════════
import fetch from 'node-fetch';

const TRELLIS_NIM_URL = 'https://ai.api.nvidia.com/v1/genai/microsoft/trellis';
const keepAliveAgent = new https.Agent({ keepAlive: true, timeout: 190_000 });

const b2 = new S3Client({
    region: 'us-east-005',
    endpoint: process.env.B2_ENDPOINT,
    credentials: { accessKeyId: process.env.B2_KEY_ID, secretAccessKey: process.env.B2_APP_KEY },
    forcePathStyle: true,
});

async function uploadMediaToB2(buffer, key, contentType) {
    await b2.send(new PutObjectCommand({
        Bucket: process.env.B2_BUCKET_NAME,
        Key: key,
        Body: buffer,
        ContentType: contentType,
    }));
    return key;
}

function safeGalleryDocId(value) {
    return String(value || '')
        .replace(/[^a-zA-Z0-9_-]/g, '_')
        .replace(/_+/g, '_')
        .replace(/^_+|_+$/g, '')
        .slice(0, 180);
}

function isAllowedGalleryImportSource(source) {
    const value = String(source || '');
    if (value.startsWith('data:image/')) return true;
    try {
        const parsed = new URL(value);
        if (!['http:', 'https:'].includes(parsed.protocol)) return false;
        const host = parsed.hostname.toLowerCase();
        return host === 'tripo3d.ai' ||
            host === 'tripo3d.com' ||
            host.endsWith('.tripo3d.ai') ||
            host.endsWith('.tripo3d.com');
    } catch {
        return false;
    }
}

async function processImageAndUpload(userId, sourceUrlOrBase64, metadata) {
    try {
        const galleryCollection = admin.firestore().collection('generated_images');
        const requestedDocId = safeGalleryDocId(metadata.docId);
        if (requestedDocId) {
            const existing = await galleryCollection.doc(requestedDocId).get();
            if (existing.exists && existing.data()?.userId === userId) {
                return {
                    id: existing.id,
                    duplicate: true,
                    fullKey: existing.data()?.full_key || null,
                    thumbKey: existing.data()?.thumb_key || null,
                    width: existing.data()?.width || null,
                    height: existing.data()?.height || null,
                    contentType: existing.data()?.contentType || 'image/png',
                    extension: 'png',
                };
            }
        }

        let inputBuffer;
        let originalMime = 'image/png';

        if (sourceUrlOrBase64.startsWith('data:')) {
            const parts = sourceUrlOrBase64.split(',');
            inputBuffer = Buffer.from(parts[1], 'base64');
            originalMime = parts[0].match(/:(.*?);/)?.[1] || 'image/png';
        } else {
            const resp = await axios.get(sourceUrlOrBase64, { responseType: 'arraybuffer' });
            inputBuffer = Buffer.from(resp.data);
            originalMime = resp.headers['content-type'] || 'image/png';
        }

        const meta = await sharp(inputBuffer).metadata();
        const ext = meta.format || 'png';

        const timestamp = Date.now();
        const rand = Math.random().toString(36).slice(2, 7);
        const baseFilename = `${timestamp}_${rand}`;

        // 1. Full resolution upload - DIRECT BUFFER (No re-encoding!)
        const fullKey = `users/${userId}/images/full/${baseFilename}.${ext}`;
        await uploadMediaToB2(inputBuffer, fullKey, originalMime);

        // 2. Thumbnail upload - (Still re-encoded for speed)
        const thumbKey = `users/${userId}/images/thumb/${baseFilename}.webp`;
        const thumbBuffer = await sharp(inputBuffer)
            .resize(300, null, { withoutEnlargement: true })
            .webp({ quality: 80 })
            .toBuffer();
        await uploadMediaToB2(thumbBuffer, thumbKey, 'image/webp');

        const storedWidth = metadata.width || meta.width || 1024;
        const storedHeight = metadata.height || meta.height || 1024;

        // 3. Save to Firestore
        const galleryPayload = {
            userId,
            full_key: fullKey,
            thumb_key: thumbKey,
            prompt: metadata.prompt || '',
            modelId: metadata.modelId || '',
            provider: metadata.provider || '',
            aspect_ratio: metadata.aspect_ratio || '1:1',
            width: storedWidth,
            height: storedHeight,
            operation: metadata.operation || null,
            requestId: metadata.requestId || null,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        };

        let docRef;
        if (requestedDocId) {
            docRef = galleryCollection.doc(requestedDocId);
            await docRef.set(galleryPayload);
        } else {
            docRef = await galleryCollection.add(galleryPayload);
        }

        return {
            id: docRef.id,
            fullKey,
            thumbKey,
            width: storedWidth,
            height: storedHeight,
            contentType: originalMime,
            extension: ext,
        };
    } catch (err) {
        console.error('[GalleryStore] Error:', err.message);
        return null;
    }
}

async function streamB2Key(key, filename, res) {
    const allowed = await canAccessMarketplaceStorageKey(admin.firestore(), {
        userId: res.req?.userId,
        key,
    });
    if (!allowed) {
        res.status(403).json({ success: false, message: 'Elobb meg kell vasarolnod az assetet' });
        return;
    }

    const cmd = new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key });
    const data = await b2.send(cmd);
    res.setHeader('Content-Type', key.endsWith('.glb') ? 'model/gltf-binary' : 'image/png');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Cache-Control', 'private, max-age=3600');
    data.Body.pipe(res);
}

async function deleteFromB2(key) {
    try {
        await b2.send(new DeleteObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }));
        return true;
    } catch (err) {
        console.warn('B2 törlés sikertelen:', err.message);
        return false;
    }
}

async function mapWithConcurrency(items, limit, mapper) {
    const results = new Array(items.length);
    let index = 0;

    async function worker() {
        while (index < items.length) {
            const current = index++;
            results[current] = await mapper(items[current], current);
        }
    }

    const workerCount = Math.min(Math.max(limit, 1), items.length || 1);
    await Promise.all(Array.from({ length: workerCount }, () => worker()));
    return results;
}

const AUDIO_MIME_EXT = {
    'audio/mpeg': 'mp3',
    'audio/mp3': 'mp3',
    'audio/wav': 'wav',
    'audio/x-wav': 'wav',
    'audio/ogg': 'ogg',
    'audio/aac': 'aac',
    'audio/flac': 'flac',
    'audio/mp4': 'm4a',
};

function safeAudioName(name = 'ludusgen_audio') {
    return String(name || 'ludusgen_audio')
        .replace(/[^\w.\-]+/g, '_')
        .replace(/_+/g, '_')
        .slice(0, 120);
}

function parseDataAudioUrl(audioUrl) {
    const match = String(audioUrl || '').match(/^data:([^;,]+)?(?:;[^,]*)?;base64,(.+)$/);
    if (!match) return null;
    const contentType = match[1] || 'audio/mpeg';
    return {
        buffer: Buffer.from(match[2], 'base64'),
        contentType,
    };
}

function audioExtFrom(contentType, fallback = 'mp3') {
    const clean = String(contentType || '').split(';')[0].trim().toLowerCase();
    return AUDIO_MIME_EXT[clean] || fallback;
}

async function loadAudioBuffer(audioUrl, req = null) {
    const dataAudio = parseDataAudioUrl(audioUrl);
    if (dataAudio) return dataAudio;

    let targetUrl = String(audioUrl || '');
    if (targetUrl.startsWith('/api/')) {
        const host = req?.get?.('host') || `localhost:${process.env.PORT || 3001}`;
        targetUrl = `${req?.protocol || 'http'}://${host}${targetUrl}`;
    }
    if (!/^https?:\/\//.test(targetUrl)) {
        throw new Error('Nem tamogatott audio URL');
    }

    const response = await axios.get(targetUrl, {
        responseType: 'arraybuffer',
        timeout: 90_000,
        headers: {
            ...(req?.headers?.authorization ? { Authorization: req.headers.authorization } : {}),
            'User-Agent': 'LudusGen-AudioHistory/1.0',
        },
    });
    return {
        buffer: Buffer.from(response.data),
        contentType: response.headers['content-type'] || 'audio/mpeg',
    };
}

async function persistAudioToHistory(userId, audioUrl, metadata = {}) {
    if (!userId || !audioUrl) return null;

    const { buffer, contentType } = await loadAudioBuffer(audioUrl);
    const fileFormat = String(metadata.fileFormat || audioExtFrom(contentType)).replace(/^\./, '').toLowerCase();
    const now = Date.now();
    const id = `${now}_${Math.random().toString(36).slice(2, 10)}`;
    const fileName = `${safeAudioName(metadata.title || metadata.type || 'ludusgen_audio')}_${id}.${fileFormat}`;
    const storageKey = `users/${userId}/audio/${fileName}`;

    await uploadMediaToB2(buffer, storageKey, contentType);

    const docRef = await admin.firestore().collection('generated_audio').add({
        userId,
        type: metadata.type || 'audio',
        title: metadata.title || 'LudusGen audio',
        prompt: metadata.prompt || '',
        provider: metadata.provider || '',
        model: metadata.model || '',
        duration: metadata.duration || null,
        b2_key: storageKey,
        fileName,
        fileFormat,
        contentType,
        fileSize: buffer.length,
        storage: 'b2',
        createdAtMs: now,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        ts: now,
    });

    return {
        id: docRef.id,
        storageKey,
        fileName,
        fileFormat,
        contentType,
        size: buffer.length,
    };
}

router.post('/audio/download', verifyFirebaseToken, async (req, res) => {
    try {
        const { audioUrl, filename = 'ludusgen_audio.mp3' } = req.body || {};
        if (!audioUrl) return res.status(400).json({ success: false, message: 'Hianyzo audio URL' });
        const { buffer, contentType } = await loadAudioBuffer(audioUrl, req);
        res.setHeader('Content-Type', contentType || 'audio/mpeg');
        res.setHeader('Content-Disposition', `attachment; filename="${safeAudioName(filename)}"`);
        res.setHeader('Cache-Control', 'private, max-age=60');
        res.send(buffer);
    } catch (err) {
        console.error('[AudioDownload] error:', err);
        res.status(500).json({ success: false, message: err.message || 'Audio letoltes sikertelen' });
    }
});

router.get('/trellis/model/:filename', verifyFirebaseToken, async (req, res) => {
    const key = `trellis/${req.params.filename}`;
    try { await streamB2Key(key, req.params.filename, res); }
    catch (err) { res.status(404).json({ success: false, message: 'Fájl nem található' }); }
});

router.get('/trellis/proxy', verifyFirebaseToken, async (req, res) => {
    let key = req.query.key;
    if (!key && req.query.url) {
        try { const u = new URL(req.query.url); key = u.pathname.replace(/^\/[^/]+\//, ''); }
        catch { return res.status(400).json({ success: false, message: 'Érvénytelen URL' }); }
    }
    if (!key) return res.status(400).json({ success: false, message: 'Hiányzó key vagy url param' });
    const filename = key.split('/').pop();
    try { await streamB2Key(key, filename, res); }
    catch (err) { res.status(404).json({ success: false, message: 'Fájl nem található' }); }
});

router.delete('/trellis/history/:id', verifyFirebaseToken, async (req, res) => {
    const { id } = req.params;
    const userId = req.userId;
    if (!id) return res.status(400).json({ success: false, message: 'Hiányzó modell ID' });

    try {
        const docRef = admin.firestore().collection('trellis_history').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(404).json({ success: false, message: 'Modell nem található' });
        const data = doc.data();
        if (data.userId !== userId) return res.status(403).json({ success: false, message: 'Nincs jogosultság' });

        if (data.b2_key) { await deleteFromB2(data.b2_key); }
        else if (data.model_url?.includes('/api/trellis/model/')) { await deleteFromB2(`trellis/${data.model_url.split('/').pop()}`); }

        await docRef.delete();
        return res.json({ success: true, message: 'Modell sikeresen törölve', deletedId: id });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Szerverhiba', error: err.message });
    }
});

router.delete('/trellis/history', verifyFirebaseToken, async (req, res) => {
    const userId = req.userId;
    try {
        const snapshot = await admin.firestore().collection('trellis_history').where('userId', '==', userId).get();
        if (snapshot.empty) return res.json({ success: true, message: 'Nincs törlendő előzmény', deletedCount: 0 });

        const deletePromises = [];
        for (const doc of snapshot.docs) {
            const data = doc.data();
            if (data.b2_key) deletePromises.push(deleteFromB2(data.b2_key));
            else if (data.model_url?.includes('/api/trellis/model/')) deletePromises.push(deleteFromB2(`trellis/${data.model_url.split('/').pop()}`));
        }
        await Promise.allSettled(deletePromises);

        const batch = admin.firestore().batch();
        snapshot.docs.forEach(doc => batch.delete(doc.ref));
        await batch.commit();

        return res.json({ success: true, message: `${snapshot.size} modell sikeresen törölve`, deletedCount: snapshot.size });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Szerverhiba', error: err.message });
    }
});

// ════════════════════════════════════════════════════
// TRELLIS — Generálás
// ════════════════════════════════════════════════════
router.post('/trellis', verifyFirebaseToken, genLimiter, async (req, res) => {
    const { prompt, seed = 0, slat_cfg_scale = 3, ss_cfg_scale = 7.5, slat_sampling_steps = 25, ss_sampling_steps = 25, jobId } = req.body;

    if (!prompt || !String(prompt).trim()) return res.status(400).json({ success: false, message: 'A prompt megadása kötelező' });
    if (String(prompt).length > 1000) return res.status(400).json({ success: false, message: 'A prompt maximum 1000 karakter lehet' });

    const apiKey = process.env.NVIDIA_API_KEY;
    if (!apiKey) return res.status(500).json({ success: false, message: 'NVIDIA_API_KEY nincs beállítva' });

    const payload = {
        prompt: String(prompt).trim(),
        seed: Math.min(2147483647, Math.max(0, Math.floor(Number(seed) || 0))),
        slat_cfg_scale: Number(slat_cfg_scale),
        ss_cfg_scale: Number(ss_cfg_scale),
        slat_sampling_steps: Math.round(Number(slat_sampling_steps)),
        ss_sampling_steps: Math.round(Number(ss_sampling_steps)),
    };

    const controller = new AbortController();
    // Modell generálásnál 30 perc (1800s) timeout
    registerJob(jobId, controller, 1800000);

    try {
        const nimResp = await fetch(TRELLIS_NIM_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'Authorization': `Bearer ${apiKey}`, 'Connection': 'keep-alive' },
            body: JSON.stringify(payload),
            signal: controller.signal,
            agent: keepAliveAgent,
        });

        if (!nimResp.ok) {
            const errText = await nimResp.text();
            const msg = nimResp.status === 401 ? 'Érvénytelen NVIDIA API kulcs' : nimResp.status === 429 ? 'NVIDIA rate limit' : `Trellis hiba (${nimResp.status}): ${errText.slice(0, 200)}`;
            return res.status(nimResp.status).json({ success: false, message: msg });
        }

        const body = await nimResp.json();
        let base64Glb = null;
        if (Array.isArray(body.artifacts) && body.artifacts.length > 0) {
            const art = body.artifacts[0];
            base64Glb = art.base64 ?? art.glb ?? art.model ?? art.data ?? null;
        }
        if (!base64Glb) base64Glb = body.base64 ?? body.glb ?? body.model ?? null;
        if (!base64Glb) return res.status(500).json({ success: false, message: 'A Trellis API nem adott vissza 3D modellt' });

        const filename = `trellis_${Date.now()}_${payload.seed}.glb`;
        let glbUrl, b2Key = null;

        try {
            const buffer = Buffer.from(base64Glb, 'base64');
            b2Key = await storageService.uploadFile(buffer, `trellis/${filename}`, 'model/gltf-binary');
            glbUrl = `/api/trellis/model/${filename}`;
        } catch (b2Err) {
            console.error('Trellis B2 upload failed:', b2Err.message);
            glbUrl = `data:model/gltf-binary;base64,${base64Glb}`;
        }

        await logUsage(req.userId, 'trellis', { prompt: payload.prompt.slice(0, 80), seed: payload.seed, b2_key: b2Key });
        return res.json({ success: true, glb_url: glbUrl, b2_key: b2Key });

    } catch (err) {
        if (err.name === 'AbortError') {
            if (!res.headersSent) res.status(499).json({ success: false, message: 'Generálás megszakítva' });
            return;
        }
        return res.status(500).json({ success: false, message: err.message ?? 'Hálózati hiba' });
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
        req.off('close', onClose);
    }
});

// ════════════════════════════════════════════════════
// SUMMARY endpointok
// ════════════════════════════════════════════════════
router.post('/chat/summary', verifyFirebaseToken, async (req, res) => {
    try {
        const { sessionId, messages, modelId } = req.body;
        if (!sessionId || !Array.isArray(messages) || messages.length === 0) {
            return res.status(400).json({ success: false, message: 'Hiányzó sessionId vagy üzenetek' });
        }

        const summaryPrompt = `Summarize this conversation in a structured format.
Detect the language used and include it in the summary.
Format:
Topic: <main topic>
Key facts established: <facts/decisions>
User preferences: <preferences>
Open questions: <unresolved questions>
Language: <detected language>

Keep it under 150 tokens. Be concise but capture all important context.`;

        const resp = await groqWithRetry({
            model: 'openai/gpt-oss-120b',
            messages: [
                { role: 'system', content: summaryPrompt },
                ...messages.slice(-20).map(m => ({ role: m.role, content: String(m.content).slice(0, 500) })),
            ],
            temperature: 0.3,
            max_tokens: 200,
            stream: false,
        });

        const summaryText = resp.data?.choices?.[0]?.message?.content || '';
        if (!summaryText) return res.status(500).json({ success: false, message: 'Üres summary' });

        const db = admin.firestore();
        const batch = db.batch();

        const summaryRef = db.collection('conversations').doc(req.userId).collection('sessions').doc(sessionId).collection(SUMMARY_COLLECTION).doc('latest');
        batch.set(summaryRef, { summaryText, messageCountAtSummary: messages.length, lastSummaryModelId: modelId || 'unknown', language: 'auto', createdAt: admin.firestore.FieldValue.serverTimestamp(), updatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

        const sessionRef = db.collection('conversations').doc(req.userId).collection('sessions').doc(sessionId);
        batch.set(sessionRef, { summary: summaryText, summarizedMessageCount: messages.length, summaryUpdatedAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });

        await batch.commit();
        return res.json({ success: true, summaryText });
    } catch (err) {
        console.error('[Summary] Generálás sikertelen:', err.message);
        return res.status(500).json({ success: false, message: 'Summary generation failed' });
    }
});

router.get('/chat/summary/:sessionId', verifyFirebaseToken, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const summaryDoc = await admin.firestore()
            .collection('conversations').doc(req.userId)
            .collection('sessions').doc(sessionId)
            .collection(SUMMARY_COLLECTION).doc('latest').get();

        if (!summaryDoc.exists) return res.json({ success: false, summary: null });
        return res.json({ success: true, summary: summaryDoc.data() });
    } catch (err) {
        return res.status(500).json({ success: false, message: err.message });
    }
});

router.post('/tripo/asset-name', verifyFirebaseToken, async (req, res) => {
    const {
        prompt = '',
        basePrompt = '',
        mode = 'generate',
        type = 'text_to_model',
        styleId = '',
        sourceName = '',
        negativePrompt = '',
        modelVersion = '',
    } = req.body || {};

    const fallbackName = buildTripoAssetNameFallback({
        mode,
        sourceName,
        basePrompt,
        prompt,
    });

    try {
        const resp = await groqWithRetry({
            model: 'openai/gpt-oss-120b',
            messages: buildTripoAssetNamingMessages({
                mode,
                type,
                prompt,
                basePrompt,
                styleId,
                sourceName,
                negativePrompt,
                modelVersion,
            }),
            temperature: 0.35,
            max_tokens: 140,
            stream: false,
        });

        const rawContent = resp.data?.choices?.[0]?.message?.content?.trim() || '';
        const jsonMatch = rawContent.match(/\{[\s\S]*\}/);
        const parsed = jsonMatch ? JSON.parse(jsonMatch[0]) : {};
        const name = normalizeTripoAssetName(parsed?.name || fallbackName) || fallbackName;
        const summary = typeof parsed?.summary === 'string' ? parsed.summary.trim() : '';
        return res.json({ success: true, name, summary });
    } catch (err) {
        console.warn('[TripoAssetName] fallback used:', err.message);
        return res.json({ success: true, name: fallbackName, summary: '' });
    }
});

router.post('/chat/switch-model', verifyFirebaseToken, async (req, res) => {
    try {
        const { sessionId, newModelId } = req.body;
        if (!sessionId || !newModelId) return res.status(400).json({ success: false, message: 'Hiányzó sessionId vagy newModelId' });

        const db = admin.firestore();
        const userId = req.userId;
        const sessionRef = db.collection('conversations').doc(userId).collection('sessions').doc(sessionId);

        const modelConfig = getModelConfig(newModelId);
        if (!modelConfig) return res.status(400).json({ success: false, message: `Ismeretlen modell: ${newModelId}` });

        const sessionDoc = await sessionRef.get();
        const sessionData = sessionDoc.exists ? sessionDoc.data() : {};

        await sessionRef.set({
            modelId: newModelId,
            modelName: modelConfig.apiModel,
        }, { merge: true });

        const messagesSnap = await sessionRef.collection('messages').orderBy('timestamp', 'asc').get();
        const allMessages = messagesSnap.docs.map((docSnap) => ({
            role: docSnap.data().role,
            content: docSnap.data().content,
        }));

        const summaryResult = await refreshSessionSummary({
            userId,
            sessionId,
            modelId: newModelId,
            allMessages,
            sessionData,
        });

        console.log(`[SwitchModel] ${sessionId} → ${newModelId} (context megőrizve)`);
        return res.json({ success: true, summaryRefreshed: summaryResult.summaryRefreshed });
    } catch (e) {
        console.error('Switch model hiba:', e);
        return res.status(500).json({ success: false, message: e.message });
    }
});

router.patch('/chat/session/:sessionId', verifyFirebaseToken, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { title } = req.body;
        if (!title) return res.status(400).json({ success: false, message: 'Hiányzó cím' });

        const db = admin.firestore();
        const userId = req.userId;
        const sessionRef = db.collection('conversations').doc(userId).collection('sessions').doc(sessionId);

        await sessionRef.update({ title });

        return res.json({ success: true, message: 'Munkamenet átnevezve' });
    } catch (e) {
        console.error('Rename session hiba:', e);
        return res.status(500).json({ success: false, message: e.message });
    }
});

router.delete('/chat/session/:sessionId', verifyFirebaseToken, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const db = admin.firestore();
        const userId = req.userId;
        const sessionRef = db.collection('conversations').doc(userId).collection('sessions').doc(sessionId);

        const sessionDoc = await sessionRef.get();
        if (!sessionDoc.exists) return res.status(404).json({ success: false, message: 'Munkamenet nem található' });

        // Töröljük az összes üzenetet
        const messagesSnap = await sessionRef.collection('messages').get();
        const batch = db.batch();
        messagesSnap.docs.forEach(doc => batch.delete(doc.ref));

        // Töröljük az összefoglalókat
        const summariesSnap = await sessionRef.collection(SUMMARY_COLLECTION).get();
        summariesSnap.docs.forEach(doc => batch.delete(doc.ref));

        // Töröljük magát a sessiont
        batch.delete(sessionRef);

        await batch.commit();

        return res.json({ success: true, message: 'Munkamenet törölve' });
    } catch (e) {
        console.error('Delete session hiba:', e);
        return res.status(500).json({ success: false, message: e.message });
    }
});


// ════════════════════════════════════════════════════
// IMAGE GALLERY endpoints
// ════════════════════════════════════════════════════

router.get('/image-gallery', verifyFirebaseToken, async (req, res) => {
    try {
        const userId = req.userId;
        const limit = clampImageGalleryLimit(req.query.limit);
        const cursor = decodeImageGalleryCursor(req.query.cursor);
        let query = admin.firestore()
            .collection('generated_images')
            .where('userId', '==', userId)
            .orderBy('createdAt', 'desc')
            .orderBy(admin.firestore.FieldPath.documentId(), 'desc')
            .limit(limit + 1);

        if (cursor?.createdAtMs && cursor?.id) {
            query = query.startAfter(
                admin.firestore.Timestamp.fromMillis(cursor.createdAtMs),
                cursor.id
            );
        }

        const snap = await query.get();
        const pageDocs = snap.docs.slice(0, limit);
        const hasMore = snap.docs.length > limit;

        const images = await Promise.all(pageDocs.map(async (doc) => {
            const data = doc.data();
            const createdAtMs = getTimestampMillis(data.createdAt);
            const createdAt = data.createdAt?.toDate
                ? data.createdAt.toDate().toISOString()
                : data.createdAt || null;
            const canReadFull = data.full_key
                ? await canAccessMarketplaceStorageKey(admin.firestore(), { userId, key: data.full_key })
                : false;
            const canReadThumb = data.thumb_key
                ? await canAccessMarketplaceStorageKey(admin.firestore(), { userId, key: data.thumb_key })
                : false;
            const fullUrl = data.full_key && canReadFull
                ? await getSignedUrl(b2, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: data.full_key }), { expiresIn: 3600 })
                : null;
            const thumbUrl = data.thumb_key && canReadThumb
                ? await getSignedUrl(b2, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: data.thumb_key }), { expiresIn: 3600 })
                : null;

            // Specifically for downloading: force attachment header
            const downloadUrl = data.full_key && canReadFull ? await getSignedUrl(b2, new GetObjectCommand({
                Bucket: process.env.B2_BUCKET_NAME,
                Key: data.full_key,
                ResponseContentDisposition: `attachment; filename="ludusgen_${doc.id}.png"`
            }), { expiresIn: 3600 }) : null;

            return {
                id: doc.id,
                prompt: data.prompt || '',
                modelId: data.modelId || '',
                provider: data.provider || '',
                aspect_ratio: data.aspect_ratio || '1:1',
                width: data.width ?? null,
                height: data.height ?? null,
                thumb_key: data.thumb_key || null,
                full_key: data.full_key || null,
                thumbUrl,
                fullUrl,
                downloadUrl,
                createdAt,
                createdAtMs,
            };
        }));

        const lastImage = images[images.length - 1];
        const nextCursor = hasMore && lastImage?.createdAtMs
            ? encodeImageGalleryCursor({ createdAtMs: lastImage.createdAtMs, id: lastImage.id })
            : null;

        res.json({ success: true, images, hasMore, nextCursor });
    } catch (err) {
        console.error('[GalleryList] Error:', err);
        res.status(500).json({ success: false, message: 'Galéria lekérdezése sikertelen' });
    }
});

router.post('/image-gallery/import', verifyFirebaseToken, async (req, res) => {
    try {
        const userId = req.userId;
        const {
            url,
            prompt = '',
            taskId = '',
            index = 0,
            type = 'tripo_image',
            mode = 'views',
            width = null,
            height = null,
            operation = 'tripo_3d_image',
        } = req.body || {};

        if (!url) return res.status(400).json({ success: false, message: 'Missing image url' });
        if (!isAllowedGalleryImportSource(url)) {
            return res.status(400).json({ success: false, message: 'Unsupported gallery import source' });
        }

        const safeTaskId = safeGalleryDocId(taskId || `manual_${Date.now()}`);
        const safeIndex = Math.max(0, Number.parseInt(index, 10) || 0);
        const stored = await processImageAndUpload(userId, url, {
            prompt,
            modelId: type || mode || 'tripo',
            provider: 'tripo',
            aspect_ratio: 'tripo',
            width,
            height,
            operation,
            requestId: `tripo:${safeTaskId}:${safeIndex}`,
            docId: `tripo_${userId}_${safeTaskId}_${safeIndex}`,
        });

        if (!stored) {
            return res.status(500).json({ success: false, message: 'Gallery import failed' });
        }

        res.json({ success: true, image: stored });
    } catch (err) {
        console.error('[GalleryImport] Error:', err);
        res.status(500).json({ success: false, message: 'Gallery import failed' });
    }
});

router.get('/image-gallery/proxy', verifyFirebaseToken, async (req, res) => {
    try {
        const userId = req.userId;
        const { key } = req.query;
        if (!key) return res.status(400).json({ success: false, message: 'Missing key' });

        // Verify the key belongs to this user
        if (!key.startsWith(`users/${userId}/`)) {
            return res.status(403).json({ success: false, message: 'Forbidden' });
        }

        const signedUrl = await getSignedUrl(b2, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 60 });
        const response = await axios.get(signedUrl, { responseType: 'arraybuffer' });
        const contentType = response.headers['content-type'] || 'image/png';
        res.set('Content-Type', contentType);
        res.set('Cache-Control', 'private, max-age=3600');
        res.send(response.data);
    } catch (err) {
        console.error('[GalleryProxy] Error:', err);
        res.status(500).json({ success: false, message: 'Proxy failed' });
    }
});

router.delete('/image-gallery/:id', verifyFirebaseToken, async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.userId;
        const docRef = admin.firestore().collection('generated_images').doc(id);
        const doc = await docRef.get();

        if (!doc.exists) return res.status(404).json({ success: false, message: 'Kép nem található' });
        const data = doc.data();
        if (data.userId !== userId) return res.status(403).json({ success: false, message: 'Nincs jogosultság' });

        // Delete from B2
        if (data.full_key) await deleteFromB2(data.full_key);
        if (data.thumb_key) await deleteFromB2(data.thumb_key);

        // Delete from Firestore
        await docRef.delete();

        res.json({ success: true, message: 'Kép sikeresen törölve' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Törlés sikertelen' });
    }
});

router.delete('/image-gallery', verifyFirebaseToken, async (req, res) => {
    try {
        const userId = req.userId;
        const col = admin.firestore().collection('generated_images');
        const snap = await col.where('userId', '==', userId).get();

        if (snap.empty) return res.json({ success: true, message: 'Nincs mit törölni' });

        // Chunking deletions for B2
        for (const doc of snap.docs) {
            const data = doc.data();
            if (data.full_key) await deleteFromB2(data.full_key);
            if (data.thumb_key) await deleteFromB2(data.thumb_key);
        }

        // Batch delete Firestore documents
        const batch = admin.firestore().batch();
        snap.docs.forEach(doc => batch.delete(doc.ref));
        await batch.commit();

        console.log(`[GalleryBulkDelete] Purged ${snap.size} objects for user ${userId}`);
        res.json({ success: true, message: 'Összes kép sikeresen törölve' });
    } catch (err) {
        console.error('[GalleryBulkDelete] Error:', err);
        res.status(500).json({ success: false, message: 'Csoportos törlés sikertelen' });
    }
});

export default router;
