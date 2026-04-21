import express from 'express';
import Anthropic from '@anthropic-ai/sdk';
import OpenAI from 'openai';
import { fal } from '@fal-ai/client';
import admin from 'firebase-admin';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import dotenv from 'dotenv';
import axios from 'axios';
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

dotenv.config();

const router = express.Router();

const REQUIRED_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'FAL_KEY', 'OPENROUTER_API_KEY', 'DEEPSEEK_API_KEY'];
REQUIRED_KEYS.forEach((key) => {
    if (!process.env[key]) console.warn(`⚠️  Hiányzó .env változó: ${key}`);
});

const activeStreams = new Map();

// ── Firebase Auth middleware ──────────────────────────────────────────────────
const verifyFirebaseToken = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split('Bearer ')[1];
        if (!token) return res.status(401).json({ success: false, message: 'Nincs autentikációs token' });

        const decoded = await admin.auth().verifyIdToken(token);
        const user = await admin.auth().getUser(decoded.uid);

        if (!user.emailVerified) {
            return res.status(403).json({ success: false, message: 'Email nincs megerősítve' });
        }

        req.userId = decoded.uid;
        req.userEmail = decoded.email;
        req.user = { uid: decoded.uid, email: decoded.email };
        next();
    } catch {
        return res.status(401).json({ success: false, message: 'Érvénytelen token' });
    }
};

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

// ── Model config ──────────────────────────────────────────────────────────────
function getModelConfig(modelId) {
    const MODEL_MAP = {
        'claude_sonnet': { apiModel: 'claude-sonnet-4-20250514', provider: 'anthropic', defaultSystemPrompt: 'You are a helpful, harmless, and honest assistant. Respond in the same language the user writes in.' },
        'claude_opus': { apiModel: 'claude-opus-4-20250514', provider: 'anthropic', defaultSystemPrompt: 'You are a helpful, harmless, and honest assistant. Respond in the same language the user writes in.' },
        'gpt4o_mini': { apiModel: 'gpt-4o-mini', provider: 'openai', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'gpt4o': { apiModel: 'gpt-4o', provider: 'openai', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'gpt4o_code': { apiModel: 'gpt-4o', provider: 'openai', defaultSystemPrompt: 'You are an elite software engineer with deep expertise across all programming languages and paradigms.\n- Produce production-ready, optimized code\n- Apply SOLID principles and design patterns\n- Include comprehensive error handling\n- Write thorough technical explanations\n- Review and suggest improvements proactively\n- Respond in the same language the user writes in' },
        'trinity-large': { apiModel: 'arcee-ai/trinity-large-preview:free', provider: 'openrouter', defaultSystemPrompt: 'You are an elite software engineer with deep expertise across all programming languages and paradigms.\n- Produce production-ready, optimized code\n- Apply SOLID principles and design patterns\n- Include comprehensive error handling\n- Write thorough technical explanations\n- Review and suggest improvements proactively\n- Respond in the same language the user writes in' },
        'gemini-3-flash': { apiModel: 'gemini-3-flash-preview', provider: 'gemini', defaultSystemPrompt: 'You are a helpful AI assistant powered by Google Gemini. Respond in the same language the user writes in.' },
        'gemini-2.5-pro': { apiModel: 'gemini-2.5-pro', provider: 'gemini', defaultSystemPrompt: 'You are a helpful AI assistant powered by Google Gemini. Respond in the same language the user writes in.' },
        'groq-gpt120b': { apiModel: 'openai/gpt-oss-120b', provider: 'groq', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'groq-qwen3': { apiModel: 'qwen/qwen3-32b', provider: 'groq', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'groq-llama70b': { apiModel: 'llama-3.3-70b-versatile', provider: 'groq', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'cerebras-llama8b': { apiModel: 'llama3.1-8b', provider: 'cerebras', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'mistral-large': { apiModel: 'mistral-large-latest', provider: 'mistral', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'nvidia-glm4.7': { apiModel: 'z-ai/glm4.7', provider: 'nvidia', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'deepseek-v3.2': { apiModel: 'deepseek-ai/deepseek-v3.2', provider: 'nvidia', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'google-gemma-3-27b-it': { apiModel: 'google/gemma-3-27b-it', provider: 'nvidia', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
    };
    return MODEL_MAP[modelId] || null;
}

// ── Rolling Context Summary konstansok ───────────────────────────────────────
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

async function generateSessionTitle(firstUserMessage) {
    try {
        const resp = await groqWithRetry({
            model: 'llama-3.3-70b-versatile',
            messages: [
                {
                    role: 'system',
                    content: 'You are a title generator. Given a user message, respond with ONLY a 2-4 word title summarizing the topic. No punctuation, no quotes, no explanation. Just the title words.',
                },
                { role: 'user', content: `Message: ${String(firstUserMessage).slice(0, 500)}\n\nTitle:` },
            ],
            temperature: 0.3,
            max_tokens: 20,
            stream: false,
        });
        const raw = resp.data?.choices?.[0]?.message?.content?.trim();
        if (!raw || raw.toLowerCase() === 'null' || raw.length < 2) return null;
        return raw;
    } catch (e) {
        console.warn('[Title] Generation failed:', e.message);
        return null;
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

        const modelId = sessionData.modelId || 'claude_sonnet';
        const modelName = sessionData.modelName || 'Claude Sonnet 4';

        const modelConfig = getModelConfig(modelId);
        if (!modelConfig) {
            return res.status(400).json({ success: false, message: `Ismeretlen modell: ${modelId}` });
        }

        const { apiModel, provider, defaultSystemPrompt } = modelConfig;

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

            const aiMsgData = {
                role: 'assistant',
                content: aiContent,
                model: modelForLog,
                modelId: modelForLog,
                modelName,
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                createdAt: new Date().toISOString(),
                ...(aiUsage.total_tokens ? { usage: aiUsage } : {}),
            };

            if (assistantMessageId) {
                await messagesRef.doc(assistantMessageId).set(aiMsgData, { merge: true });
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
                allMessages: [...baseMessages, { role: 'assistant', content: aiContent }],
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
                    totalContent += text;
                    res.write(`data: ${JSON.stringify({ delta: text })}\n\n`);
                });

                stream.on('message_stop', (message) => {
                    if (message.message?.usage) {
                        usageInfo.output_tokens = message.message.usage.output_tokens || 0;
                    }
                });

                stream.on('end', async () => {
                    if (totalContent.length > 0) {
                        try {
                            // Check if summary will be triggered
                            const totalMessages = (baseMessages?.length || 0) + 1;
                            if (totalMessages - (sessionData.summarizedMessageCount || 0) >= SUMMARY_TRIGGER_COUNT) {
                                res.write(`data: ${JSON.stringify({ summaryStarted: true })}\n\n`);
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
                            res.write(`data: ${JSON.stringify({ summaryRefreshed: summaryResult?.summaryRefreshed || false })}\n\n`);
                        } catch (e) {
                            console.error('[Chat] Anthropic mentés sikertelen:', e.message);

                        }
                    }
                    activeStreams.delete(streamKey);
                    res.write('data: [DONE]\n\n');
                    res.end();
                });

                stream.on('error', (err) => {
                    activeStreams.delete(streamKey);
                    if (err.name === 'AbortError') {
                        console.log('[Anthropic] Stream leállítva.');
                    } else {
                        console.error('Anthropic stream hiba:', err);
                        res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                    }
                    if (!res.writableEnded) res.end();
                });

            } catch (err) {
                activeStreams.delete(streamKey);
                console.error('Anthropic setup hiba:', err);
                if (!res.headersSent) {
                    res.status(500).json({ success: false, message: err.message });
                } else {
                    res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                    res.end();
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
                    parts: [{ text: Array.isArray(m.content) ? JSON.stringify(m.content) : String(m.content) }],
                }));

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
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[Gemini] Stream leállítva.');
                    return;
                }
                console.error('Gemini kapcsolódási hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
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
                        chat_template_kwargs: { enable_thinking: true }
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
                console.error('OpenRouter kapcsolódási hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
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

        const charCount = content?.length || 0;
        const estimatedTokens = Math.ceil(charCount / 4);

        await msgRef.set({
            content: content || "",
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

// ════════════════════════════════════════════════════
// 3.  TTS  —  POST /api/generate-tts
// ════════════════════════════════════════════════════
router.post('/generate-tts', verifyFirebaseToken, audioLimiter, async (req, res) => {
    try {
        const { model = 'tts-1', provider = 'openai', text, voice = 'nova', speed = 1.0, format = 'mp3', jobId } = req.body;
        const controller = new AbortController();
        registerJob(jobId, controller, 600000);

        if (!text?.trim()) return res.status(400).json({ success: false, message: 'Hiányzó szöveg' });
        if (text.length > 4096) return res.status(400).json({ success: false, message: 'Max 4096 karakter' });

        const safeSpeed = Math.min(Math.max(0.25, speed), 4.0);
        const safeFormat = ['mp3', 'opus', 'aac', 'flac'].includes(format) ? format : 'mp3';
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
            await logUsage(req.userId, 'tts', { provider: 'nvidia-riva', model: 'magpie-tts-multilingual', chars: text.length });
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

        await logUsage(req.userId, 'tts', { provider, model, chars: text.length });
        unregisterJob(jobId);
        return res.json({ success: true, audioUrl });

    } catch (err) {
        unregisterJob(req.body.jobId);
        if (err.name === 'AbortError' || err.message === 'AbortError') return res.status(499).json({ success: false, message: 'Folyamat megszakítva (User/Timeout)' });
        console.error('❌ TTS hiba:', err);
        return res.status(500).json({ success: false, message: err.message || 'TTS hiba' });
    }
});

// ════════════════════════════════════════════════════
// 4.  ZENEGENERÁLÁS  —  POST /api/generate-music
// ════════════════════════════════════════════════════
router.post('/generate-music', verifyFirebaseToken, audioLimiter, async (req, res) => {
    try {
        const { apiId, prompt, genre = '', mood = '', duration = 30, instrumental = true, jobId } = req.body;
        const controller = new AbortController();
        registerJob(jobId, controller, 600000);

        if (!apiId || !prompt?.trim()) return res.status(400).json({ success: false, message: 'Hiányzó apiId vagy prompt' });
        if (!process.env.FAL_KEY) return res.status(500).json({ success: false, message: 'FAL_KEY nincs beállítva' });

        const safeDuration = Math.min(Math.max(5, duration), 90);
        const fullPrompt = [prompt.trim(), genre ? `genre: ${genre}` : '', mood ? `mood: ${mood}` : '', instrumental ? 'instrumental, no vocals' : ''].filter(Boolean).join(', ');

        let audioUrl = '';

        if (apiId.includes('musicgen')) {
            const result = await fal.subscribe(apiId, { input: { prompt: fullPrompt, duration: safeDuration }, logs: false, signal: controller.signal });
            audioUrl = result.data?.audio?.url || result.data?.audio_file?.url || '';
        } else if (apiId.includes('stable-audio')) {
            const result = await fal.subscribe(apiId, { input: { prompt: fullPrompt, seconds_total: safeDuration, steps: 100 }, logs: false, signal: controller.signal });
            audioUrl = result.data?.audio_file?.url || result.data?.audio?.url || '';
        } else {
            return res.status(400).json({ success: false, message: `Ismeretlen zene API: ${apiId}` });
        }

        if (!audioUrl) throw new Error('Nem érkezett audio URL');
        await logUsage(req.userId, 'music', { apiId, duration: safeDuration });
        unregisterJob(jobId);
        return res.json({ success: true, audioUrl });

    } catch (err) {
        unregisterJob(req.body.jobId);
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

async function processImageAndUpload(userId, sourceUrlOrBase64, metadata) {
    try {
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

        // 3. Save to Firestore
        const docRef = await admin.firestore().collection('generated_images').add({
            userId,
            full_key: fullKey,
            thumb_key: thumbKey,
            prompt: metadata.prompt || '',
            modelId: metadata.modelId || '',
            provider: metadata.provider || '',
            aspect_ratio: metadata.aspect_ratio || '1:1',
            width: metadata.width || 1024,
            height: metadata.height || 1024,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        return docRef.id;
    } catch (err) {
        console.error('[GalleryStore] Error:', err.message);
        return null;
    }
}

async function streamB2Key(key, filename, res) {
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
            b2Key = await uploadGlbToB2(base64Glb, filename);
            glbUrl = `/api/trellis/model/${filename}`;
        } catch (b2Err) {
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
        const snap = await admin.firestore()
            .collection('generated_images')
            .where('userId', '==', userId)
            .orderBy('createdAt', 'desc')
            .limit(100)
            .get();

        if (snap.empty) return res.json({ success: true, images: [] });

        const images = await Promise.all(snap.docs.map(async (doc) => {
            const data = doc.data();
            const fullUrl = await getSignedUrl(b2, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: data.full_key }), { expiresIn: 3600 });
            const thumbUrl = await getSignedUrl(b2, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: data.thumb_key }), { expiresIn: 3600 });

            // Specifically for downloading: force attachment header
            const downloadUrl = await getSignedUrl(b2, new GetObjectCommand({
                Bucket: process.env.B2_BUCKET_NAME,
                Key: data.full_key,
                ResponseContentDisposition: `attachment; filename="ludusgen_${doc.id}.png"`
            }), { expiresIn: 3600 });

            return {
                id: doc.id,
                ...data,
                fullUrl,
                thumbUrl,
                downloadUrl,
                createdAt: data.createdAt?.toDate?.() || new Date(),
            };
        }));

        res.json({ success: true, images });
    } catch (err) {
        console.error('[GalleryList] Error:', err);
        res.status(500).json({ success: false, message: 'Galéria lekérdezése sikertelen' });
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