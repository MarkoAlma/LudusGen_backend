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
import { buildContext, trimToContextLimit, RECENT_MESSAGE_COUNT } from './src/lib/contextBuilder.js';

import { existsSync, writeFileSync, unlinkSync } from 'fs';

// ── Riva proto letöltés + betöltés (egyszer, induláskor) ───────────
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROTO_DIR  = path.join(__dirname, 'protos');
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
    const dataSize   = pcmBuffer.length;
    const byteRate   = sampleRate * channels * (bitDepth / 8);
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

// ── .env változók ellenőrzése induláskor ──────────────
const REQUIRED_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'FAL_KEY', 'OPENROUTER_API_KEY', 'DEEPSEEK_API_KEY'];
REQUIRED_KEYS.forEach((key) => {
    if (!process.env[key]) console.warn(`⚠️  Hiányzó .env változó: ${key}`);
});

// Map to track active AI streams for safe stopping
const activeStreams = new Map();

// ── API kliensek inicializálása ───────────────────────
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

fal.config({ credentials: process.env.FAL_KEY });

// ── Firebase Auth middleware ──────────────────────────
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
        next();
    } catch {
        return res.status(401).json({ success: false, message: 'Érvénytelen token' });
    }
};

// ── Rate limitek ─────────────────────────────────────
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

// ── Firestore usage log ───────────────────────────────
async function logUsage(userId, type, meta = {}) {
    try {
        const cleanMeta = Object.fromEntries(
            Object.entries(meta).filter(([, v]) => v !== undefined && v !== null)
        );
        await admin.firestore().collection('usage_logs').add({
            userId, type, ...cleanMeta,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
    } catch (e) {
        console.warn('Usage log failed:', e.message);
    }
}

// ── Segédfüggvény: messages normalizálása (vision support) ──────────
function normalizeMessages(messages) {
    if (!messages || !Array.isArray(messages)) return [];

    // 1. Basic cleaning and filtering out entirely empty content
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

    // 2. Merge consecutive messages with the same role
    const merged = [];
    for (const msg of cleaned) {
        if (merged.length > 0 && merged[merged.length - 1].role === msg.role) {
            const last = merged[merged.length - 1];
            // Merge content
            if (typeof last.content === 'string' && typeof msg.content === 'string') {
                last.content += "\n\n" + msg.content;
            } else {
                // Handle complex content (e.g. vision or mixtures)
                const lastParts = Array.isArray(last.content) ? last.content : [{ type: 'text', text: String(last.content) }];
                const nextParts = Array.isArray(msg.content) ? msg.content : [{ type: 'text', text: String(msg.content) }];
                last.content = [...lastParts, ...nextParts];
            }
        } else {
            merged.push({ ...msg });
        }
    }

    // 3. Enforce structure: System messages at front, then alternating User/Assistant starting with User
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

    // Mistral/Anthropic requirement: first message after system MUST be 'user'
    while (chatMsgs.length > 0 && chatMsgs[0].role === 'assistant') {
        chatMsgs.shift();
    }

    finalMessages.push(...chatMsgs);

    return finalMessages;
}

/**
 * Get model config by modelId.
 * This mirrors the frontend models.js structure.
 */
function getModelConfig(modelId) {
    const MODEL_MAP = {
        'claude_sonnet': { apiModel: 'claude-sonnet-4-20250514', provider: 'anthropic', defaultSystemPrompt: 'You are a helpful, harmless, and honest assistant. Respond in the same language the user writes in.' },
        'claude_opus': { apiModel: 'claude-opus-4-20250514', provider: 'anthropic', defaultSystemPrompt: 'You are a helpful, harmless, and honest assistant. Respond in the same language the user writes in.' },
        'gpt4o_mini': { apiModel: 'gpt-4o-mini', provider: 'openai', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'gpt4o': { apiModel: 'gpt-4o', provider: 'openai', defaultSystemPrompt: 'You are a helpful assistant. Respond in the same language the user writes in.' },
        'gpt4o_code': { apiModel: 'gpt-4o', provider: 'openai', defaultSystemPrompt: 'You are an elite software engineer with deep expertise across all programming languages and paradigms.\n- Produce production-ready, optimized code\n- Apply SOLID principles and design patterns\n- Include comprehensive error handling\n- Write thorough technical explanations\n- Review and suggest improvements proactively\n- Respond in the same language the user writes in' },
        'deepseek_code': { apiModel: 'arcee-ai/trinity-large-preview:free', provider: 'openrouter', defaultSystemPrompt: 'You are an elite software engineer with deep expertise across all programming languages and paradigms.\n- Produce production-ready, optimized code\n- Apply SOLID principles and design patterns\n- Include comprehensive error handling\n- Write thorough technical explanations\n- Review and suggest improvements proactively\n- Respond in the same language the user writes in' },
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

/**
 * Generate summary in background (fire-and-forget).
 * Loads ALL messages from Firestore, generates summary, saves to session doc.
 */
async function generateSummaryInBackground(userId, sessionId, modelId) {
    const db = admin.firestore();
    const messagesRef = db.collection('conversations').doc(userId).collection('sessions').doc(sessionId).collection('messages');

    // Load all messages (limit to last 50 for summary)
    const snap = await messagesRef.orderBy('timestamp', 'asc').limit(50).get();
    const messages = snap.docs.map(d => ({ role: d.data().role, content: String(d.data().content).slice(0, 2000) }));

    if (messages.length < 20) return; // Too few messages to summarize (need at least 20)

    const summaryPrompt = `Summarize this conversation in a structured format.
Detect the language used and include it in the summary.
Format:
Topic: <main topic>
Key facts established: <facts/decisions>
User preferences: <preferences>
Open questions: <unresolved questions>
Language: <detected language>

Keep it under 200 tokens. Be concise but capture all important context.`;

    const summaryMessages = [
        { role: 'system', content: summaryPrompt },
        ...messages,
    ];

    // Use Groq for summary generation (cheap and fast)
    const resp = await axios.post(
        'https://api.groq.com/openai/v1/chat/completions',
        {
            model: 'openai/gpt-oss-120b',
            messages: summaryMessages,
            temperature: 0.3,
            max_tokens: 500,
        },
        {
            headers: {
                'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
                'Content-Type': 'application/json',
            },
        }
    );

    const summaryText = resp.data.choices?.[0]?.message?.content || '';

    if (summaryText) {
        const sessionRef = db.collection('conversations').doc(userId).collection('sessions').doc(sessionId);
        await sessionRef.set({
            summary: summaryText,
            summaryGeneratedAt: admin.firestore.FieldValue.serverTimestamp(),
            summaryMessageCount: messages.length,
        }, { merge: true });

        console.log(`[Summary] Generated for session ${sessionId} (${messages.length} messages)`);
    }
}

// ── Rolling Context Summary constants ────────────────────────────────
const RECENT_MESSAGE_WINDOW = 15;
const SUMMARY_COLLECTION = 'chat_summaries';

/**
 * Build optimized message array for API call.
 * If summaryText exists: [system prompt with summary prefix] + [last N messages]
 * If no summary: [system prompt] + [all messages up to 50 limit]
 */
function buildOptimizedMessages(allMessages, systemPrompt, summaryText, recentCount = RECENT_MESSAGE_WINDOW) {
    const nonSystemMessages = allMessages.filter(m => m.role !== 'system');
    const systemMsg = allMessages.find(m => m.role === 'system');

    if (summaryText) {
        const enhancedSystemPrompt = systemPrompt
            ? `${systemPrompt}\n\n--- Korábbi üzenetek összefoglalója ---\n${summaryText}`
            : `--- Korábbi üzenetek összefoglalója ---\n${summaryText}`;

        const recentMessages = nonSystemMessages.slice(-recentCount);
        return [
            { role: 'system', content: enhancedSystemPrompt },
            ...recentMessages.map(m => ({ role: m.role, content: m.content })),
        ];
    }

    const cappedMessages = nonSystemMessages.slice(-50);
    return [
        ...(systemMsg ? [{ role: 'system', content: systemMsg.content }] : []),
        ...cappedMessages.map(m => ({ role: m.role, content: m.content })),
    ];
}

/**
 * Look up stored summary for a session.
 * Summary is only generated on explicit model switch (triggered by frontend).
 * Returns { summaryText }.
 */
async function getSummary(userId, sessionId) {
    if (!userId || !sessionId) {
        return { summaryText: null };
    }

    try {
        const db = admin.firestore();
        const summaryRef = db.collection('conversations')
            .doc(userId)
            .collection('sessions')
            .doc(sessionId)
            .collection(SUMMARY_COLLECTION)
            .doc('latest');

        const summaryDoc = await summaryRef.get();

        if (summaryDoc.exists) {
            return { summaryText: summaryDoc.data().summaryText };
        }
    } catch (e) {
        console.warn('Summary lookup failed:', e.message);
    }

    return { summaryText: null };
}

/**
 * Generate and store a summary using gpt-oss-120b via Groq.
 * Fire-and-forget — does not block the response.
 */
async function generateSummary(userId, sessionId, messages, modelId) {
    try {
        const summaryPrompt = `Summarize this conversation in a structured format.
Detect the language used and include it in the summary.
Format:
Topic: <main topic>
Key facts established: <facts/decisions>
User preferences: <preferences>
Open questions: <unresolved questions>
Language: <detected language>

Keep it under 200 tokens. Be concise but capture all important context.`;

        // Use last 30 messages, cap each at 2000 chars
        const summaryMessages = [
            { role: 'system', content: summaryPrompt },
            ...messages
                .slice(-30)
                .map(m => ({ role: m.role, content: String(m.content).slice(0, 2000) })),
        ];

        const resp = await axios.post(
            'https://api.groq.com/openai/v1/chat/completions',
            {
                model: 'openai/gpt-oss-120b',
                messages: summaryMessages,
                temperature: 0.3,
                max_tokens: 300,
                top_p: 0.9,
                stream: false,
            },
            {
                headers: {
                    'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
                    'Content-Type': 'application/json',
                },
                timeout: 30000,
            }
        );

        const summaryText = resp.data?.choices?.[0]?.message?.content || '';
        if (!summaryText) return;

        const db = admin.firestore();
        const batch = db.batch();

        // Store summary document
        const summaryRef = db.collection('conversations')
            .doc(userId)
            .collection('sessions')
            .doc(sessionId)
            .collection(SUMMARY_COLLECTION)
            .doc('latest');

        batch.set(summaryRef, {
            summaryText,
            messageCountAtSummary: messages.length,
            lastSummaryModelId: modelId || 'unknown',
            language: 'auto',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

        // Update session doc
        const sessionRef = db.collection('conversations')
            .doc(userId)
            .collection('sessions')
            .doc(sessionId);

        batch.set(sessionRef, {
            summaryGenerated: true,
            lastSummaryAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

        await batch.commit();
        console.log(`[Summary] Generated for session ${sessionId.slice(0, 12)}... (${summaryText.length} chars)`);
    } catch (err) {
        console.error('[Summary] Generation failed:', err.message);
    }
}

// ════════════════════════════════════════════════════
// 1.  CHAT  —  POST /api/chat
// ════════════════════════════════════════════════════
router.post('/chat', verifyFirebaseToken, chatLimiter, async (req, res) => {
    try {
        const { sessionId, message, attachedImage, messageId } = req.body;

        if (!sessionId) {
            return res.status(400).json({ success: false, message: 'Hiányzó sessionId' });
        }
        if (!message || (typeof message !== 'string' && !attachedImage)) {
            return res.status(400).json({ success: false, message: 'Hiányzó üzenet' });
        }

        const adminDb = admin.firestore();
        const userId = req.userId;

        // ── Centralized Abort Handling ──
        const controller = new AbortController();
        const signal = controller.signal;

        // Register the stream in activeStreams for safe stopping
        const streamKey = `${userId}:${sessionId}`;
        activeStreams.set(streamKey, controller);

        req.on('close', () => {
            console.log(`[Chat] Client disconnected, aborting AI stream...`);
            controller.abort();
            activeStreams.delete(streamKey);
        });

        // ── Load session doc ──
        const sessionRef = adminDb.collection('conversations').doc(userId).collection('sessions').doc(sessionId);
        const sessionDoc = await sessionRef.get();
        const sessionData = sessionDoc.exists ? sessionDoc.data() : {};

        const modelId = sessionData.modelId || 'claude_sonnet';
        const modelName = sessionData.modelName || 'Claude Sonnet 4';

        // Resolve model config
        const modelConfig = getModelConfig(modelId);
        if (!modelConfig) {
            return res.status(400).json({ success: false, message: `Ismeretlen modell: ${modelId}` });
        }

        const { apiModel, provider, defaultSystemPrompt } = modelConfig;

        // ── Load recent messages from Firestore ──
        const messagesRef = sessionRef.collection('messages');
        const messagesQuery = messagesRef.orderBy('timestamp', 'desc').limit(RECENT_MESSAGE_COUNT + 1);
        const messagesSnap = await messagesQuery.get();

        let sessionMessages = messagesSnap.docs
            .map(d => d.data())
            .reverse()
            .map(m => ({ role: m.role, content: m.content }));

        // ── Build new user message ──
        const newMessage = attachedImage
            ? { role: 'user', content: [{ type: 'image_url', image_url: { url: attachedImage } }, { type: 'text', text: message }] }
            : { role: 'user', content: message };

        // ── Build context ──
        const summary = sessionData.summary ? { text: sessionData.summary, messageCount: sessionData.summaryMessageCount || 0 } : null;
        let context = buildContext(sessionMessages, summary, newMessage, defaultSystemPrompt || null);

        // ── Trim to context limit if needed ──
        const maxContextTokens = 8192 * 32 * 0.8;
        context = trimToContextLimit(context, maxContextTokens);

        // ── Extract params ──
        const temperature = sessionData.temperature ?? 0.7;
        const max_tokens = sessionData.maxTokens ?? 2048;
        const top_p = sessionData.topP ?? 0.9;
        const frequency_penalty = sessionData.frequencyPenalty ?? 0;
        const presence_penalty = sessionData.presencePenalty ?? 0;

        const safeMax = Math.min(Math.max(128, max_tokens), 8192 * 32);

        // ── Helper: save AI response + update session ──
        let isResponseSaved = false;
        async function saveResponse(aiContent, aiUsage, modelForLog, providerForLog) {
            if (isResponseSaved) return; // Prevent double save
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

            if (messageId) {
                // Use provided ID to synchronize with frontend
                await messagesRef.doc(messageId).set(aiMsgData, { merge: true });
            } else {
                await messagesRef.add(aiMsgData);
            }

            const newMessageCount = (sessionData.messageCount || 0) + 2;
            // Only generate summary if we have at least 20 messages AND no existing summary,
            // OR if we have an existing summary and 20+ new messages since it was generated
            const needsSummary = (!sessionData.summary && newMessageCount >= 20) ||
                (sessionData.summary && (newMessageCount - (sessionData.summaryMessageCount || 0)) >= 20);

            await sessionRef.set({
                sessionId,
                modelId: modelForLog,
                modelName,
                lastMessage: message.slice(0, 100),
                lastRole: 'assistant',
                updatedAt: admin.firestore.FieldValue.serverTimestamp(),
                messageCount: newMessageCount,
            }, { merge: true });

            if (needsSummary) {
                generateSummaryInBackground(userId, sessionId, modelForLog).catch(e => console.warn('[Summary] Background gen failed:', e.message));
            }
        }

        // ── Anthropic ────────────────────────────────────
        if (provider === 'anthropic') {
            if (!process.env.ANTHROPIC_API_KEY) {
                return res.status(500).json({ success: false, message: 'ANTHROPIC_API_KEY nincs beállítva a .env-ben' });
            }

            const normalized = normalizeMessages(context);
            const systemMsg = normalized.find((m) => m.role === 'system');
            const chatMsgs = normalized.filter((m) => m.role !== 'system');

            const resp = await anthropic.messages.create({
                model: apiModel,
                max_tokens: safeMax,
                temperature: Math.min(Math.max(0, temperature), 1),
                ...(systemMsg ? { system: systemMsg.content } : {}),
                messages: chatMsgs,
            }, { abortSignal: signal });

            const content = resp.content?.[0]?.text || '';
            const usage = {
                input_tokens: resp.usage?.input_tokens || 0,
                output_tokens: resp.usage?.output_tokens || 0,
                total_tokens: (resp.usage?.input_tokens || 0) + (resp.usage?.output_tokens || 0),
            };

            await logUsage(req.userId, 'chat', { model: apiModel, provider, tokens: usage.total_tokens });
            await saveResponse(content, usage, modelId, provider);
            return res.json({ success: true, content, usage });
        }

        // ── OpenAI ───────────────────────────────────────
        else if (provider === 'openai') {
            if (!process.env.OPENAI_API_KEY) {
                return res.status(500).json({ success: false, message: 'OPENAI_API_KEY nincs beállítva a .env-ben' });
            }

            const resp = await openai.chat.completions.create({
                model: apiModel,
                messages: normalizeMessages(context),
                temperature: Math.min(Math.max(0, temperature), 2),
                max_tokens: safeMax,
                top_p: Math.min(Math.max(0, top_p), 1),
                frequency_penalty: Math.min(Math.max(-2, frequency_penalty), 2),
                presence_penalty: Math.min(Math.max(-2, presence_penalty), 2),
            }, { signal });

            const content = resp.choices?.[0]?.message?.content || '';
            const usage = {
                input_tokens: resp.usage?.prompt_tokens || 0,
                output_tokens: resp.usage?.completion_tokens || 0,
                total_tokens: resp.usage?.total_tokens || 0,
            };

            await logUsage(req.userId, 'chat', { model: apiModel, provider, tokens: usage.total_tokens });
            await saveResponse(content, usage, modelId, provider);
            return res.json({ success: true, content, usage });
        }

        // ── Cerebras ─────────────────────────────────────
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
                        signal, // Use global signal
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[Cerebras] Stream aborted by client.');
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
                saveResponse(totalContent, {}, modelId, 'cerebras').catch(e => console.error('[Chat] Cerebras abort-save failed:', e.message));
            });

            let totalContent = '';
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
                    } catch {}
                }
            });

            streamResp.data.on('end', async () => {
                activeStreams.delete(streamKey);
                res.write('data: [DONE]\n\n');
                res.end();
                // Always try to save what was generated so far
                if (totalContent.length > 0) {
                    try {
                        await logUsage(req.userId, 'chat', { model: apiModel, provider: 'cerebras', tokens: totalContent.length });
                        await saveResponse(totalContent, {}, modelId, 'cerebras');
                    } catch (e) {
                        console.error('[Chat] Cerebras save failed:', e.message);
                    }
                }
            });

            streamResp.data.on('error', () => {
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        // ── Mistral ───────────────────────────────────────
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
                        signal, // Use global signal
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[Mistral] Stream aborted by client.');
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
                saveResponse(totalContent, {}, modelId, 'mistral').catch(e => console.error('[Chat] Mistral abort-save failed:', e.message));
            });

            let totalContent = '';
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
                    } catch {}
                }
            });

            streamResp.data.on('end', async () => {
                activeStreams.delete(streamKey);
                res.write('data: [DONE]\n\n');
                res.end();
                // Save partial response even on disconnect
                if (totalContent.length > 0) {
                    try {
                        await logUsage(req.userId, 'chat', { model: apiModel, provider: 'mistral', tokens: totalContent.length });
                        await saveResponse(totalContent, {}, modelId, 'mistral');
                    } catch (e) {
                        console.error('[Chat] Mistral save failed:', e.message);
                    }
                }
            });

            streamResp.data.on('error', () => {
                activeStreams.delete(streamKey);
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        // ── Groq ──────────────────────────────────────────
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
            try {
                streamResp = await axios.post(
                    'https://api.groq.com/openai/v1/chat/completions',
                    {
                        model: apiModel,
                        messages: chatMsgs,
                        temperature: Math.min(Math.max(0, temperature), 2),
                        max_tokens: safeMax,
                        top_p: Math.min(Math.max(0, top_p), 1),
                        stream: true,
                    },
                    {
                        headers: {
                            'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
                            'Content-Type': 'application/json',
                        },
                        responseType: 'stream',
                        timeout: 60000,
                        signal, // Use global signal
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[Groq] Stream aborted by client.');
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
                saveResponse(totalContent, {}, modelId, 'groq').catch(e => console.error('[Chat] Groq abort-save failed:', e.message));
            });

            let totalContent = '';
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
                    } catch {}
                }
            });

            streamResp.data.on('end', async () => {
                activeStreams.delete(streamKey);
                res.write('data: [DONE]\n\n');
                res.end();
                // Save partial results even if client disconnected
                if (totalContent.length > 0) {
                    try {
                        await logUsage(req.userId, 'chat', { model: apiModel, provider: 'groq', tokens: totalContent.length });
                        await saveResponse(totalContent, {}, modelId, 'groq');
                    } catch (e) {
                        console.error('[Chat] Groq save failed:', e.message);
                    }
                }
            });

            streamResp.data.on('error', (err) => {
                activeStreams.delete(streamKey);
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        // ── Gemini ────────────────────────────────────────
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
            try {
                streamResp = await axios.post(
                    `https://generativelanguage.googleapis.com/v1beta/models/${apiModel}:streamGenerateContent?alt=sse`,
                    {
                        contents,
                        ...(systemMsg ? {
                            systemInstruction: { parts: [{ text: systemMsg.content }] }
                        } : {}),
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
                        signal, // Use global signal
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[Gemini] Stream aborted by client.');
                    return;
                }
                console.error('Gemini kapcsolódási hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

            let clientConnected = true;
            let totalContent = '';
            req.on('close', () => { 
                clientConnected = false; 
                if (!res.writableEnded) streamResp.data.destroy(); 
                saveResponse(totalContent, {}, modelId, 'gemini').catch(e => console.error('[Chat] Gemini abort-save failed:', e.message));
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
                    } catch {}
                }
            });

            streamResp.data.on('end', async () => {
                res.write('data: [DONE]\n\n');
                res.end();
                // Save partial results even if client disconnected
                if (totalContent.length > 0) {
                    try {
                        await logUsage(req.userId, 'chat', { model: apiModel, provider: 'gemini', tokens: totalContent.length });
                        await saveResponse(totalContent, {}, modelId, 'gemini');
                    } catch (e) {
                        console.error('[Chat] Gemini save failed:', e.message);
                    }
                }
            });

            streamResp.data.on('error', (err) => {
                console.error('Gemini stream hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        // ── NVIDIA — SSE Streaming + Vision támogatás ─────
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
                    },
                    {
                        headers: {
                            'Authorization': `Bearer ${process.env.NVIDIA_API_KEY}`,
                            'Content-Type': 'application/json',
                        },
                        responseType: 'stream',
                        timeout: 300000,
                        signal, // Use global signal
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[NVIDIA] Stream aborted by client.');
                    return;
                }
                console.error('NVIDIA kapcsolódási hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

            const keepAlive = setInterval(() => { if (!res.writableEnded) res.write(': ping\n\n'); }, 15000);

            let clientConnected = true;
            req.on('close', () => { 
                clientConnected = false; 
                clearInterval(keepAlive); 
                if (!res.writableEnded) streamResp.data.destroy(); 
                // Ensure partial save on disconnect
                saveResponse(totalContent, {}, modelId, 'nvidia').catch(e => console.error('[Chat] NVIDIA abort-save failed:', e.message));
            });

            let totalContent = '';
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
                    } catch {}
                }
            });

            streamResp.data.on('end', async () => {
                activeStreams.delete(streamKey);
                clearInterval(keepAlive);
                res.write('data: [DONE]\n\n');
                res.end();
                if (totalContent.length > 0) {
                    try {
                        await logUsage(req.userId, 'chat', { model: apiModel, provider: 'nvidia', tokens: totalContent.length });
                        await saveResponse(totalContent, {}, modelId, 'nvidia');
                    } catch (e) {
                        console.error('[Chat] NVIDIA save failed:', e.message);
                    }
                }
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

        // ── OpenRouter — SSE Streaming ────────────────────
        else if (provider === 'openrouter') {
            if (!process.env.OPENROUTER_API_KEY) {
                return res.status(500).json({ success: false, message: 'OPENROUTER_API_KEY nincs beállítva a .env-ben' });
            }

            const chatMsgs = normalizeMessages(context);

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            let streamResp;
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
                        signal, // Use global signal
                    }
                );
            } catch (err) {
                if (err.name === 'AbortError' || err.code === 'ERR_CANCELED') {
                    console.log('[OpenRouter] Stream aborted by client.');
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
                saveResponse(totalContent, {}, modelId, 'openrouter').catch(e => console.error('[Chat] OpenRouter abort-save failed:', e.message));
            });

            let totalContent = '';
            let buf = '';

            streamResp.data.on('data', (chunk) => {
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
                    } catch { /* csonka JSON — kihagyjuk */ }
                }
            });

            streamResp.data.on('end', async () => {
                activeStreams.delete(streamKey);
                res.write('data: [DONE]\n\n');
                res.end();
                if (totalContent.length > 0) {
                    try {
                        await logUsage(req.userId, 'chat', { model: apiModel, provider: 'openrouter', tokens: totalContent.length });
                        await saveResponse(totalContent, {}, modelId, 'openrouter');
                    } catch (e) {
                        console.error('[Chat] OpenRouter save failed:', e.message);
                    }
                }
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
        console.error('❌ Chat error:', err);
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

// ── FINALIZE — Sync visible text and update tokens ─────
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

        // Calculate approximate tokens based on the verified visible length
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

        // Also update session summary state if needed (optional)
        return res.json({ success: true, message: 'Üzenet szinkronizálva' });
    } catch (err) {
        console.error('❌ Finalize error:', err.message);
        return res.status(500).json({ success: false, message: err.message });
    }
});

// ── STOP — Safe termination of the upstream AI stream ──
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
            console.log(`[Chat] Stop requested for session ${sessionId}. Aborting upstream...`);
            controller.abort();
            activeStreams.delete(streamKey);
            return res.json({ success: true, message: 'Adatfolyam leállítva' });
        } else {
            return res.json({ success: true, message: 'Nincs aktív adatfolyam' });
        }
    } catch (err) {
        console.error('❌ Stop error:', err.message);
        return res.status(500).json({ success: false, message: err.message });
    }
});

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
        console.log(messages);
        

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

        const safeMax = Math.min(Math.max(128, max_tokens), 1024);

        const chatMsgs = normalizeMessages(optimizedMessages);


        let resp;
        try {
            resp = await axios.post(
                'https://api.groq.com/openai/v1/chat/completions',
                {
                    model,
                    messages: chatMsgs,
                    temperature:       Math.min(Math.max(0, temperature), 2),
                    max_tokens:        safeMax,
                    top_p:             Math.min(Math.max(0, top_p), 1),
                    frequency_penalty: Math.min(Math.max(-2, frequency_penalty), 2),
                    presence_penalty:  Math.min(Math.max(-2, presence_penalty), 2),
                    stream: false,
                },
                {
                    headers: {
                        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
                        'Content-Type':  'application/json',
                    },
                    timeout: 60000,
                }
            );
        } catch (err) {
            const msg = err.response?.data?.error?.message || err.message || 'Groq API hiba';
            console.error('❌ Groq API hiba:', msg);
            return res.status(err.response?.status || 500).json({ success: false, message: msg });
        }

        const choice0 = resp.data?.choices?.[0];
        const content = choice0?.message?.content ?? '';

        if (!content) {
            console.warn('⚠️ Groq üres válasz');
            console.warn('finish_reason:', choice0?.finish_reason);
            console.warn('Full resp:', JSON.stringify(resp.data).slice(0, 2000));
        }

        const usage = {
            input_tokens:  resp.data?.usage?.prompt_tokens     || 0,
            output_tokens: resp.data?.usage?.completion_tokens || 0,
            total_tokens:  resp.data?.usage?.total_tokens      || 0,
        };

        await logUsage(req.userId, 'chat', { model, provider: 'groq', tokens: usage.total_tokens });

        return res.json({ success: true, content, usage });

    } catch (err) {
        console.error('❌ Enhance error:', err);
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
      return res.status(500).json({ success: false, message: 'NVIDIA_API_KEY nincs beállítva a szerveren' });
    }

    // ── Üzenet felépítése: rendszerprompt + képek ──────────────────────────
    // A Gemma 3 27B IT NVIDIA API-n keresztül OpenAI-kompatibilis formátumot
    // vár: a képeket image_url típusú content block-ként kell átadni.
    const userContentBlocks = [
      {
        type: 'text',
        text: systemPrompt || 'Describe the uploaded image(s) in detail.',
      },
      ...images.map((dataUrl, idx) => ({
        type: 'image_url',
        image_url: {
          url: dataUrl, // base64 data URL: "data:image/jpeg;base64,..."
        },
      })),
    ];

    let resp;
    try {
      resp = await axios.post(
        'https://integrate.api.nvidia.com/v1/chat/completions',
        {
          model:       'google/gemma-3-27b-it',
          messages: [
            {
              role:    'user',
              content: userContentBlocks,
            },
          ],
          max_tokens:  1500,
          temperature: 0.2,
          top_p:       0.7,
          stream:      false,
        },
        {
          headers: {
            Authorization:  `Bearer ${process.env.NVIDIA_API_KEY}`,
            'Content-Type': 'application/json',
          },
          timeout: 90000, // vision modellek lassabbak
        }
      );
    } catch (err) {
      const msg = err.response?.data?.message || err.response?.data?.detail || err.message || 'NVIDIA API hiba';
      console.error('Vision describe NVIDIA hiba:', msg);
      return res.status(502).json({ success: false, message: `NVIDIA API hiba: ${msg}` });
    }

    const description = resp.data?.choices?.[0]?.message?.content?.trim() || '';

    if (!description) {
      console.warn('Vision describe: Gemma üres választ adott');
      console.warn('finish_reason:', resp.data?.choices?.[0]?.finish_reason);
      return res.status(500).json({ success: false, message: 'Gemma üres választ adott vissza' });
    }

    await logUsage(req.userId, 'vision-describe', {
      model:    'google/gemma-3-27b-it',
      provider: 'nvidia',
      tokens:   resp.data?.usage?.total_tokens || 0,
      images:   images.length,
    });

    return res.json({ success: true, description });

  } catch (err) {
    console.error('❌ Vision describe error:', err);
    if (!res.headersSent) {
      return res.status(500).json({
        success: false,
        message: err?.message || 'Vision describe hiba',
      });
    }
  }
});

// ── Kontext preferált felbontások ────────────────────────
const KONTEXT_PREFERRED_RESOLUTIONS = [
  [672,1568],[688,1504],[720,1456],[752,1392],[800,1328],
  [832,1248],[880,1184],[944,1104],[1024,1024],[1104,944],
  [1184,880],[1248,832],[1328,800],[1392,752],[1456,720],
  [1504,688],[1568,672],
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
        } = req.body;

        if (!prompt?.trim()) {
            return res.status(400).json({ success: false, message: 'Hiányzó prompt' });
        }

        // ── Google Gemini Image Generation ───────────────
        if (provider === 'google-image') {
            if (!process.env.GEMINI_API_KEY) {
                return res.status(500).json({ success: false, message: 'GEMINI_API_KEY nincs beállítva a .env-ben' });
            }

            console.log('🎨 Gemini image generation:', prompt.trim());

            const response = await axios.post(
                `https://generativelanguage.googleapis.com/v1beta/models/${apiId}:generateContent`,
                {
                    contents: [{
                        parts: [{ text: prompt.trim() }]
                    }],
                    generationConfig: {
                        response_modalities: ['TEXT', 'IMAGE'],
                    },
                },
                {
                    headers: {
                        'x-goog-api-key': process.env.GEMINI_API_KEY,
                        'Content-Type': 'application/json',
                    },
                    timeout: 120000,
                }
            );

            const parts = response.data?.candidates?.[0]?.content?.parts || [];
            const images = [];

            for (const part of parts) {
                if (part.inlineData?.mimeType?.startsWith('image/')) {
                    const base64 = part.inlineData.data;
                    const mimeType = part.inlineData.mimeType;
                    images.push({
                        url: `data:${mimeType};base64,${base64}`,
                        width: image_size.width || 1024,
                        height: image_size.height || 1024,
                    });
                }
            }

            if (images.length === 0) {
                throw new Error('A Gemini nem adott vissza képet. Próbálj más promptot!');
            }

            await logUsage(req.userId, 'image', { provider: 'google-image', apiId, numImages: images.length });
            return res.json({ success: true, images });
        }

        // ── ModelScope (Z-Image-Turbo) ────────────────────────
else if (provider === 'modelscope') {

    if (!process.env.MODELSCOPE_API_KEY) {
        return res.status(500).json({
            success: false,
            message: 'MODELSCOPE_API_KEY nincs beállítva a .env-ben'
        });
    }

    const msHeaders = {
        Authorization: `Bearer ${process.env.MODELSCOPE_API_KEY}`,
        'Content-Type': 'application/json',
    };

    const isQwenEditModel = apiId.includes('Qwen');
    const isKontextModel  = apiId.includes('Kontext') || apiId.includes('FLUX.1-Kontext');

    // ── input_image (single) vagy input_images (array) támogatás ─
    const rawInputImages = req.body.input_images
        ? req.body.input_images
        : input_image
            ? [input_image]
            : [];

    const isEditModel = rawInputImages.length > 0;

    let imageUrlsForApi  = [];
    let tempB2Keys       = [];
    let originalWidth    = null;
    let originalHeight   = null;
    let resizeMultiplier = 1;
    if (isEditModel) {
        try {
            for (let idx = 0; idx < rawInputImages.length; idx++) {
                const inputBuffer = Buffer.from(
                    rawInputImages[idx].replace(/^data:image\/\w+;base64,/, ''),
                    'base64'
                );

                const meta = await sharp(inputBuffer).metadata();

                if (idx === 0) {
                    originalWidth  = meta.width;
                    originalHeight = meta.height;
                }

                let processedBuffer;

                if (isQwenEditModel) {
                    const TARGET_PIXELS = 1_000_000;
                    const scaleFactor = Math.sqrt(TARGET_PIXELS / (meta.width * meta.height));
                    let newW = Math.round(meta.width  * scaleFactor / 16) * 16;
                    let newH = Math.round(meta.height * scaleFactor / 16) * 16;
                    console.log(`📐 Qwen resize: ${meta.width}x${meta.height} → ${newW}x${newH}`);
                    const areaScale = (meta.width * meta.height) / (newW * newH);
                    resizeMultiplier = Math.min(1.5, 0.4 + Math.log2(areaScale) * 0.4);
                    processedBuffer = await sharp(inputBuffer)
                        .resize(newW, newH, { fit: 'fill', kernel: 'lanczos3' })
                        .png().toBuffer();

                } else if (isKontextModel) {
                    // Kontext-specifikus: legközelebbi preferált felbontás
                    const { w: newW, h: newH } = snapToKontextResolution(meta.width, meta.height);
                    console.log(`📐 Kontext resize: ${meta.width}x${meta.height} → ${newW}x${newH}`);
                    const areaScale =
                        (meta.width * meta.height) /
                        (newW * newH);
                    resizeMultiplier = Math.min(1.5, 0.4 + Math.log2(areaScale) * 0.4);
                    processedBuffer = await sharp(inputBuffer)
                        .resize(newW, newH, { fit: 'fill', kernel: 'lanczos3' })
                        .png().toBuffer();

                } else {
                    // más edit modell: nincs resize, csak png konverzió
                    processedBuffer = await sharp(inputBuffer).png().toBuffer();
                }

                const filename = `edit_${Date.now()}_${idx}_${req.userId.slice(0, 8)}.png`;
                const tempKey  = `temp_edit/${filename}`;
                tempB2Keys.push(tempKey);

                await b2.send(new PutObjectCommand({
                    Bucket: process.env.B2_BUCKET_NAME,
                    Key: tempKey,
                    Body: processedBuffer,
                    ContentType: 'image/png',
                }));

                const signedUrl = await getSignedUrl(
                    b2,
                    new GetObjectCommand({
                        Bucket: process.env.B2_BUCKET_NAME,
                        Key: tempKey,
                    }),
                    { expiresIn: 600 }
                );

                imageUrlsForApi.push(signedUrl);
                console.log(`☁️  B2 feltöltve (#${idx + 1})`);
            }
        } catch (e) {
            console.error('B2 hiba:', e.message);
            return res.status(500).json({ success: false, message: e.message });
        }
    }

    // ── Request body ──────────────────────────────────────────────────────────

    const msBody = isEditModel
        ? {
              model:     apiId,
              prompt:    prompt.trim(),
              steps: Math.min(Math.max(1, num_inference_steps), 50),
              guidance: Math.min(Math.max(1, guidance_scale), 20),
              negative_prompt: negative_prompt ? negative_prompt.trim() : undefined,
              seed:      seed ? parseInt(seed) : undefined,
              prompt_extend,
              image_url: imageUrlsForApi,
          }
        : {
              model:  apiId,
              prompt: prompt.trim(),
              steps: Math.min(Math.max(1, num_inference_steps), 50),
              guidance: Math.min(Math.max(1, guidance_scale), 20),
              ...(negative_prompt ? { negative_prompt: negative_prompt.trim() } : {}),
              ...(seed ? { seed: parseInt(seed) } : {}),
              size: `${image_size.width || 1024}x${image_size.height || 1024}`,
          };
          console.log(msBody)

    console.log(imageUrlsForApi);

    console.log(
        'ModelScope body:',
        JSON.stringify({ ...msBody, image_url: msBody.image_url ? `[${msBody.image_url.length} URL]` : undefined })
    );

    // ── 1. Generálás indítása ─────────────────────────────────────────────────

    let taskId       = null;
    let immediateUrl = null;

    try {
        const genResp = await fetch(
            'https://api-inference.modelscope.ai/v1/images/generations',
            {
                method:  'POST',
                headers: { ...msHeaders, 'X-ModelScope-Async-Mode': 'true' },
                body:    JSON.stringify(msBody),
                signal:  AbortSignal.timeout(30000),
            }
        );

        const genData = await genResp.json();
        console.log('ModelScope gen response:', JSON.stringify(genData).slice(0, 300));

        if (!genResp.ok) {
            return res.status(500).json({
                success: false,
                message: `ModelScope hiba: ${JSON.stringify(genData?.errors || genData).slice(0, 200)}`
            });
        }

        if (genData.output_images?.length > 0) {
            immediateUrl = genData.output_images[0];
        } else if (genData.task_id) {
            taskId = genData.task_id;
            console.log(`ModelScope task_id: ${taskId}`);
        } else {
            return res.status(500).json({
                success: false,
                message: `ModelScope: ismeretlen válasz: ${JSON.stringify(genData).slice(0, 200)}`
            });
        }

    } catch (err) {
        return res.status(500).json({
            success: false,
            message: 'ModelScope kapcsolódási hiba: ' + err.message
        });
    }

    // ── Temp képek törlése B2-ről ─────────────────────────────────────────────

    const cleanupB2 = async () => {
        for (const key of tempB2Keys) {
            try {
                await b2.send(new DeleteObjectCommand({
                    Bucket: process.env.B2_BUCKET_NAME,
                    Key: key,
                }));
                console.log(`🗑️  Temp kép törölve: ${key}`);
            } catch (e) {
                console.warn('Temp kép törlése sikertelen:', e.message);
            }
        }
    };

    // ── Utófeldolgozás: fetch + visszaméretezés → base64 (csak Qwen) ──────────

const postProcess = async (url, resizeMultiplier) => {
    if (!isEditModel) {
        return { url, base64: null };
    }

    try {
        const response        = await fetch(url);
        const generatedBuffer = Buffer.from(await response.arrayBuffer());

        const genMeta = await sharp(generatedBuffer).metadata();
        console.log(`📥 Kapott kép: ${genMeta.width}x${genMeta.height}`);
        console.log(resizeMultiplier);
        
        const restored = await sharp(generatedBuffer)
            .resize(originalWidth, originalHeight, {
                fit:    'fill',
                kernel: 'lanczos3',
            })
            .sharpen({
                sigma:  resizeMultiplier,
                m1:     0.5,
                m2:     3.0,
                x1:     2.0,
                y2:     15.0,
                y3:     15.0,
            })
            .modulate({ brightness: 1.015 })
            .png({ compressionLevel: 0 })
            .toBuffer();

        const base64 = `data:image/png;base64,${restored.toString('base64')}`;
        console.log(`✅ Visszaméretezve: ${originalWidth}x${originalHeight}`);
        return { url: null, base64 };

    } catch (err) {
        console.error('Post-process hiba:', err.message);
        return { url, base64: null };
    }
};
    // ── Szinkron eredmény ─────────────────────────────────────────────────────

    if (immediateUrl) {
        await cleanupB2();
        console.log("Ez fut le (szinkron)");
        
        const { url: finalUrl, base64 } = await postProcess(immediateUrl, resizeMultiplier);
        await logUsage(req.userId, 'image', { provider: 'modelscope', apiId });
        return res.json({
            success: true,
            images: [{
                url:    base64 || finalUrl,
                width:  originalWidth  || image_size?.width  || 1024,
                height: originalHeight || image_size?.height || 1024,
            }]
        });
    }

    // ── 2. Polling ────────────────────────────────────────────────────────────

    let imageUrl = null;

    for (let i = 0; i < 150; i++) {
        await new Promise((r) => setTimeout(r, i === 0 ? 2000 : 3000));

        let pollData;
        try {
            const pollResp = await fetch(
                `https://api-inference.modelscope.ai/v1/tasks/${taskId}`,
                {
                    headers: { ...msHeaders, 'X-ModelScope-Task-Type': 'image_generation' },
                    signal:  AbortSignal.timeout(15000),
                }
            );
            pollData = await pollResp.json();
        } catch (e) {
            console.warn(`ModelScope poll [${i + 1}] hálózati hiba:`, e.message);
            continue;
        }

        const status = pollData?.task_status;
        console.log(
            `ModelScope poll [${i + 1}]: ${status}`,
            pollData?.output_images ? `→ ${pollData.output_images.length} kép` :
            pollData?.errors        ? `→ ${JSON.stringify(pollData.errors)}`    : ''
        );

        if (status === 'SUCCEED') {
            imageUrl = pollData?.output_images?.[0];
            if (!imageUrl) {
                await cleanupB2();
                return res.status(500).json({
                    success: false,
                    message: 'ModelScope SUCCEED de nincs output_images'
                });
            }
            break;

        } else if (status === 'FAILED') {
            const errDetail = pollData?.errors?.message || JSON.stringify(pollData?.errors || {});
            console.error('ModelScope FAILED:', JSON.stringify(pollData));
            await cleanupB2();
            return res.status(500).json({
                success: false,
                message: `ModelScope generálás sikertelen: ${errDetail}`
            });
        }
        // PENDING / PROCESSING → folytatjuk
    }

    if (!imageUrl) {
        return res.status(504).json({ success: false, message: 'ModelScope időtúllépés (>150s)' });
    }

    const { url: finalUrl, base64 } = await postProcess(imageUrl, resizeMultiplier);
    await cleanupB2();

    await logUsage(req.userId, 'image', { provider: 'modelscope', apiId });
    return res.json({
        success: true,
        images: [{
            url:    base64 || finalUrl,
            width:  originalWidth  || image_size?.width  || 1024,
            height: originalHeight || image_size?.height || 1024,
        }]
    });
}

        // ── Cloudflare Workers AI ─────────────────────────
        else if (provider === 'cloudflare') {
            if (!process.env.CLOUDFLARE_API_KEY) {
                return res.status(500).json({ success: false, message: 'CLOUDFLARE_API_KEY nincs beállítva a .env-ben' });
            }
            if (!process.env.CLOUDFLARE_ACCOUNT_ID) {
                return res.status(500).json({ success: false, message: 'CLOUDFLARE_ACCOUNT_ID nincs beállítva a .env-ben' });
            }

            console.log('🎨 Cloudflare AI image generation:', apiId, prompt.trim());

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
                    headers: {
                        'Authorization': `Bearer ${process.env.CLOUDFLARE_API_KEY}`,
                        'Content-Type': 'application/json',
                    },
                    responseType: 'arraybuffer',
                    timeout: 120000,
                }
            );

            const base64 = Buffer.from(cfResp.data).toString('base64');
            const contentType = cfResp.headers['content-type']?.split(';')[0] || 'image/png';

            const images = [{
                url: `data:${contentType};base64,${base64}`,
                width: image_size.width || 1024,
                height: image_size.height || 1024,
            }];

            await logUsage(req.userId, 'image', { provider: 'cloudflare', apiId, numImages: 1 });
            return res.json({ success: true, images });
        }

        // ── NVIDIA NIM Image Generation ───────────────────
        else if (provider === 'nvidia-image') {
            if (!process.env.NVIDIA_API_KEY) {
                return res.status(500).json({ success: false, message: 'NVIDIA_API_KEY nincs beállítva' });
            }

            console.log('🎨 NVIDIA NIM image generation:', apiId, prompt.trim());

            const id = apiId.toLowerCase();
            const isFluxKontext = id.includes('kontext');
            const isFlux        = id.includes('flux') && !isFluxKontext;
            const isSD3         = id.includes('stable-diffusion-3');

            const safeSeed = seed !== undefined && seed !== null && seed !== '' && !isNaN(parseInt(seed))
                ? parseInt(seed)
                : undefined;

            let requestBody;

            if (isFlux) {
                requestBody = {
                    prompt: prompt.trim(),
                    mode: 'base',
                    cfg_scale: Math.min(Math.max(1, guidance_scale), 30),
                    width: image_size?.width || 1024,
                    height: image_size?.height || 1024,
                    steps: Math.min(Math.max(1, num_inference_steps), 50),
                    ...(safeSeed !== undefined ? { seed: safeSeed } : {}),
                };
            } else if (isSD3) {
                requestBody = {
                    prompt: prompt.trim(),
                    cfg_scale: Math.min(Math.max(1, guidance_scale), 20),
                    aspect_ratio: aspect_ratio || '1:1',
                    steps: Math.min(Math.max(1, num_inference_steps), 50),
                    ...(safeSeed !== undefined ? { seed: safeSeed } : {}),
                    ...(negative_prompt ? { negative_prompt: negative_prompt.trim() } : {}),
                };
            } else {
                requestBody = {
                    prompt: prompt.trim(),
                    ...(safeSeed !== undefined ? { seed: safeSeed } : {}),
                    ...(negative_prompt ? { negative_prompt: negative_prompt.trim() } : {}),
                };
            }

            let nimResp;
            try {
                nimResp = await axios.post(
                    `https://ai.api.nvidia.com/v1/genai/${apiId}`,
                    requestBody,
                    {
                        headers: {
                            'Authorization': `Bearer ${process.env.NVIDIA_API_KEY}`,
                            'Content-Type': 'application/json',
                            'Accept': 'application/json',
                        },
                        timeout: 180000,
                    }
                );
            } catch (err) {
                console.error('NVIDIA image hiba:', err.response?.data || err.message);
                return res.status(500).json({
                    success: false,
                    message: err.response?.data?.detail || err.response?.data?.title || err.message,
                });
            }

            const base64Image = nimResp.data?.image ?? nimResp.data?.artifacts?.[0]?.base64;

            if (!base64Image) {
                return res.status(500).json({ success: false, message: 'Nem érkezett kép az NVIDIA API-tól' });
            }

            const images = [{
                url: `data:image/png;base64,${base64Image}`,
                width: image_size.width || 1024,
                height: image_size.height || 1024,
            }];

            await logUsage(req.userId, 'image', { provider: 'nvidia-image', apiId, numImages: 1 });
            return res.json({ success: true, images });
        }

        // ── fal.ai (eredeti) ──────────────────────────────
        else {
            if (!apiId) {
                return res.status(400).json({ success: false, message: 'Hiányzó apiId' });
            }
            if (!process.env.FAL_KEY) {
                return res.status(500).json({ success: false, message: 'FAL_KEY nincs beállítva a .env-ben' });
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

            const images = (result.data?.images || []).map((img) => ({
                url: img.url, width: img.width, height: img.height,
            }));

            if (images.length === 0) throw new Error('Nem érkezett kép');

            await logUsage(req.userId, 'image', { apiId, numImages: num_images });
            return res.json({ success: true, images });
        }

    } catch (err) {
        console.error('❌ Image gen error:', err);

        if (err.response?.status === 402) {
            return res.status(402).json({
                success: false,
                message: 'Nincs elegendő Stability AI kredit',
            });
        }
        if (err.response?.status === 403) {
            return res.status(403).json({
                success: false,
                message: 'Érvénytelen Stability AI API kulcs',
            });
        }

        return res.status(500).json({
            success: false,
            message: err?.message?.includes('safety')
                ? 'A kép tartalma nem megengedett (safety filter)'
                : err?.message || 'Képgenerálási hiba',
        });
    }
});

// ════════════════════════════════════════════════════
// 3.  TTS  —  POST /api/generate-tts
// ════════════════════════════════════════════════════
router.post('/generate-tts', verifyFirebaseToken, audioLimiter, async (req, res) => {
    try {
        const {
            model = 'tts-1', provider = 'openai', text,
            voice = 'nova', speed = 1.0, format = 'mp3',
        } = req.body;

        if (!text?.trim()) return res.status(400).json({ success: false, message: 'Hiányzó szöveg' });
        if (text.length > 4096) return res.status(400).json({ success: false, message: 'Max 4096 karakter' });

        const safeSpeed = Math.min(Math.max(0.25, speed), 4.0);
        const safeFormat = ['mp3', 'opus', 'aac', 'flac'].includes(format) ? format : 'mp3';
        let audioUrl = '';

        if (provider === 'openai') {
            if (!process.env.OPENAI_API_KEY) {
                return res.status(500).json({ success: false, message: 'OPENAI_API_KEY nincs beállítva a .env-ben' });
            }
            const safeVoice = ['alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer'].includes(voice) ? voice : 'nova';
            const resp = await openai.audio.speech.create({
                model, voice: safeVoice, input: text.trim(), speed: safeSpeed, response_format: safeFormat,
            });
            const mimeTypes = { mp3: 'audio/mpeg', opus: 'audio/ogg', aac: 'audio/aac', flac: 'audio/flac' };
            const buffer = Buffer.from(await resp.arrayBuffer());
            audioUrl = `data:${mimeTypes[safeFormat]};base64,${buffer.toString('base64')}`;
        }

        else if (provider === 'nvidia-riva') {
            if (!process.env.NVIDIA_API_KEY) {
                return res.status(500).json({ success: false, message: 'NVIDIA_API_KEY nincs beállítva' });
            }

            const FUNCTION_ID = '877104f7-e885-42b9-8de8-f6e4c6303969';
            const { voice = 'Magpie-Multilingual.EN-US.Aria', language_code = 'en-US' } = req.body;

            const client = createRivaClient();

            const meta = new grpc.Metadata();
            meta.add('authorization', `Bearer ${process.env.NVIDIA_API_KEY}`);
            meta.add('function-id', FUNCTION_ID);

            const audioBuffer = await new Promise((resolve, reject) => {
                client.synthesize(
                    {
                        text: text.trim(),
                        language_code,
                        voice_name: voice,
                        encoding: 'LINEAR_PCM',
                        sample_rate_hz: 22050,
                    },
                    meta,
                    (err, response) => {
                        if (err) {
                            console.error('Riva gRPC error details:', err.code, err.message, err.details);
                            reject(new Error(`gRPC hiba: ${err.message} (code: ${err.code})`));
                        } else {
                            resolve(response.audio);
                        }
                    }
                );
            });

            const wavBuffer = pcmToWav(audioBuffer, 22050, 1, 16);
            audioUrl = `data:audio/wav;base64,${wavBuffer.toString('base64')}`;

            await logUsage(req.userId, 'tts', {
                provider: 'nvidia-riva',
                model: 'magpie-tts-multilingual',
                chars: text.length,
            });
        }

        else if (provider === 'elevenlabs') {
            if (!process.env.ELEVENLABS_API_KEY) {
                return res.status(500).json({ success: false, message: 'ELEVENLABS_API_KEY nincs beállítva a .env-ben' });
            }
            const voiceId = process.env.ELEVENLABS_VOICE_ID || '21m00Tcm4TlvDq8ikWAM';
            const resp = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${voiceId}`, {
                method: 'POST',
                headers: {
                    'xi-api-key': process.env.ELEVENLABS_API_KEY,
                    'Content-Type': 'application/json',
                    Accept: 'audio/mpeg',
                },
                body: JSON.stringify({
                    text: text.trim(),
                    model_id: model,
                    voice_settings: { stability: 0.75, similarity_boost: 0.85, style: 0.0, use_speaker_boost: true },
                }),
            });
            if (!resp.ok) {
                const err = await resp.json().catch(() => ({}));
                throw new Error(err?.detail?.message || `ElevenLabs hiba: ${resp.status}`);
            }
            const buffer = Buffer.from(await resp.arrayBuffer());
            audioUrl = `data:audio/mpeg;base64,${buffer.toString('base64')}`;
        }

        else {
            return res.status(400).json({ success: false, message: `Ismeretlen TTS provider: ${provider}` });
        }

        await logUsage(req.userId, 'tts', { provider, model, chars: text.length });
        return res.json({ success: true, audioUrl });

    } catch (err) {
        console.error('❌ TTS error:', err);
        return res.status(500).json({ success: false, message: err.message || 'TTS hiba' });
    }
});

// ════════════════════════════════════════════════════
// 4.  ZENEGENERÁLÁS  —  POST /api/generate-music
// ════════════════════════════════════════════════════
router.post('/generate-music', verifyFirebaseToken, audioLimiter, async (req, res) => {
    try {
        const {
            apiId, prompt, genre = '', mood = '', duration = 30, instrumental = true,
        } = req.body;

        if (!apiId || !prompt?.trim()) {
            return res.status(400).json({ success: false, message: 'Hiányzó apiId vagy prompt' });
        }
        if (!process.env.FAL_KEY) {
            return res.status(500).json({ success: false, message: 'FAL_KEY nincs beállítva a .env-ben' });
        }

        const safeDuration = Math.min(Math.max(5, duration), 90);
        const fullPrompt = [
            prompt.trim(),
            genre ? `genre: ${genre}` : '',
            mood ? `mood: ${mood}` : '',
            instrumental ? 'instrumental, no vocals' : '',
        ].filter(Boolean).join(', ');

        let audioUrl = '';

        if (apiId.includes('musicgen')) {
            const result = await fal.subscribe(apiId, {
                input: { prompt: fullPrompt, duration: safeDuration },
                logs: false,
            });
            audioUrl = result.data?.audio?.url || result.data?.audio_file?.url || '';
        }

        else if (apiId.includes('stable-audio')) {
            const result = await fal.subscribe(apiId, {
                input: { prompt: fullPrompt, seconds_total: safeDuration, steps: 100 },
                logs: false,
            });
            audioUrl = result.data?.audio_file?.url || result.data?.audio?.url || '';
        }

        else {
            return res.status(400).json({ success: false, message: `Ismeretlen zene API: ${apiId}` });
        }

        if (!audioUrl) throw new Error('Nem érkezett audio URL');

        await logUsage(req.userId, 'music', { apiId, duration: safeDuration });
        return res.json({ success: true, audioUrl });

    } catch (err) {
        console.error('❌ Music gen error:', err);
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
        snap.docs.forEach((d) => {
            const t = d.data().type;
            if (t in stats) stats[t]++;
            stats.total++;
        });

        return res.json({ success: true, stats, period: 'month' });
    } catch (err) {
        console.error('❌ Usage stats error:', err);
        return res.status(500).json({ success: false, message: 'Statisztika hiba' });
    }
});

// ════════════════════════════════════════════════════
router.post('/meshy/text-to-3d', verifyFirebaseToken, genLimiter, async (req, res) => {
  if (!MESHY_KEY)
    return res.status(500).json({ success: false, message: 'MESHY_API_KEY nincs beállítva' });

  const {
    prompt,
    ai_model         = 'latest',
    topology         = 'triangle',
    target_polycount = 100_000,
    should_remesh    = false,
    symmetry_mode    = 'auto',
    pose_mode        = '',
    moderation       = false,
  } = req.body;

  if (!prompt?.trim())
    return res.status(400).json({ success: false, message: 'Prompt megadása kötelező' });
  if (prompt.length > 600)
    return res.status(400).json({ success: false, message: 'Prompt max 600 karakter' });

  try {
    const { data } = await meshy.post('/openapi/v2/text-to-3d', {
      mode:             'preview',
      prompt:           prompt.trim(),
      ai_model,
      topology,
      target_polycount: Math.min(Math.max(100, Number(target_polycount)), 300_000),
      should_remesh,
      symmetry_mode,
      ...(pose_mode ? { pose_mode } : {}),
      moderation,
    });

    await logUsage(req.userId, 'meshy_text_to_3d', { prompt: prompt.slice(0, 80), ai_model });
    return res.json({ success: true, task_id: data.result });
  } catch (err) {
    console.error('Meshy text-to-3d error:', err.response?.data || err.message);
    return res.status(err.response?.status || 500).json({
      success: false,
      message: err.response?.data?.message || err.message || 'Meshy API hiba',
    });
  }
});

// ════════════════════════════════════════════════════
// 7.  MESHY — Image to 3D
// ════════════════════════════════════════════════════
router.post('/meshy/image-to-3d', verifyFirebaseToken, genLimiter, async (req, res) => {
  if (!MESHY_KEY)
    return res.status(500).json({ success: false, message: 'MESHY_API_KEY nincs beállítva' });

  const {
    image_url,
    model_type       = 'standard',
    ai_model         = 'latest',
    topology         = 'triangle',
    target_polycount = 100_000,
    symmetry_mode    = 'auto',
    should_remesh    = false,
    should_texture   = true,
    enable_pbr       = false,
    pose_mode        = '',
    texture_prompt   = '',
    moderation       = false,
  } = req.body;

  if (!image_url)
    return res.status(400).json({ success: false, message: 'image_url megadása kötelező' });

  try {
    const { data } = await meshy.post('/openapi/v1/image-to-3d', {
      image_url,
      model_type,
      ai_model,
      topology,
      target_polycount: Math.min(Math.max(100, Number(target_polycount)), 300_000),
      symmetry_mode,
      should_remesh,
      should_texture,
      enable_pbr,
      ...(pose_mode     ? { pose_mode }     : {}),
      ...(texture_prompt ? { texture_prompt } : {}),
      moderation,
    });

    await logUsage(req.userId, 'meshy_image_to_3d', { ai_model });
    return res.json({ success: true, task_id: data.result });
  } catch (err) {
    console.error('Meshy image-to-3d error:', err.response?.data || err.message);
    return res.status(err.response?.status || 500).json({
      success: false,
      message: err.response?.data?.message || err.message || 'Meshy API hiba',
    });
  }
});

// ════════════════════════════════════════════════════
// 8.  MESHY — Text to 3D Refine
// ════════════════════════════════════════════════════
router.post('/meshy/refine', verifyFirebaseToken, async (req, res) => {
  if (!MESHY_KEY)
    return res.status(500).json({ success: false, message: 'MESHY_API_KEY nincs beállítva' });

  const {
    preview_task_id,
    enable_pbr        = true,
    texture_prompt    = '',
    texture_image_url = '',
    ai_model          = 'latest',
    moderation        = false,
  } = req.body;

  if (!preview_task_id)
    return res.status(400).json({ success: false, message: 'preview_task_id kötelező' });

  try {
    const { data } = await meshy.post('/openapi/v2/text-to-3d', {
      mode: 'refine',
      preview_task_id,
      enable_pbr,
      ai_model,
      moderation,
      ...(texture_prompt    ? { texture_prompt }    : {}),
      ...(texture_image_url ? { texture_image_url } : {}),
    });

    await logUsage(req.userId, 'meshy_refine', { preview_task_id });
    return res.json({ success: true, task_id: data.result });
  } catch (err) {
    console.error('Meshy refine error:', err.response?.data || err.message);
    return res.status(err.response?.status || 500).json({
      success: false,
      message: err.response?.data?.message || err.message || 'Meshy refine hiba',
    });
  }
});

// ════════════════════════════════════════════════════
// 9.  MESHY — Task státusz lekérdezés
// ════════════════════════════════════════════════════
router.get('/meshy/task/:type/:taskId', verifyFirebaseToken, async (req, res) => {
  if (!MESHY_KEY)
    return res.status(500).json({ success: false, message: 'MESHY_API_KEY nincs beállítva' });

  const { type, taskId } = req.params;
  const endpoint = type === 'text-to-3d'
    ? `/openapi/v2/text-to-3d/${taskId}`
    : `/openapi/v1/image-to-3d/${taskId}`;

  try {
    const { data } = await meshy.get(endpoint);
    return res.json({
      success:       true,
      status:        data.status,
      progress:      data.progress      ?? 0,
      model_urls:    data.model_urls    ?? {},
      thumbnail_url: data.thumbnail_url ?? null,
      task_error:    data.task_error    ?? null,
    });
  } catch (err) {
    console.error('Meshy task status error:', err.response?.data || err.message);
    return res.status(err.response?.status || 500).json({
      success: false,
      message: err.response?.data?.message || 'Taszk lekérdezési hiba',
    });
  }
});
// ════════════════════════════════════════════════════════════════════════════
// Backend változtatások - trellis.js
// ════════════════════════════════════════════════════════════════════════════
//
// ✅ ÚJ ENDPOINT: DELETE /api/trellis/history/:id
// - Törli az egyedi Trellis modellt a Firestore-ból
// - Opcionálisan törli a B2-ből is a GLB fájlt
//
// ════════════════════════════════════════════════════════════════════════════

import fetch from 'node-fetch';
import { log } from 'console';

const TRELLIS_NIM_URL = 'https://ai.api.nvidia.com/v1/genai/microsoft/trellis';

// ── Keep-alive HTTPS agent — elkerüli az ismételt TCP/TLS handshake overhead-et
const keepAliveAgent = new https.Agent({ keepAlive: true, timeout: 190_000 });

const b2 = new S3Client({
  region:      'us-east-005',
  endpoint:    process.env.B2_ENDPOINT,
  credentials: {
    accessKeyId:     process.env.B2_KEY_ID,
    secretAccessKey: process.env.B2_APP_KEY,
  },
  forcePathStyle: true,
});

async function uploadGlbToB2(base64Glb, filename) {
  const buffer = Buffer.from(base64Glb, 'base64');
  const key    = `trellis/${filename}`;

  await b2.send(new PutObjectCommand({
    Bucket:      process.env.B2_BUCKET_NAME,
    Key:         key,
    Body:        buffer,
    ContentType: 'model/gltf-binary',
  }));

  console.log(`☁️  B2 feltöltve: ${key}`);
  return key;
}

async function streamB2Key(key, filename, res) {
  const cmd  = new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key });
  const data = await b2.send(cmd);
  res.setHeader('Content-Type', 'model/gltf-binary');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Cache-Control', 'private, max-age=3600');
  data.Body.pipe(res);
}

async function deleteFromB2(key) {
  try {
    await b2.send(new DeleteObjectCommand({
      Bucket: process.env.B2_BUCKET_NAME,
      Key:    key,
    }));
    console.log(`🗑️  B2-ből törölve: ${key}`);
    return true;
  } catch (err) {
    console.warn('⚠️  B2 törlés sikertelen:', err.message);
    return false;
  }
}

router.get('/trellis/model/:filename', verifyFirebaseToken, async (req, res) => {
  const key = `trellis/${req.params.filename}`;
  try {
    await streamB2Key(key, req.params.filename, res);
  } catch (err) {
    console.error('❌ B2 proxy hiba:', err.message);
    res.status(404).json({ success: false, message: 'Fájl nem található' });
  }
});

router.get('/trellis/proxy', verifyFirebaseToken, async (req, res) => {
  let key = req.query.key;

  if (!key && req.query.url) {
    try {
      const u = new URL(req.query.url);
      key = u.pathname.replace(/^\/[^/]+\//, '');
    } catch {
      return res.status(400).json({ success: false, message: 'Érvénytelen URL' });
    }
  }

  if (!key) return res.status(400).json({ success: false, message: 'Hiányzó key vagy url param' });

  const filename = key.split('/').pop();
  try {
    await streamB2Key(key, filename, res);
  } catch (err) {
    console.error('❌ B2 proxy (fallback) hiba:', err.message);
    res.status(404).json({ success: false, message: 'Fájl nem található' });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// Egyedi Trellis modell törlése
// ════════════════════════════════════════════════════════════════════════════
router.delete('/trellis/history/:id', verifyFirebaseToken, async (req, res) => {
  const { id } = req.params;
  const userId = req.userId;

  if (!id) {
    return res.status(400).json({ success: false, message: 'Hiányzó modell ID' });
  }

  try {
    const docRef = admin.firestore().collection('trellis_history').doc(id);
    const doc = await docRef.get();

    if (!doc.exists) {
      return res.status(404).json({ success: false, message: 'Modell nem található' });
    }

    const data = doc.data();

    if (data.userId !== userId) {
      return res.status(403).json({ success: false, message: 'Nincs jogosultság a törléshez' });
    }

    if (data.b2_key) {
      await deleteFromB2(data.b2_key);
    } else if (data.model_url && data.model_url.includes('/api/trellis/model/')) {
      const filename = data.model_url.split('/').pop();
      const b2Key = `trellis/${filename}`;
      await deleteFromB2(b2Key);
    }

    await docRef.delete();

    console.log(`🗑️  Trellis modell törölve: ${id} (user: ${userId})`);

    return res.json({ 
      success: true, 
      message: 'Modell sikeresen törölve',
      deletedId: id,
    });

  } catch (err) {
    console.error('❌ Trellis modell törlés hiba:', err.message);
    return res.status(500).json({ 
      success: false, 
      message: 'Szerverhiba a törlés során',
      error: err.message,
    });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// Összes előzmény törlése
// ════════════════════════════════════════════════════════════════════════════
router.delete('/trellis/history', verifyFirebaseToken, async (req, res) => {
  const userId = req.userId;

  try {
    const snapshot = await admin.firestore()
      .collection('trellis_history')
      .where('userId', '==', userId)
      .get();

    if (snapshot.empty) {
      return res.json({ 
        success: true, 
        message: 'Nincs törlendő előzmény',
        deletedCount: 0,
      });
    }

    const deletePromises = [];
    for (const doc of snapshot.docs) {
      const data = doc.data();
      
      if (data.b2_key) {
        deletePromises.push(deleteFromB2(data.b2_key));
      } else if (data.model_url && data.model_url.includes('/api/trellis/model/')) {
        const filename = data.model_url.split('/').pop();
        const b2Key = `trellis/${filename}`;
        deletePromises.push(deleteFromB2(b2Key));
      }
    }

    await Promise.allSettled(deletePromises);

    const batch = admin.firestore().batch();
    snapshot.docs.forEach(doc => {
      batch.delete(doc.ref);
    });
    await batch.commit();

    console.log(`🗑️  Összes Trellis előzmény törölve: ${snapshot.size} db (user: ${userId})`);

    return res.json({ 
      success: true, 
      message: `${snapshot.size} modell sikeresen törölve`,
      deletedCount: snapshot.size,
    });

  } catch (err) {
    console.error('❌ Összes Trellis előzmény törlés hiba:', err.message);
    return res.status(500).json({ 
      success: false, 
      message: 'Szerverhiba a törlés során',
      error: err.message,
    });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// Trellis generálás
// ════════════════════════════════════════════════════════════════════════════
router.post('/trellis', verifyFirebaseToken, genLimiter, async (req, res) => {
  const {
    prompt,
    seed                = 0,
    slat_cfg_scale      = 3,
    ss_cfg_scale        = 7.5,
    slat_sampling_steps = 25,
    ss_sampling_steps   = 25,
  } = req.body;

  if (!prompt || !String(prompt).trim()) {
    return res.status(400).json({ success: false, message: 'A prompt megadása kötelező' });
  }
  if (String(prompt).length > 1000) {
    return res.status(400).json({ success: false, message: 'A prompt maximum 1000 karakter lehet' });
  }

  const apiKey = process.env.NVIDIA_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ success: false, message: 'NVIDIA_API_KEY nincs beállítva' });
  }

  const payload = {
    prompt:              String(prompt).trim(),
    seed:                Math.min(2147483647, Math.max(0, Math.floor(Number(seed) || 0))),
    slat_cfg_scale:      Number(slat_cfg_scale),
    ss_cfg_scale:        Number(ss_cfg_scale),
    slat_sampling_steps: Math.round(Number(slat_sampling_steps)),
    ss_sampling_steps:   Math.round(Number(ss_sampling_steps)),


    
  };

  console.log(`🧊 Trellis → ${TRELLIS_NIM_URL}`);
  console.log(`   prompt: "${payload.prompt.slice(0, 80)}" | seed: ${payload.seed}`);

  const controller = new AbortController();

  // ── Manuális 180s timeout — megbízhatóbb Node 18-on mint AbortSignal.any()
  let timeoutId = setTimeout(() => {
    console.log('🧊 Trellis: 180s timeout, abort...');
    controller.abort();
  }, 180_000);

  const onClose = () => {
    console.log('🧊 Trellis: kliens megszakította, abort...');
    controller.abort();
  };
  req.on('close', onClose);

  try {
    const nimResp = await fetch(TRELLIS_NIM_URL, {
      method:  'POST',
      headers: {
        'Content-Type':  'application/json',
        'Accept':        'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'Connection':    'keep-alive',
      },
      body:   JSON.stringify(payload),
      signal: controller.signal,
      agent:  keepAliveAgent,
    });

    // Sikeres válasz érkezett — timer már nem kell
    clearTimeout(timeoutId);
    timeoutId = null;

    if (!nimResp.ok) {
      const errText = await nimResp.text();
      console.error(`❌ Trellis HTTP ${nimResp.status}:`, errText.slice(0, 400));
      const msg =
        nimResp.status === 401 ? 'Érvénytelen NVIDIA API kulcs' :
        nimResp.status === 422 ? `Érvénytelen kérés: ${errText}` :
        nimResp.status === 429 ? 'NVIDIA rate limit — próbáld újra később' :
        nimResp.status === 503 ? 'NVIDIA szerver nem elérhető' :
        `Trellis hiba (${nimResp.status}): ${errText.slice(0, 200)}`;
      return res.status(nimResp.status).json({ success: false, message: msg });
    }

    const body = await nimResp.json();
    console.log('🧊 Trellis response keys:', Object.keys(body));

    let base64Glb = null;
    if (Array.isArray(body.artifacts) && body.artifacts.length > 0) {
      const art = body.artifacts[0];
      base64Glb = art.base64 ?? art.glb ?? art.model ?? art.data ?? null;
    }
    if (!base64Glb) base64Glb = body.base64 ?? body.glb ?? body.model ?? null;

    if (!base64Glb) {
      console.error('🧊 Trellis: nincs base64 GLB:', JSON.stringify(body).slice(0, 400));
      return res.status(500).json({ success: false, message: 'A Trellis API nem adott vissza 3D modellt' });
    }

    const filename = `trellis_${Date.now()}_${payload.seed}.glb`;
    let glbUrl;
    let b2Key = null;

    try {
      b2Key = await uploadGlbToB2(base64Glb, filename);
      glbUrl = `/api/trellis/model/${filename}`;
    } catch (b2Err) {
      console.warn('⚠️  B2 feltöltés sikertelen, data URI fallback:', b2Err.message);
      glbUrl = `data:model/gltf-binary;base64,${base64Glb}`;
    }

    await logUsage(req.userId, 'trellis', {
      prompt: payload.prompt.slice(0, 80),
      seed:   payload.seed,
      b2_key: b2Key,
    });

    return res.json({ 
      success: true, 
      glb_url: glbUrl,
      b2_key: b2Key,
    });

  } catch (err) {
    if (err.name === 'AbortError') {
      console.log('🧊 Trellis: generálás megszakítva (kliens vagy 180s timeout)');
      if (!res.headersSent) res.status(499).json({ success: false, message: 'Generálás megszakítva' });
      return;
    }
    console.error('❌ Trellis fetch hiba:', err.message);
    return res.status(500).json({ success: false, message: err.message ?? 'Hálózati hiba' });
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
    req.off('close', onClose);
  }
});




// tripoRouter.js — Tripo3D API backend route
// Helyezd el ott ahol a többi router van (pl. server.js-be importálva)
// .env: TRIPO3D_API_KEY=tsk_xxxxxxxxxxxxxxxx

// import { verifyFirebaseToken } from './middleware.js';  // ← a te auth middleware-d
// import admin from './firebaseAdmin.js';                 // ← Firestore ha kell

// ════════════════════════════════════════════════════════════════════════════
// SERVER.JS-BE IMPORTÁLÁS:
//
// import tripoRouter from './tripoRouter.js';
// app.use('/api', tripoRouter);
//
// .env:
// TRIPO3D_API_KEY=tsk_xxxxxxxxxxxxxxxx
// ════════════════════════════════════════════════════════════════════════════
// ════════════════════════════════════════════════════════════════════════════
// HASZNÁLATI ÚTMUTATÓ
// ════════════════════════════════════════════════════════════════════════════
/**
 * ÚJ ENDPOINTOK:
 * 
 * 1. DELETE /api/trellis/history/:id
 *    - Törli az egyedi Trellis modellt
 *    - Authorization: Bearer token (Firebase)
 *    - Response: { success: true, deletedId: string }
 * 
 * 2. DELETE /api/trellis/history
 *    - Törli az összes Trellis modellt a felhasználóhoz
 *    - Authorization: Bearer token (Firebase)
 *    - Response: { success: true, deletedCount: number }
 * 
 * FRONTEND HASZNÁLAT:
 * 
 * // Egyedi törlés
 * const handleDeleteHistoryItem = async (item) => {
 *   const headers = await authHeaders();
 *   const res = await fetch(`http://localhost:3001/api/trellis/history/${item.id}`, {
 *     method: 'DELETE',
 *     headers,
 *   });
 *   const data = await res.json();
 *   if (data.success) {
 *     setHistory(h => h.filter(i => i.id !== item.id));
 *     if (activeItem?.id === item.id) {
 *       setActiveItem(null);
 *       setModelUrl(null);
 *     }
 *   }
 * };
 * 
 * // Összes törlés
 * const handleClearHistory = async () => {
 *   const headers = await authHeaders();
 *   const res = await fetch('http://localhost:3001/api/trellis/history', {
 *     method: 'DELETE',
 *     headers,
 *   });
 *   const data = await res.json();
 *   if (data.success) {
 *     setHistory([]);
 *     setActiveItem(null);
 *     setModelUrl(null);
 *   }
 * };
 */

// ════════════════════════════════════════════════════
// 10. MESHY — Előzmények
// ════════════════════════════════════════════════════

// ════════════════════════════════════════════════════
// TRIPO3D — Task indítása
// ════════════════════════════════════════════════════
// tripo.routes.js — Teljes Tripo3D API backend
// Támogatott műveletek: text→3D, image→3D, texture, animate (rig+retarget), refine, convert
// routes/tripo.js
//
// Production-ready Tripo API routes.
//
// Tripo API base: https://api.tripo3d.ai/v2/openapi
//
// Supported model_version strings (as of 2025):
//   v3.0-20250812       — default, best quality (~90s), geometry_quality support
//   v2.5-20250123       — fast & balanced (~25-30s)
//   turbo-v1.0-20250506 — fastest prototyping (~5-10s)
//   v2.0-20240919       — legacy, still valid
//   v1.4-20240625       — legacy
//   (deprecated: v1.3-20240522, v1.4-20240522 multiview)
//
// Face-limit constraints:
//   smart_low_poly=false, quad=false → auto (0), max 500 000
//   smart_low_poly=false, quad=true  → auto default 10 000, max 100 000
//   smart_low_poly=true,  quad=false → required: 1 000 – 20 000
//   smart_low_poly=true,  quad=true  → required:   500 – 10 000
//
// generate_parts constraints:
//   NOT compatible with texture=true, pbr=true, or quad=true
//
// Rigged model restrictions:
//   mesh_segmentation → NOT supported on rigged model inputs
//   mesh_completion   → NOT supported on rigged model inputs
//   convert_model     → OBJ and STL formats NOT supported for rigged inputs
//   smart_low_poly    → NOT supported on rigged model inputs
//
// Quad topology:
//   Anywhere quad=true is sent → forces FBX output format

// ==================== TRIPO ROUTER BEKÖTÉSE ====================
// Ezt add hozzá a server.js-hez, a meglévő import-ok mellé:




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
    console.error('Meshy history error:', err.message);
    return res.status(500).json({ success: false, message: 'Előzmény lekérdezési hiba' });
  }
});

// ════════════════════════════════════════════════════
// 2.  SUMMARY  —  POST /api/chat/summary
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

Keep it under 200 tokens. Be concise but capture all important context.`;

        const summaryMessages = [
            { role: 'system', content: summaryPrompt },
            ...messages
                .slice(-30)
                .map(m => ({ role: m.role, content: String(m.content).slice(0, 2000) })),
        ];

        const resp = await axios.post(
            'https://api.groq.com/openai/v1/chat/completions',
            {
                model: 'openai/gpt-oss-120b',
                messages: summaryMessages,
                temperature: 0.3,
                max_tokens: 300,
                top_p: 0.9,
                stream: false,
            },
            {
                headers: {
                    'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
                    'Content-Type': 'application/json',
                },
                timeout: 30000,
            }
        );

        const summaryText = resp.data?.choices?.[0]?.message?.content || '';
        if (!summaryText) {
            return res.status(500).json({ success: false, message: 'Üres summary' });
        }

        const db = admin.firestore();
        const batch = db.batch();

        const summaryRef = db.collection('conversations')
            .doc(req.userId)
            .collection('sessions')
            .doc(sessionId)
            .collection(SUMMARY_COLLECTION)
            .doc('latest');

        batch.set(summaryRef, {
            summaryText,
            messageCountAtSummary: messages.length,
            lastSummaryModelId: modelId || 'unknown',
            language: 'auto',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

        const sessionRef = db.collection('conversations')
            .doc(req.userId)
            .collection('sessions')
            .doc(sessionId);

        batch.set(sessionRef, {
            summaryGenerated: true,
            lastSummaryAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

        await batch.commit();
        console.log(`[Summary] Generated for session ${sessionId.slice(0, 12)}... (${summaryText.length} chars)`);

        return res.json({ success: true, summaryText });
    } catch (err) {
        console.error('[Summary] Generation failed:', err.message);
        return res.status(500).json({ success: false, message: 'Summary generation failed' });
    }
});

// ════════════════════════════════════════════════════
// 3.  SUMMARY GET  —  GET /api/chat/summary/:sessionId
// ════════════════════════════════════════════════════
router.get('/chat/summary/:sessionId', verifyFirebaseToken, async (req, res) => {
    try {
        const { sessionId } = req.params;

        const summaryDoc = await admin.firestore()
            .collection('conversations')
            .doc(req.userId)
            .collection('sessions')
            .doc(sessionId)
            .collection(SUMMARY_COLLECTION)
            .doc('latest')
            .get();

        if (!summaryDoc.exists) {
            return res.json({ success: false, summary: null });
        }

        return res.json({ success: true, summary: summaryDoc.data() });
    } catch (err) {
        return res.status(500).json({ success: false, message: err.message });
    }
});

// ════════════════════════════════════════════════════
// 3.  SWITCH-MODEL  —  POST /api/chat/switch-model
// ════════════════════════════════════════════════════
router.post('/chat/switch-model', verifyFirebaseToken, async (req, res) => {
    try {
        const { sessionId, newModelId } = req.body;

        if (!sessionId || !newModelId) {
            return res.status(400).json({ success: false, message: 'Hiányzó sessionId vagy newModelId' });
        }

        const db = admin.firestore();
        const userId = req.userId;
        const sessionRef = db.collection('conversations').doc(userId).collection('sessions').doc(sessionId);

        // Load all messages for summary
        const messagesRef = sessionRef.collection('messages');
        const snap = await messagesRef.orderBy('timestamp', 'asc').limit(50).get();
        const messages = snap.docs.map(d => ({ role: d.data().role, content: String(d.data().content).slice(0, 2000) }));

        // Generate summary
        const summaryPrompt = `Summarize this conversation in a structured format.
Detect the language used and include it in the summary.
Format:
Topic: <main topic>
Key facts established: <facts/decisions>
User preferences: <preferences>
Open questions: <unresolved questions>
Language: <detected language>

Keep it under 200 tokens. Be concise but capture all important context.`;

        const summaryMessages = [
            { role: 'system', content: summaryPrompt },
            ...messages,
        ];

        const resp = await axios.post(
            'https://api.groq.com/openai/v1/chat/completions',
            {
                model: 'openai/gpt-oss-120b',
                messages: summaryMessages,
                temperature: 0.3,
                max_tokens: 500,
            },
            {
                headers: {
                    'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
                    'Content-Type': 'application/json',
                },
            }
        );

        const summaryText = resp.data.choices?.[0]?.message?.content || '';

        // Resolve new model config
        const modelConfig = getModelConfig(newModelId);
        if (!modelConfig) {
            return res.status(400).json({ success: false, message: `Ismeretlen modell: ${newModelId}` });
        }

        // Update session with new model and summary
        await sessionRef.set({
            modelId: newModelId,
            modelName: modelConfig.apiModel,
            summary: summaryText,
            summaryGeneratedAt: admin.firestore.FieldValue.serverTimestamp(),
            summaryMessageCount: messages.length,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        }, { merge: true });

        console.log(`[SwitchModel] Session ${sessionId} switched to ${newModelId}, summary generated (${messages.length} messages)`);

        return res.json({ success: true, summary: summaryText });
    } catch (e) {
        console.error('Switch model error:', e);
        return res.status(500).json({ success: false, message: e.message });
    }
});

export default router;