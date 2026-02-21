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
import { log } from 'console';


const httpsAgent = new https.Agent({ family: 4 });

dotenv.config();

const router = express.Router();

// ── .env változók ellenőrzése induláskor ──────────────
const REQUIRED_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'FAL_KEY', 'OPENROUTER_API_KEY', 'DEEPSEEK_API_KEY'];
REQUIRED_KEYS.forEach((key) => {
    if (!process.env[key]) console.warn(`⚠️  Hiányzó .env változó: ${key}`);
});

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
    windowMs: 60 * 60 * 1000, max: 60,
    keyGenerator: (req) => req.userId || ipKeyGenerator(req),
    message: { success: false, message: 'Túl sok kérés — próbáld újra 1 óra múlva' },
});
const imageLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, max: 20,
    keyGenerator: (req) => req.userId || ipKeyGenerator(req),
    message: { success: false, message: 'Túl sok képgenerálás — próbáld újra 1 óra múlva' },
});
const audioLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, max: 30,
    keyGenerator: (req) => req.userId || ipKeyGenerator(req),
    message: { success: false, message: 'Túl sok hanggenerálás — próbáld újra 1 óra múlva' },
});
const genLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 30,
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

// ════════════════════════════════════════════════════
// 1.  CHAT  —  POST /api/chat
// ════════════════════════════════════════════════════
router.post('/chat', verifyFirebaseToken, chatLimiter, async (req, res) => {
    try {
        const {
            model, provider, messages,
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

        const safeMax = Math.min(Math.max(128, max_tokens), 8192);
        let content = '';
        let usage = {};

        // ── Anthropic ────────────────────────────────────
        if (provider === 'anthropic') {
            if (!process.env.ANTHROPIC_API_KEY) {
                return res.status(500).json({ success: false, message: 'ANTHROPIC_API_KEY nincs beállítva a .env-ben' });
            }

            const systemMsg = messages.find((m) => m.role === 'system');
            const chatMsgs = messages
                .filter((m) => m.role !== 'system')
                .map((m) => ({ role: m.role, content: String(m.content) }));

            const resp = await anthropic.messages.create({
                model,
                max_tokens: safeMax,
                temperature: Math.min(Math.max(0, temperature), 1),
                ...(systemMsg ? { system: systemMsg.content } : {}),
                messages: chatMsgs,
            });

            content = resp.content?.[0]?.text || '';
            usage = {
                input_tokens: resp.usage?.input_tokens || 0,
                output_tokens: resp.usage?.output_tokens || 0,
                total_tokens: (resp.usage?.input_tokens || 0) + (resp.usage?.output_tokens || 0),
            };

            await logUsage(req.userId, 'chat', { model, provider, tokens: usage.total_tokens });
            return res.json({ success: true, content, usage });
        }

        // ── OpenAI ───────────────────────────────────────
        else if (provider === 'openai') {
            if (!process.env.OPENAI_API_KEY) {
                return res.status(500).json({ success: false, message: 'OPENAI_API_KEY nincs beállítva a .env-ben' });
            }

            const resp = await openai.chat.completions.create({
                model,
                messages: messages.map((m) => ({ role: m.role, content: String(m.content) })),
                temperature: Math.min(Math.max(0, temperature), 2),
                max_tokens: safeMax,
                top_p: Math.min(Math.max(0, top_p), 1),
                frequency_penalty: Math.min(Math.max(-2, frequency_penalty), 2),
                presence_penalty: Math.min(Math.max(-2, presence_penalty), 2),
            });

            content = resp.choices?.[0]?.message?.content || '';
            usage = {
                input_tokens: resp.usage?.prompt_tokens || 0,
                output_tokens: resp.usage?.completion_tokens || 0,
                total_tokens: resp.usage?.total_tokens || 0,
            };

            await logUsage(req.userId, 'chat', { model, provider, tokens: usage.total_tokens });
            return res.json({ success: true, content, usage });
        }

        // ── Cerebras ─────────────────────────────────────
        else if (provider === 'cerebras') {
            if (!process.env.CEREBRAS_API_KEY) {
                return res.status(500).json({ success: false, message: 'CEREBRAS_API_KEY nincs beállítva' });
            }

            const chatMsgs = messages.map(m => ({ role: m.role, content: String(m.content) }));

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
                        model,
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
                    }
                );
            } catch (err) {
                console.error('Cerebras hiba:', err.response?.data || err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

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
                        if (delta) {
                            totalContent += delta;
                            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                        }
                    } catch {}
                }
            });

            streamResp.data.on('end', async () => {
                res.write('data: [DONE]\n\n');
                res.end();
                await logUsage(req.userId, 'chat', { model, provider: 'cerebras', tokens: totalContent.length });
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

            const chatMsgs = messages.map((m) => ({ role: m.role, content: String(m.content) }));

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
                        model,
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
                    }
                );
            } catch (err) {
                console.error('Mistral hiba:', err.response?.data || err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

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
                        if (delta) {
                            totalContent += delta;
                            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                        }
                    } catch {}
                }
            });

            streamResp.data.on('end', async () => {
                res.write('data: [DONE]\n\n');
                res.end();
                await logUsage(req.userId, 'chat', { model, provider: 'mistral', tokens: totalContent.length });
            });

            streamResp.data.on('error', () => {
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

            const chatMsgs = messages.map((m) => ({ role: m.role, content: String(m.content) }));

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
                        model,
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
                    }
                );
            } catch (err) {
                console.error('Groq hiba:', err.response?.data || err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

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
                        if (delta) {
                            totalContent += delta;
                            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                        }
                    } catch {}
                }
            });

            streamResp.data.on('end', async () => {
                res.write('data: [DONE]\n\n');
                res.end();
                await logUsage(req.userId, 'chat', { model, provider: 'groq', tokens: totalContent.length });
            });

            streamResp.data.on('error', (err) => {
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

            const systemMsg = messages.find((m) => m.role === 'system');
            const contents = messages
                .filter((m) => m.role !== 'system')
                .map((m) => ({
                    role: m.role === 'assistant' ? 'model' : 'user',
                    parts: [{ text: String(m.content) }],
                }));

            res.setHeader('Content-Type', 'text/event-stream');
            res.setHeader('Cache-Control', 'no-cache');
            res.setHeader('Connection', 'keep-alive');
            res.setHeader('X-Accel-Buffering', 'no');
            res.flushHeaders();

            let streamResp;
            try {
                streamResp = await axios.post(
                    `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse`,
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
                    }
                );
            } catch (err) {
                console.error('Gemini kapcsolódási hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

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
                    try {
                        const parsed = JSON.parse(raw);
                        const delta = parsed.candidates?.[0]?.content?.parts?.[0]?.text || '';
                        if (delta) {
                            totalContent += delta;
                            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                        }
                    } catch {}
                }
            });

            streamResp.data.on('end', async () => {
                res.write('data: [DONE]\n\n');
                res.end();
                await logUsage(req.userId, 'chat', { model, provider: 'gemini', tokens: totalContent.length });
            });

            streamResp.data.on('error', (err) => {
                console.error('Gemini stream hiba:', err.message);
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

            const chatMsgs = messages.map((m) => ({
                role: m.role,
                content: String(m.content),
            }));

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
                        model,
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
                    }
                );
            } catch (err) {
                console.error('OpenRouter kapcsolódási hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
                return res.end();
            }

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
                        if (delta) {
                            totalContent += delta;
                            res.write(`data: ${JSON.stringify({ delta })}\n\n`);
                        }
                    } catch { /* csonka JSON — kihagyjuk */ }
                }
            });

            streamResp.data.on('end', async () => {
                res.write('data: [DONE]\n\n');
                res.end();
                await logUsage(req.userId, 'chat', { model, provider: 'openrouter', tokens: totalContent.length });
            });

            streamResp.data.on('error', (err) => {
                console.error('OpenRouter stream hiba:', err.message);
                res.write(`data: ${JSON.stringify({ error: 'Stream megszakadt' })}\n\n`);
                res.end();
            });

            return;
        }

        else {
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

// ════════════════════════════════════════════════════
// 2.  KÉPGENERÁLÁS  —  POST /api/generate-image
// ════════════════════════════════════════════════════
router.post('/generate-image', verifyFirebaseToken, imageLimiter, async (req, res) => {
    try {
        const {
            apiId, prompt, negative_prompt, provider,
            image_size = { width: 1024, height: 1024 },
            num_inference_steps = 28,
            guidance_scale = 7.5,
            seed, num_images = 1,
            aspect_ratio = '1:1',
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

            // gemini-2.5-flash-image uses 'generateContent'
            // response_modalities must be lowercase per new API spec
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
            // Cloudflare image models return image/png directly
            const contentType = cfResp.headers['content-type']?.split(';')[0] || 'image/png';

            const images = [{
                url: `data:${contentType};base64,${base64}`,
                width: image_size.width || 1024,
                height: image_size.height || 1024,
            }];

            await logUsage(req.userId, 'image', { provider: 'cloudflare', apiId, numImages: 1 });
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

        // Stability AI specifikus hibák
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
//     POST /api/meshy/image-to-3d
//     Body: { image_url, model_type?, ai_model?, topology?,
//             target_polycount?, symmetry_mode?, should_remesh?,
//             should_texture?, enable_pbr?, pose_mode?,
//             texture_prompt?, moderation? }
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
//     POST /api/meshy/refine
//     Body: { preview_task_id, enable_pbr?, texture_prompt?,
//             texture_image_url?, ai_model?, moderation? }
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
//     GET /api/meshy/task/:type/:taskId
//     type: "text-to-3d" | "image-to-3d"
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

// ════════════════════════════════════════════════════
// 10. MESHY — Előzmények
//     GET /api/meshy/history
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
    console.error('Meshy history error:', err.message);
    return res.status(500).json({ success: false, message: 'Előzmény lekérdezési hiba' });
  }
});
export default router;
