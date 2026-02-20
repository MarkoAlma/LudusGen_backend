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

const httpsAgent = new https.Agent({
  family: 4
});

dotenv.config();

const router = express.Router();


// ── .env változók ellenőrzése induláskor ──────────────
const REQUIRED_KEYS = ['ANTHROPIC_API_KEY', 'OPENAI_API_KEY', 'FAL_KEY', 'OPENROUTER_API_KEY', 'DEEPSEEK_API_KEY'];
REQUIRED_KEYS.forEach((key) => {
    if (!process.env[key]) console.warn(`⚠️  Hiányzó .env változó: ${key}`);
});

// ── API kliensek inicializálása ───────────────────────
const anthropic = new Anthropic({
    apiKey: process.env.ANTHROPIC_API_KEY,
});

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
});

fal.config({
    credentials: process.env.FAL_KEY,
});

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

// ── Firestore usage log ───────────────────────────────
async function logUsage(userId, type, meta = {}) {
  try {
    // undefined mezők kiszűrése
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

            console.log("kugyafaja provie",provider);
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
        }

        // ── OpenRouter ───────────────────────────────────

else if (provider === 'openrouter') {

    if (!process.env.OPENROUTER_API_KEY) {
        return res.status(500).json({ success: false, message: 'OPENROUTER_API_KEY nincs beállítva a .env-ben' });
    }

    const chatMsgs = messages.map((m) => ({
        role: m.role,
        content: String(m.content)
    }));

        console.log("kutya");
    try {
    console.log("➡️ AXIOS ELŐTT");
    console.log("MODEL:", model);
    console.log("API KEY:", process.env.OPENROUTER_API_KEY ? "OK" : "NINCS");
        
const response = await axios.post(
    'https://openrouter.ai/api/v1/chat/completions',
    {
        model,
        messages: chatMsgs,
        temperature: Math.min(Math.max(0, temperature), 2),
        max_tokens: safeMax,
        top_p: Math.min(Math.max(0, top_p), 1),
        stream: false
    },
    {
        headers: {
            Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
            'Content-Type': 'application/json'
        },
        httpsAgent,   // 👈 EZ FONTOS
        timeout: 10000
    }
);


const data = response.data;

console.log("FULL RESPONSE:", response);
console.log("DATA:", response.data);


        if (data.error) {
            return res.status(500).json({ success: false, message: data.error.message });
        }

        content = data.choices?.[0]?.message?.content ?? '';

        usage = {
            input_tokens: data.usage?.prompt_tokens ?? 0,
            output_tokens: data.usage?.completion_tokens ?? 0,
            total_tokens: data.usage?.total_tokens ?? 0
        };

    } catch (err) {
        console.error("OpenRouter hiba:", err.response?.data || err.message);
        return res.status(500).json({ success: false, message: 'OpenRouter API hiba' });
    }

    await logUsage(req.userId, 'chat', { model, provider, tokens: usage.total_tokens });
    return res.json({ success: true, content, usage });
}




    } catch (err) {
        console.error('❌ Chat error:', err);
        return res.status(500).json({
            success: false,
            message: err?.status === 429
                ? 'API rate limit — próbáld újra pár perc múlva'
                : err?.message || 'Chat hiba',
        });
    }
});

// ════════════════════════════════════════════════════
// 2.  KÉPGENERÁLÁS  —  POST /api/generate-image
// ════════════════════════════════════════════════════
router.post('/generate-image', verifyFirebaseToken, imageLimiter, async (req, res) => {
    try {
        const {
            apiId,
            prompt,
            negative_prompt,
            image_size = { width: 1024, height: 1024 },
            num_inference_steps = 28,
            guidance_scale = 7.5,
            seed,
            num_images = 1,
        } = req.body;

        if (!apiId || !prompt?.trim()) {
            return res.status(400).json({ success: false, message: 'Hiányzó apiId vagy prompt' });
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

    } catch (err) {
        console.error('❌ Image gen error:', err);
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
            model = 'tts-1',
            provider = 'openai',
            text,
            voice = 'nova',
            speed = 1.0,
            format = 'mp3',
        } = req.body;

        if (!text?.trim()) return res.status(400).json({ success: false, message: 'Hiányzó szöveg' });
        if (text.length > 4096) return res.status(400).json({ success: false, message: 'Max 4096 karakter' });

        const safeSpeed = Math.min(Math.max(0.25, speed), 4.0);
        const safeFormat = ['mp3', 'opus', 'aac', 'flac'].includes(format) ? format : 'mp3';
        let audioUrl = '';

        // ── OpenAI TTS ───────────────────────────────────
        if (provider === 'openai') {
            if (!process.env.OPENAI_API_KEY) {
                return res.status(500).json({ success: false, message: 'OPENAI_API_KEY nincs beállítva a .env-ben' });
            }

            const safeVoice = ['alloy', 'echo', 'fable', 'onyx', 'nova', 'shimmer'].includes(voice) ? voice : 'nova';

            const resp = await openai.audio.speech.create({
                model,
                voice: safeVoice,
                input: text.trim(),
                speed: safeSpeed,
                response_format: safeFormat,
            });

            const mimeTypes = { mp3: 'audio/mpeg', opus: 'audio/ogg', aac: 'audio/aac', flac: 'audio/flac' };
            const buffer = Buffer.from(await resp.arrayBuffer());
            audioUrl = `data:${mimeTypes[safeFormat]};base64,${buffer.toString('base64')}`;
        }

        // ── ElevenLabs ───────────────────────────────────
        else if (provider === 'elevenlabs') {
            if (!process.env.ELEVENLABS_API_KEY) {
                return res.status(500).json({ success: false, message: 'ELEVENLABS_API_KEY nincs beállítva a .env-ben' });
            }

            const voiceId = process.env.ELEVENLABS_VOICE_ID || '21m00Tcm4TlvDq8ikWAM';

            const resp = await fetch(
                `https://api.elevenlabs.io/v1/text-to-speech/${voiceId}`,
                {
                    method: 'POST',
                    headers: {
                        'xi-api-key': process.env.ELEVENLABS_API_KEY,
                        'Content-Type': 'application/json',
                        Accept: 'audio/mpeg',
                    },
                    body: JSON.stringify({
                        text: text.trim(),
                        model_id: model,
                        voice_settings: {
                            stability: 0.75,
                            similarity_boost: 0.85,
                            style: 0.0,
                            use_speaker_boost: true,
                        },
                    }),
                }
            );

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
            apiId,
            prompt,
            genre = '',
            mood = '',
            duration = 30,
            instrumental = true,
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

        // ── MusicGen ─────────────────────────────────────
        if (apiId.includes('musicgen')) {
            const result = await fal.subscribe(apiId, {
                input: { prompt: fullPrompt, duration: safeDuration },
                logs: false,
            });
            audioUrl = result.data?.audio?.url || result.data?.audio_file?.url || '';
        }

        // ── Stable Audio ─────────────────────────────────
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

export default router;