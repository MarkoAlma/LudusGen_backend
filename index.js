import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import admin from "firebase-admin";
import { readFileSync } from "fs";
import nodemailer from "nodemailer";
import axios from "axios";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";

import aiRoutes from './ai-routes.js';
import { verifyFirebaseToken } from './src/middleware/verifyFirebaseToken.js';
import { createMarketplaceRouter } from './src/routes/marketplace.routes.js';
import { createReportRouter } from './src/routes/report.routes.js';
import { createTripoRouter } from './src/routes/tripo.routes.js';
import { startTaskRecovery, stopTaskRecovery } from './src/services/taskRecoveryService.js';

dotenv.config();

const app = express();          // Initialize app first

const DEFAULT_DEV_ORIGINS = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:5174',
  'http://127.0.0.1:5174',
  'http://localhost:5179',
  'http://127.0.0.1:5179',
];
const configuredCorsOrigins = (process.env.CORS_ORIGINS || process.env.FRONTEND_URL || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
const allowedCorsOrigins = new Set([
  ...configuredCorsOrigins,
  ...(process.env.NODE_ENV === 'production' ? [] : DEFAULT_DEV_ORIGINS),
]);
const EMAIL_SEND_TIMEOUT_MS = Number(process.env.EMAIL_SEND_TIMEOUT_MS || 20000);
const RESEND_API_URL = 'https://api.resend.com/emails';
const MAIL_PROVIDER = process.env.RESEND_API_KEY ? 'resend' : 'smtp';
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || SMTP_PORT === 465;

function getFrontendUrl() {
  return (process.env.FRONTEND_URL || 'http://localhost:5173').trim().replace(/\/+$/, '');
}

function getMailFrom() {
  const configuredFrom = (process.env.EMAIL_FROM || process.env.MAIL_FROM || '').trim();
  if (configuredFrom) return configuredFrom;

  const emailUser = (process.env.EMAIL_USER || '').trim();
  return emailUser ? `LudusGen <${emailUser}>` : '';
}

function getSafeErrorMessage(error) {
  if (error?.response?.data) {
    const data = typeof error.response.data === 'string'
      ? error.response.data
      : JSON.stringify(error.response.data);
    return `${error.response.status || 'HTTP'} ${data}`;
  }
  return error?.message || String(error);
}

function withTimeout(promise, timeoutMs, message) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}

function maskEmail(email) {
  const [name = '', domain = ''] = String(email || '').split('@');
  if (!domain) return 'unknown';
  return `${name.slice(0, 2)}***@${domain}`;
}

const isDevCorsOrigin = (origin) => {
  if (process.env.NODE_ENV === 'production') return false;
  try {
    const url = new URL(origin);
    if (url.protocol !== 'http:') return false;
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') return true;
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(url.hostname)) return true;
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname)) return true;
    if (/^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(url.hostname)) return true;
  } catch {
    return false;
  }
  return false;
};

// Middlewares
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedCorsOrigins.has(origin)) return callback(null, true);
    if (isDevCorsOrigin(origin)) return callback(null, true);
    return callback(new Error(`CORS origin not allowed: ${origin}`));
  },
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
// 1. RAW body capture for Tripo webhooks — must come BEFORE bodyParser.json()
app.use("/api/tripo/webhook", express.raw({
  type: "application/json",
  verify: (req, _res, buf) => { req.rawBody = buf; }
}));

app.use(bodyParser.json({ limit: '10mb' }));

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "ludusgen-backend" });
});

app.use('/api', aiRoutes);     // Add routes after middlewares
app.use('/api', createMarketplaceRouter(verifyFirebaseToken));
app.use('/api', createReportRouter(verifyFirebaseToken));

// ==================== CLOUDINARY CONFIG ====================

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

console.log('☁️ Cloudinary configured:', process.env.CLOUDINARY_CLOUD_NAME ? '✅' : '❌ Missing credentials');

// ==================== FIREBASE ADMIN INIT ====================
try {
  let serviceAccount;
  
  if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_CLIENT_EMAIL) {
    serviceAccount = {
      projectId: process.env.FIREBASE_PROJECT_ID,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n').replace(/"/g, ''),
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    };
  } else {
    serviceAccount = JSON.parse(readFileSync("./serviceAccountKey.json"));
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log("✅ Firebase Admin inicializálva");
} catch (error) {
  console.error("❌ Firebase Admin init hiba:", error.message);
  if (!process.env.FIREBASE_PROJECT_ID) {
    console.log("Győződj meg róla, hogy a serviceAccountKey.json létezik, vagy állítsd be a környezeti változókat!");
  }
}

const db = admin.firestore();


// ==================== EMAIL SETUP ====================
const smtpTransporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE, // true for 465, false for STARTTLS ports
  connectionTimeout: Number(process.env.SMTP_CONNECTION_TIMEOUT_MS || 10000),
  greetingTimeout: Number(process.env.SMTP_GREETING_TIMEOUT_MS || 10000),
  socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT_MS || 20000),
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
  tls: {
    rejectUnauthorized: false
  }
});



console.log('[Email] Provider:', MAIL_PROVIDER);
console.log('[Email] From configured:', getMailFrom() ? 'yes' : 'no');
console.log('[Email] Frontend URL:', getFrontendUrl());

if (MAIL_PROVIDER === 'smtp') {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
    console.warn('[Email] SMTP credentials are missing. Set EMAIL_USER and EMAIL_PASSWORD.');
  } else {
    smtpTransporter.verify(function (error) {
      if (error) {
        console.log('[Email] SMTP connection error:', getSafeErrorMessage(error));
      } else {
        console.log('[Email] SMTP server is ready to send emails');
      }
    });
  }
} else {
  console.log('[Email] Using Resend HTTP API for transactional emails');
}

async function sendTransactionalEmail(mailOptions) {
  const from = mailOptions.from || getMailFrom();
  if (!from) {
    throw new Error('Email sender is not configured. Set EMAIL_FROM or EMAIL_USER.');
  }

  if (MAIL_PROVIDER === 'resend') {
    try {
      const response = await axios.post(
        RESEND_API_URL,
        {
          from,
          to: mailOptions.to,
          subject: mailOptions.subject,
          text: mailOptions.text,
          html: mailOptions.html,
        },
        {
          headers: {
            Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
            'Content-Type': 'application/json',
          },
          timeout: EMAIL_SEND_TIMEOUT_MS,
        },
      );

      return {
        provider: 'resend',
        messageId: response.data?.id,
      };
    } catch (error) {
      throw new Error(`Resend email failed: ${getSafeErrorMessage(error)}`);
    }
  }

  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
    throw new Error('SMTP credentials are not configured. Set EMAIL_USER and EMAIL_PASSWORD.');
  }

  const info = await smtpTransporter.sendMail({
    ...mailOptions,
    from,
  });

  return {
    provider: 'smtp',
    messageId: info.messageId,
  };
}

async function sendForgotPasswordEmail(email, resetLink, displayName) {
  const mailOptions = {
    from: getMailFrom(),
    to: email,
    subject: 'Jelszó visszaállítása - LudusGen',
    text: `Jelszó visszaállítási kérelem érkezett a fiókodhoz. Kattints az alábbi linkre: ${resetLink}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
      </head>
      <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
        <table role="presentation" style="width: 100%; border-collapse: collapse;">
          <tr>
            <td align="center" style="padding: 40px 0;">
              <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="padding: 40px 40px 20px 40px; text-align: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px 8px 0 0;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px;">🎮 LudusGen</h1>
                  </td>
                </tr>

                <!-- Content -->
                <tr>
                  <td style="padding: 40px;">
                    <h2 style="margin: 0 0 20px 0; color: #333333; font-size: 24px;">
                      Jelszó visszaállítása 🔐
                    </h2>

                    <p style="margin: 0 0 20px 0; color: #666666; font-size: 16px; line-height: 1.6;">
                      Szia${displayName ? ` ${displayName}` : ''}! Jelszó visszaállítási kérelem érkezett a fiókoddal kapcsolatban.
                    </p>

                    <p style="margin: 0 0 30px 0; color: #666666; font-size: 16px; line-height: 1.6;">
                      Kattints az alábbi gombra az új jelszó beállításához:
                    </p>

                    <!-- Button -->
                    <table role="presentation" style="margin: 0 auto;">
                      <tr>
                        <td style="border-radius: 6px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                          <a href="${resetLink}" target="_blank" style="
                            display: inline-block;
                            padding: 16px 40px;
                            color: #ffffff;
                            text-decoration: none;
                            font-size: 16px;
                            font-weight: bold;
                            border-radius: 6px;
                          ">
                            🔑 Jelszó visszaállítása
                          </a>
                        </td>
                      </tr>
                    </table>

                    <p style="margin: 30px 0 20px 0; color: #999999; font-size: 14px; line-height: 1.6;">
                      Ha a gomb nem működik, másold be ezt a linket a böngészőbe:
                    </p>

                    <p style="margin: 0 0 30px 0; padding: 15px; background-color: #f8f8f8; border-radius: 4px; word-break: break-all; color: #666666; font-size: 13px; font-family: monospace;">
                      ${resetLink}
                    </p>

                    <hr style="border: none; border-top: 1px solid #eeeeee; margin: 30px 0;">

                    <p style="margin: 0; color: #999999; font-size: 13px; line-height: 1.6;">
                      ⚠️ Ha nem te kérted a jelszó visszaállítását, hagyd figyelmen kívül ezt az emailt. A link 1 óra múlva lejár.
                    </p>
                  </td>
                </tr>

                <!-- Footer -->
                <tr>
                  <td style="padding: 30px 40px; background-color: #f8f8f8; border-radius: 0 0 8px 8px; text-align: center;">
                    <p style="margin: 0; color: #999999; font-size: 12px;">
                      © ${new Date().getFullYear()} LudusGen. Minden jog fenntartva.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
  };

  return sendTransactionalEmail(mailOptions);
}

// Email küldő függvény
async function sendVerificationEmail(email, verificationLink, displayName) {
  const mailOptions = {
    from: getMailFrom(),
    to: email,
    subject: 'Erősítsd meg az email címedet - LudusGen',
    text: `Üdvözlünk a LudusGen-nél! Kattints az alábbi linkre az email megerősítéséhez: ${verificationLink}`, // ✅ Plaintext verzió
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
      </head>
      <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f4;">
        <table role="presentation" style="width: 100%; border-collapse: collapse;">
          <tr>
            <td align="center" style="padding: 40px 0;">
              <table role="presentation" style="width: 600px; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="padding: 40px 40px 20px 40px; text-align: center; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px 8px 0 0;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px;">🎮 LudusGen</h1>
                  </td>
                </tr>
                
                <!-- Content -->
                <tr>
                  <td style="padding: 40px;">
                    <h2 style="margin: 0 0 20px 0; color: #333333; font-size: 24px;">
                      Üdvözlünk${displayName ? `, ${displayName}` : ''}! 👋
                    </h2>
                    
                    <p style="margin: 0 0 20px 0; color: #666666; font-size: 16px; line-height: 1.6;">
                      Köszönjük, hogy regisztráltál a LudusGen platformra! Már csak egy lépés van hátra.
                    </p>
                    
                    <p style="margin: 0 0 30px 0; color: #666666; font-size: 16px; line-height: 1.6;">
                      Kattints az alábbi gombra az email címed megerősítéséhez:
                    </p>
                    
                    <!-- Button -->
                    <table role="presentation" style="margin: 0 auto;">
                      <tr>
                        <td style="border-radius: 6px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                          <a href="${verificationLink}" target="_blank" style="
                            display: inline-block;
                            padding: 16px 40px;
                            color: #ffffff;
                            text-decoration: none;
                            font-size: 16px;
                            font-weight: bold;
                            border-radius: 6px;
                          ">
                            ✉️ Email megerősítése
                          </a>
                        </td>
                      </tr>
                    </table>
                    
                    <p style="margin: 30px 0 20px 0; color: #999999; font-size: 14px; line-height: 1.6;">
                      Ha a gomb nem működik, másold be ezt a linket a böngészőbe:
                    </p>
                    
                    <p style="margin: 0 0 30px 0; padding: 15px; background-color: #f8f8f8; border-radius: 4px; word-break: break-all; color: #666666; font-size: 13px; font-family: monospace;">
                      ${verificationLink}
                    </p>
                    
                    <hr style="border: none; border-top: 1px solid #eeeeee; margin: 30px 0;">
                    
                    <p style="margin: 0; color: #999999; font-size: 13px; line-height: 1.6;">
                      ⚠️ Ha nem te regisztráltál, hagyd figyelmen kívül ezt az emailt. A link 24 óra múlva lejár.
                    </p>
                  </td>
                </tr>
                
                <!-- Footer -->
                <tr>
                  <td style="padding: 30px 40px; background-color: #f8f8f8; border-radius: 0 0 8px 8px; text-align: center;">
                    <p style="margin: 0; color: #999999; font-size: 12px;">
                      © ${new Date().getFullYear()} LudusGen. Minden jog fenntartva.
                    </p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
  };

  const info = await sendTransactionalEmail(mailOptions);
  console.log('[Email] Verification email sent to:', maskEmail(email));
  if (info.messageId) {
    console.log('[Email] Message ID:', info.messageId);
  }
  return info;
}

// verifyFirebaseToken imported from ./src/middleware/verifyFirebaseToken.js

// ==================== HELPER FUNCTIONS ====================

async function get2FAData(userId) {
  try {
    const doc = await db.collection("users").doc(userId).get();
    if (!doc.exists) return null;

    const data = doc.data();
    return {
      secret: data.twoFA?.secret || null,
      is2FAEnabled: data.twoFA?.enabled || false,
      backupCodes: data.twoFA?.backupCodes || [],
    };
  } catch (error) {
    console.error("Get 2FA data error:", error);
    return null;
  }
}

async function save2FAData(userId, twoFAData) {
  try {
    await db.collection("users").doc(userId).set(
      {
        twoFA: {
          secret: twoFAData.secret || null,
          enabled: twoFAData.is2FAEnabled || false,
          backupCodes: twoFAData.backupCodes || [],
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
      },
      { merge: true }
    );
    return true;
  } catch (error) {
    console.error("Save 2FA data error:", error);
    return false;
  }
}

function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    codes.push(code);
  }
  return codes;
}

// ==================== MULTER CONFIGURATION FOR FILE UPLOADS ====================

// Memory storage for Cloudinary upload
const storage = multer.memoryStorage();

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype) {
      return cb(null, true);
    } else {
      cb(new Error('Csak képfájlokat lehet feltölteni!'));
    }
  }
});

// ==================== PUBLIC ENDPOINTS ====================

// ✅ BIZTONSÁGOS REGISZTRÁCIÓ NODEMAILER-REL
app.post("/api/register-user", async (req, res) => {
  try {
    const { email, password, displayName } = req.body;

    // Validáció
    if (!email || !password || !displayName) {
      return res.status(400).json({
        success: false,
        message: "Email, jelszó és név szükséges"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "A jelszó legalább 6 karakter hosszú legyen"
      });
    }

    if (displayName.trim().length < 1) {
      return res.status(400).json({
        success: false,
        message: "A név legalább 2 karakter hosszú legyen"
      });
    }

    console.log("📝 Registering new user:", email);

    // 1. Firebase Auth user létrehozása (Admin SDK - NEM jelentkeztet be!)
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: displayName.trim(),
      emailVerified: false,
    });

    console.log("✅ Firebase Auth user created:", userRecord.uid);

    // 2. Email verifikációs link generálása
    const verificationLink = await admin.auth().generateEmailVerificationLink(email, {
      url: getFrontendUrl(),
    });

    console.log("📧 Email verification link generated");

    // 3. Email küldése
    try {
      await withTimeout(
        sendVerificationEmail(email, verificationLink, displayName),
        EMAIL_SEND_TIMEOUT_MS,
        'Verification email sending timed out',
      );
    } catch (emailError) {
      console.error('[Email] Verification email failed:', getSafeErrorMessage(emailError));
      try {
        await admin.auth().deleteUser(userRecord.uid);
        console.warn('[Email] Deleted auth user after verification email failure:', userRecord.uid);
      } catch (cleanupError) {
        console.error('[Email] Could not delete auth user after email failure:', getSafeErrorMessage(cleanupError));
      }

      return res.status(502).json({
        success: false,
        message: "Az email küldése sikertelen. Próbáld újra később.",
      });
    }

    // 4. Firestore dokumentum létrehozása
    await db.collection("users").doc(userRecord.uid).set({
      email,
      name: displayName.trim(),
      displayName: displayName.trim(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      twoFA: {
        enabled: false,
        secret: null,
        backupCodes: [],
      },
    });

    console.log("✅ Firestore user document created");
    console.log("✅ Registration complete for:", email);

    res.json({
      success: true,
      message: "Regisztráció sikeres! Elküldtük az email megerősítő linket.",
    });

  } catch (error) {
    console.error("❌ Registration error:", error);

    if (error.code === 'auth/email-already-exists') {
      return res.status(400).json({
        success: false,
        message: "Ez az email cím már regisztrálva van"
      });
    }

    if (error.code === 'auth/invalid-email') {
      return res.status(400).json({
        success: false,
        message: "Érvénytelen email cím"
      });
    }

    res.status(500).json({
      success: false,
      message: error.message || "Regisztrációs hiba"
    });
  }
});

app.post("/api/check-2fa-required", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email cím szükséges"
      });
    }

    const userRecord = await admin.auth().getUserByEmail(email);
    const twoFAData = await get2FAData(userRecord.uid);

    res.json({
      success: true,
      requires2FA: twoFAData?.is2FAEnabled || false,
      userId: userRecord.uid,
    });
  } catch (error) {
    if (error.code === "auth/user-not-found") {
      return res.json({
        success: true,
        requires2FA: false
      });
    }

    console.error("Check 2FA required error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

app.post("/api/validate-password", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email és jelszó szükséges"
      });
    }

    console.log("🔐 Validating password for:", email);

    const firebaseApiKey = process.env.FIREBASE_API_KEY;

    if (!firebaseApiKey) {
      throw new Error("FIREBASE_API_KEY nincs beállítva a .env fájlban!");
    }

    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${firebaseApiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email,
          password,
          returnSecureToken: true,
        }),
      }
    );

    const data = await response.json();

    if (response.ok) {
      console.log("✅ Password is valid for:", email);

      // Email verifikáció ellenőrzése
      const userRecord = await admin.auth().getUserByEmail(email);
      if (!userRecord.emailVerified) {
        return res.status(401).json({
          success: false,
          message: "Nincs megerősítve az email!"
        });
      }

      res.json({
        success: true,
        message: "Jelszó helyes"
      });
    } else {
      console.log("❌ Invalid password for:", email);
      res.status(401).json({
        success: false,
        message: "Hibás email/jelszó páros"
      });
    }
  } catch (error) {
    console.error("❌ Password validation error:", error);
    res.status(500).json({
      success: false,
      message: "Szerver hiba"
    });
  }
});

app.post("/api/login-with-2fa", async (req, res) => {
  try {
    const { email, code } = req.body;
    console.log("🔐 2FA Login attempt:", email);

    if (!email || !code) {
      return res.status(400).json({
        success: false,
        message: "Email és kód szükséges"
      });
    }

    const userRecord = await admin.auth().getUserByEmail(email);
    const userId = userRecord.uid;

    // Email verifikáció ellenőrzése
    if (!userRecord.emailVerified) {
      return res.status(403).json({
        success: false,
        message: "Email nincs megerősítve!"
      });
    }

    const twoFAData = await get2FAData(userId);

    if (!twoFAData || !twoFAData.is2FAEnabled) {
      return res.status(400).json({
        success: false,
        message: "2FA nincs engedélyezve"
      });
    }

    let isValid = speakeasy.totp.verify({
      secret: twoFAData.secret,
      encoding: 'base32',
      token: code,
      window: 2
    });

    if (!isValid && twoFAData.backupCodes.includes(code)) {
      isValid = true;
      const updatedBackupCodes = twoFAData.backupCodes.filter(bc => bc !== code);
      await save2FAData(userId, {
        ...twoFAData,
        backupCodes: updatedBackupCodes,
      });
      console.log(`✅ Backup kód használva. Megmaradt: ${updatedBackupCodes.length}`);
    }

    if (isValid) {
      const customToken = await admin.auth().createCustomToken(userId);

      res.json({
        success: true,
        message: "Sikeres 2FA validáció",
        customToken: customToken,
        remainingBackupCodes: twoFAData.backupCodes?.length || 0,
      });
    } else {
      res.status(400).json({
        success: false,
        message: "Érvénytelen kód"
      });
    }
  } catch (error) {
    if (error.code === "auth/user-not-found") {
      return res.status(404).json({
        success: false,
        message: "Felhasználó nem található"
      });
    }

    console.error("Login 2FA error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

app.post("/api/create-user", async (req, res) => {
  try {
    const { uid, email, name, displayName } = req.body;

    if (!uid || !email) {
      return res.status(400).json({
        success: false,
        message: "UID és email szükséges"
      });
    }

    await db.collection("users").doc(uid).set({
      email,
      name: name || displayName || "User",
      displayName: displayName || name || "User",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      twoFA: {
        enabled: false,
        secret: null,
        backupCodes: [],
      },
    });

    res.json({
      success: true,
      message: "User dokumentum létrehozva"
    });
  } catch (error) {
    console.error("Create user error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

// ==================== PROTECTED ENDPOINTS ====================

// Backend: /api/get-user/:uid módosítása
// ✅ PUBLIKUS PROFIL LEKÉRÉSE (CSAK BIZTONSÁGOS MEZŐK)
app.get("/api/get-public-profile/:uid", verifyFirebaseToken, async (req, res) => {
  try {
    const { uid } = req.params;

    const userDocRef = admin.firestore().collection("users").doc(uid);
    const userDoc = await userDocRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        message: "Felhasználó nem található"
      });
    }

    const data = userDoc.data();

    // 🔥 CSAK BIZTONSÁGOS ADATOKAT ADUNK KI
    const publicProfile = {
      uid: uid,
      displayName: data.displayName || data.name || "Névtelen",
      profilePicture: data.profilePicture || data.photoURL || null,
      createdAt: data.createdAt || null,
      name: data.name || data.displayName || "Névtelen"
    };

    res.json({
      success: true,
      user: publicProfile
    });

  } catch (error) {
    console.error("Error in get-public-profile:", error);
    res.status(500).json({
      success: false,
      message: "Szerver hiba"
    });
  }
});

app.get("/api/get-user/:uid", async (req, res) => {
  try {
    const { uid } = req.params;
    const token = req.headers.authorization?.split("Bearer ")[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token hiányzik"
      });
    }

    // Token verifikálás
    const decodedToken = await admin.auth().verifyIdToken(token);

    if (decodedToken.uid !== uid) {
      return res.status(403).json({
        success: false,
        message: "Hozzáférés megtagadva"
      });
    }

    const userDocRef = admin.firestore().collection("users").doc(uid);
    const userDoc = await userDocRef.get();

    // 🔥 HA NEM LÉTEZIK, HOZZUK LÉTRE
    if (!userDoc.exists) {
      console.log("⚠️ User document not found, creating it now for:", uid);

      const userRecord = await admin.auth().getUser(uid);
      const isGoogleProvider = userRecord.providerData.some(
        p => p.providerId === 'google.com'
      );

      await userDocRef.set({
        email: userRecord.email,
        displayName: userRecord.displayName || "",
        name: userRecord.displayName || "",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        provider: isGoogleProvider ? "google" : "email",
        photoURL: userRecord.photoURL || null,
        twoFA: {
          enabled: false,
          secret: null,
          backupCodes: []
        }
      });

      console.log("✅ User document created for:", userRecord.email);

      // Frissen létrehozott dokumentum visszaadása
      const newUserDoc = await userDocRef.get();
      return res.json({
        success: true,
        user: newUserDoc.data()
      });
    }

    res.json({
      success: true,
      user: userDoc.data()
    });

  } catch (error) {
    console.error("Error in get-user:", error);
    res.status(500).json({
      success: false,
      message: "Szerver hiba"
    });
  }
});

app.get("/api/check-2fa-status", verifyFirebaseToken, async (req, res) => {
  try {
    const twoFAData = await get2FAData(req.userId);

    res.json({
      success: true,
      is2FAEnabled: twoFAData?.is2FAEnabled || false
    });
  } catch (error) {
    console.error("Check 2FA status error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

app.get("/api/setup-mfa", verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const userEmail = req.userEmail;

    console.log('🔧 Setting up MFA for user:', userId);

    const existing2FA = await get2FAData(userId);

    let secret;
    let backupCodes;

    if (existing2FA?.secret && !existing2FA.is2FAEnabled) {
      console.log('♻️ Reusing existing secret');
      secret = existing2FA.secret;
      backupCodes = existing2FA.backupCodes;
    } else {
      console.log('🆕 Generating new secret with Speakeasy');

      const secretObj = speakeasy.generateSecret({
        name: `LudusGen (${userEmail})`,
        issuer: 'LudusGen',
        length: 32
      });

      secret = secretObj.base32;
      backupCodes = generateBackupCodes();

      console.log('💾 Saving new secret to DB...');

      await save2FAData(userId, {
        secret,
        is2FAEnabled: false,
        backupCodes,
      });

      const verification = await get2FAData(userId);
      console.log('✅ Secrets match:', verification?.secret === secret);
    }

    const testToken = speakeasy.totp({
      secret: secret,
      encoding: 'base32'
    });
    console.log('🧪 Test token generated:', testToken);

    const otpauthUrl = speakeasy.otpauthURL({
      secret: secret,
      label: userEmail,
      issuer: 'LudusGen',
      encoding: 'base32'
    });

    const qr = await QRCode.toDataURL(otpauthUrl);

    console.log('✅ MFA setup data prepared');

    res.json({
      qr,
      secret,
      backupCodes,
    });
  } catch (error) {
    console.error("❌ Setup MFA error:", error);
    res.status(500).json({
      success: false,
      message: "Szerver hiba",
    });
  }
});

app.post("/api/verify-mfa", verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const code = String(req.body.code || "").trim();

    console.log('🔐 Verify MFA Request:');
    console.log('User ID:', userId);
    console.log('Code received:', code);

    if (!code || code.length !== 6) {
      console.warn('❌ Invalid code format');
      return res.status(400).json({
        success: false,
        message: "6 számjegyű kód szükséges",
      });
    }

    const twoFAData = await get2FAData(userId);

    if (!twoFAData || !twoFAData.secret) {
      console.error('❌ No 2FA session found');
      return res.status(400).json({
        success: false,
        message: "Nincs inicializált 2FA session",
      });
    }

    if (twoFAData.is2FAEnabled) {
      console.warn('❌ 2FA already enabled');
      return res.status(400).json({
        success: false,
        message: "2FA már aktív",
      });
    }

    const verified = speakeasy.totp.verify({
      secret: twoFAData.secret,
      encoding: 'base32',
      token: code,
      window: 2
    });

    console.log('🔍 Verification result:', verified);

    if (!verified) {
      const currentToken = speakeasy.totp({
        secret: twoFAData.secret,
        encoding: 'base32'
      });
      console.log('❓ Current valid token would be:', currentToken);

      return res.status(400).json({
        success: false,
        message: "Érvénytelen kód. Próbáld újra!",
      });
    }

    console.log('✅ Code verified, activating 2FA...');

    await save2FAData(userId, {
      secret: twoFAData.secret,
      backupCodes: twoFAData.backupCodes,
      is2FAEnabled: true,
      enabledAt: new Date().toISOString(),
    });

    console.log('✅ 2FA successfully enabled for user:', userId);

    res.json({
      success: true,
      message: "2FA sikeresen aktiválva",
      backupCodes: twoFAData.backupCodes,
    });
  } catch (error) {
    console.error("❌ Verify MFA error:", error);
    res.status(500).json({
      success: false,
      message: "Szerver hiba",
    });
  }
});

app.post("/api/disable-2fa", verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { code } = req.body;

    const twoFAData = await get2FAData(userId);

    if (!twoFAData || !twoFAData.is2FAEnabled) {
      return res.status(400).json({
        success: false,
        message: "2FA nincs engedélyezve"
      });
    }

    const verified = speakeasy.totp.verify({
      secret: twoFAData.secret,
      encoding: 'base32',
      token: code,
      window: 2
    });

    if (verified) {
      await save2FAData(userId, {
        secret: null,
        is2FAEnabled: false,
        backupCodes: [],
      });

      console.log('🔓 2FA disabled for user:', userId);

      res.json({
        success: true,
        message: "2FA kikapcsolva"
      });
    } else {
      res.status(400).json({
        success: false,
        message: "Érvénytelen kód"
      });
    }
  } catch (error) {
    console.error("Disable 2FA error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

app.get("/api/get-user/:userId", verifyFirebaseToken, async (req, res) => {
  try {
    const { userId } = req.params;

    if (userId !== req.userId) {
      return res.status(403).json({
        success: false,
        message: "Nincs jogosultságod ehhez az adathoz"
      });
    }

    const userDoc = await db.collection("users").doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        message: "User nem található"
      });
    }

    const userData = userDoc.data();

    res.json({
      success: true,
      user: {
        ...userData,
        uid: userId,
      }
    });
  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

app.post("/api/update-profile", verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { name, displayName, bio } = req.body;

    console.log('📥 Update profile request for user:', userId);
    console.log('📥 Received data:', { name, displayName, bio });

    if (displayName !== undefined && (!displayName || displayName.trim().length < 1)) {
      return res.status(400).json({
        success: false,
        message: "Name must be at least 2 characters long"
      });
    }

    const updateData = {};

    if (name !== undefined) updateData.name = name.trim();
    if (displayName !== undefined) updateData.displayName = displayName.trim();
    if (bio !== undefined) updateData.bio = bio.trim();

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({
        success: false,
        message: "No data to update"
      });
    }

    updateData.updatedAt = admin.firestore.FieldValue.serverTimestamp();

    console.log('💾 Saving to Firestore:', updateData);

    await db.collection("users").doc(userId).set(
      updateData,
      { merge: true }
    );

    console.log('✅ Profile updated successfully');

    const userDoc = await db.collection("users").doc(userId).get();
    const userData = userDoc.data();

    console.log('📤 Sending back updated user data');

    res.json({
      success: true,
      message: "Profil sikeresen frissítve",
      user: {
        ...userData,
        uid: userId,
      }
    });
  } catch (error) {
    console.error("❌ Update profile error:", error);
    res.status(500).json({
      success: false,
      message: "Szerver hiba"
    });
  }
});

// ==================== PROFILE PICTURE ENDPOINTS ====================

app.post("/api/upload-profile-picture", verifyFirebaseToken, upload.single('profilePicture'), async (req, res) => {
  try {
    const userId = req.userId;

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "Nincs feltöltött fájl"
      });
    }

    console.log('📸 Uploading profile picture to Cloudinary for user:', userId);
    console.log('📁 File info:', {
      originalname: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype
    });

    // Get old profile picture to delete from Cloudinary
    const userDoc = await db.collection("users").doc(userId).get();
    const oldProfilePicture = userDoc.data()?.profilePicture;
    const oldPublicId = userDoc.data()?.profilePicturePublicId;

    // Upload to Cloudinary
    const uploadPromise = new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          folder: 'profile-pictures',
          public_id: `user_${userId}_${Date.now()}`,
          transformation: [
            { width: 500, height: 500, crop: 'limit' },
            { quality: 'auto' }
          ]
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );

      uploadStream.end(req.file.buffer);
    });

    const cloudinaryResult = await uploadPromise;

    console.log('☁️ Cloudinary upload successful:', cloudinaryResult.public_id);

    // Delete old image from Cloudinary if exists
    if (oldPublicId) {
      try {
        await cloudinary.uploader.destroy(oldPublicId);
        console.log('🗑️ Old profile picture deleted from Cloudinary');
      } catch (err) {
        console.log('⚠️ Could not delete old image from Cloudinary:', err.message);
      }
    }

    // Save new profile picture URL to Firestore
    await db.collection("users").doc(userId).set(
      {
        profilePicture: cloudinaryResult.secure_url,
        profilePicturePublicId: cloudinaryResult.public_id,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    console.log('✅ Profile picture uploaded successfully');

    res.json({
      success: true,
      message: "Profilkép sikeresen feltöltve",
      profilePictureUrl: cloudinaryResult.secure_url
    });
  } catch (error) {
    console.error("❌ Upload profile picture error:", error);
    res.status(500).json({
      success: false,
      message: error.message || "Szerver hiba"
    });
  }
});

// // ✅ GOOGLE TOKEN VALIDÁLÁS + FIRESTORE DOKUMENTUM LÉTREHOZÁS + SESSION TÁROLÁS
// app.post("/api/validate-google-token", async (req, res) => {
//   try {
//     const { googleToken, email } = req.body;

//     if (!googleToken || !email) {
//       return res.status(400).json({ 
//         success: false, 
//         message: "Google token és email szükséges" 
//       });
//     }

//     console.log("🔐 Validating Google token for:", email);

//     // Google token verifikálása
//     const decodedToken = await admin.auth().verifyIdToken(googleToken);

//     if (decodedToken.email !== email) {
//       return res.status(401).json({ 
//         success: false, 
//         message: "Email nem egyezik" 
//       });
//     }

//     const userRecord = await admin.auth().getUserByEmail(email);

//     if (userRecord.email !== email) {
//       return res.status(400).json({ 
//         success: false, 
//         message: "Email mismatch" 
//       });
//     }

//     if (!userRecord.emailVerified) {
//       return res.status(401).json({ 
//         success: false, 
//         message: "Nincs megerősítve az email!" 
//       });
//     }

//     console.log("✅ Google token is valid for:", email);

//     // 🔥 FIRESTORE DOKUMENTUM LÉTREHOZÁSA (ha még nincs)
//     const userDocRef = admin.firestore().collection("users").doc(decodedToken.uid);
//     const userDoc = await userDocRef.get();

//     if (!userDoc.exists) {
//       await userDocRef.set({
//         email,
//         displayName: userRecord.displayName || "",
//         name: userRecord.displayName || "",
//         createdAt: admin.firestore.FieldValue.serverTimestamp(),
//         provider: "google",
//         photoURL: userRecord.photoURL || null,
//         twoFA: {
//           enabled: false,
//           secret: null,
//           backupCodes: []
//         }
//       });
//       console.log("✅ Google user document created in Firestore for:", email);
//     } else {
//       console.log("✅ Google user document already exists for:", email);
//     }

//     // ✅ TÁROLJUK A SESSION-T 2FA-hoz (mint az emailes verzióban)
//     const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

//     // In-memory tárolás (production-ben használj Redis-t!)
//     pendingAuth.set(sessionId, {
//       email,
//       googleToken,
//       uid: decodedToken.uid,
//       timestamp: Date.now(),
//       provider: 'google'
//     });

//     res.json({ 
//       success: true,
//       message: "Google token helyes",
//       sessionId  // ← Ezt add vissza a frontend-nek
//     });

//   } catch (error) {
//     console.error("❌ Google token validation error:", error);
//     res.status(500).json({ 
//       success: false, 
//       message: "Google token érvénytelen" 
//     });
//   }
// });

// ==================== IN-MEMORY SESSION STORAGE ====================
const pendingAuth = new Map();

// Cleanup régi sessionök
setInterval(() => {
  const now = Date.now();
  const fiveMinutes = 5 * 60 * 1000;

  for (const [sessionId, sessionData] of pendingAuth.entries()) {
    if (now - sessionData.timestamp > fiveMinutes) {
      pendingAuth.delete(sessionId);
      console.log(`🗑️ Expired session deleted: ${sessionId}`);
    }
  }
}, 60 * 1000);

// ✅ GOOGLE 2FA LOGIN
app.post("/api/login-with-2fa-google", async (req, res) => {
  try {
    const { sessionId, code } = req.body;

    console.log("🔐 Google 2FA Login attempt with sessionId:", sessionId);

    if (!sessionId || !code) {
      return res.status(400).json({
        success: false,
        message: "SessionId és kód szükséges"
      });
    }

    const session = pendingAuth.get(sessionId);

    if (!session) {
      return res.status(400).json({
        success: false,
        message: "Lejárt vagy érvénytelen session"
      });
    }

    if (session.provider !== 'google') {
      return res.status(400).json({
        success: false,
        message: "Ez a session nem Google bejelentkezéshez tartozik"
      });
    }

    const userId = session.uid;
    const twoFAData = await get2FAData(userId);

    if (!twoFAData || !twoFAData.is2FAEnabled) {
      return res.status(400).json({
        success: false,
        message: "2FA nincs engedélyezve"
      });
    }

    let isValid = speakeasy.totp.verify({
      secret: twoFAData.secret,
      encoding: 'base32',
      token: code,
      window: 2
    });

    if (!isValid && twoFAData.backupCodes.includes(code)) {
      isValid = true;
      const updatedBackupCodes = twoFAData.backupCodes.filter(bc => bc !== code);
      await save2FAData(userId, {
        ...twoFAData,
        backupCodes: updatedBackupCodes,
      });
      console.log(`✅ Backup kód használva. Megmaradt: ${updatedBackupCodes.length}`);
    }

    if (isValid) {
      const customToken = await admin.auth().createCustomToken(userId);
      pendingAuth.delete(sessionId);

      res.json({
        success: true,
        message: "Sikeres 2FA validáció",
        customToken: customToken,
        remainingBackupCodes: twoFAData.backupCodes?.length || 0,
      });
    } else {
      res.status(400).json({
        success: false,
        message: "Érvénytelen kód"
      });
    }
  } catch (error) {
    console.error("❌ Google 2FA login error:", error);
    res.status(500).json({
      success: false,
      message: "Szerver hiba"
    });
  }
});

// ✅ GOOGLE SESSION VALIDÁLÁS - FIREBASE ID TOKEN-NEL
app.post("/api/validate-google-session", async (req, res) => {
  try {
    const { firebaseIdToken, email } = req.body;

    if (!firebaseIdToken || !email) {
      return res.status(400).json({
        success: false,
        message: "Firebase token és email szükséges"
      });
    }

    console.log("🔐 Validating Firebase token for Google user:", email);

    // ✅ Firebase ID token verifikálása (ez most működni fog!)
    const decodedToken = await admin.auth().verifyIdToken(firebaseIdToken);

    if (decodedToken.email !== email) {
      return res.status(401).json({
        success: false,
        message: "Email nem egyezik"
      });
    }

    const userRecord = await admin.auth().getUser(decodedToken.uid);

    if (!userRecord.emailVerified) {
      return res.status(401).json({
        success: false,
        message: "Nincs megerősítve az email!"
      });
    }

    console.log("✅ Firebase token is valid for:", email);

    // 🔥 FIRESTORE DOKUMENTUM LÉTREHOZÁSA (ha még nincs)
    const userDocRef = admin.firestore().collection("users").doc(decodedToken.uid);

    // Transaction használata race condition ellen
    await admin.firestore().runTransaction(async (transaction) => {
      const doc = await transaction.get(userDocRef);

      if (!doc.exists) {
        const isGoogleProvider = userRecord.providerData.some(
          p => p.providerId === 'google.com'
        );

        transaction.set(userDocRef, {
          email,
          displayName: userRecord.displayName || "",
          name: userRecord.displayName || "",
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
          provider: isGoogleProvider ? "google" : "email",
          photoURL: userRecord.photoURL || null,
          twoFA: {
            enabled: false,
            secret: null,
            backupCodes: []
          }
        });

        console.log("✅ Google user document created in Firestore for:", email);
      } else {
        console.log("✅ Google user document already exists for:", email);
      }
    });

    // ✅ SESSION TÁROLÁS 2FA-hoz
    const sessionId = `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    pendingAuth.set(sessionId, {
      email,
      uid: decodedToken.uid,
      timestamp: Date.now(),
      provider: 'google'
    });

    console.log("✅ Session created:", sessionId);

    res.json({
      success: true,
      message: "Session létrehozva",
      sessionId
    });

  } catch (error) {
    console.error("❌ Google session validation error:", error);
    res.status(500).json({
      success: false,
      message: "Token érvénytelen"
    });
  }
});

app.post('/api/forgot-password', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();

  try {
    if (!email) {
      return res.status(200).json({ message: 'Ha létezik a fiók, kiküldtük az emailt.' });
    }

    console.log('📨 Forgot password requested for:', maskEmail(email));

    // 1. Ellenőrzd hogy létezik-e a user (Firebase Admin)
    let userRecord;
    try {
      userRecord = await admin.auth().getUserByEmail(email);
    } catch (err) {
      // Ha nem létezik, ne áruljuk el - biztonsági okból
      return res.status(200).json({ message: 'Ha létezik a fiók, kiküldtük az emailt.' });
    }

    // 2. Firebase generálja a reset linket (automatikusan kezeli a tokent)
    const resetLink = await admin.auth().generatePasswordResetLink(email, {
      url: getFrontendUrl(), // ide irányít vissza reset után
    });

    // 3. Küldd ki az emailt a konfigurált email providerrel
    await withTimeout(
      sendForgotPasswordEmail(email, resetLink, userRecord.displayName),
      EMAIL_SEND_TIMEOUT_MS,
      'Forgot password email sending timed out',
    );

    console.log('📧 Forgot password email sent to:', maskEmail(email));

    res.status(200).json({ message: 'Ha létezik a fiók, kiküldtük az emailt.' });
  } catch (error) {
    console.error('[Email] Forgot password error:', getSafeErrorMessage(error));
    res.status(502).json({ error: 'Az email szolgáltatás átmenetileg nem elérhető.' });
  }
});

app.delete("/api/delete-profile-picture", verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;

    console.log('🗑️ Deleting profile picture for user:', userId);

    const userDoc = await db.collection("users").doc(userId).get();
    const profilePicture = userDoc.data()?.profilePicture;
    const publicId = userDoc.data()?.profilePicturePublicId;

    if (!profilePicture) {
      return res.status(400).json({
        success: false,
        message: "Nincs profilkép a törléshez"
      });
    }

    // Delete from Cloudinary
    if (publicId) {
      try {
        await cloudinary.uploader.destroy(publicId);
        console.log('✅ Profile picture deleted from Cloudinary');
      } catch (err) {
        console.log('⚠️ Could not delete from Cloudinary:', err.message);
      }
    }

    // Update Firestore
    await db.collection("users").doc(userId).set(
      {
        profilePicture: admin.firestore.FieldValue.delete(),
        profilePicturePublicId: admin.firestore.FieldValue.delete(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    console.log('✅ Profile picture deleted successfully');

    res.json({
      success: true,
      message: "Profilkép sikeresen törölve"
    });
  } catch (error) {
    console.error("❌ Delete profile picture error:", error);
    res.status(500).json({
      success: false,
      message: "Szerver hiba"
    });
  }
});
// ==================== CREDIT SYSTEM ENDPOINTS ====================

// Engedélyezett kredit csomagok (whitelist – nem lehet tetszőleges összeget küldeni)
const CREDIT_PACKAGES = {
  starter: { id: 'starter', name: 'Starter', amount: 100, price: 'Ingyenes' },
  basic: { id: 'basic', name: 'Basic', amount: 500, price: '$4.99' },
  pro: { id: 'pro', name: 'Pro', amount: 1000, price: '$9.99' },
  ultra: { id: 'ultra', name: 'Ultra', amount: 5000, price: '$39.99' },
};

// GET /api/get-credits – aktuális egyenleg lekérése
app.get('/api/get-credits', verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const userDoc = await db.collection('users').doc(userId).get();

    if (!userDoc.exists) {
      return res.status(404).json({ success: false, message: 'Felhasználó nem található' });
    }

    const data = userDoc.data();
    const credits = data.credits ?? 0;

    // Utolsó 5 tranzakció összefoglaló
    const txSnap = await db
      .collection('users').doc(userId)
      .collection('creditTransactions')
      .orderBy('createdAt', 'desc')
      .limit(5)
      .get();

    const recentTransactions = txSnap.docs.map(d => ({ id: d.id, ...d.data() }));

    res.json({ success: true, credits, recentTransactions });
  } catch (error) {
    console.error('❌ get-credits error:', error);
    res.status(500).json({ success: false, message: 'Szerver hiba' });
  }
});

// POST /api/add-credits – kredit hozzáadása whitelist-validációval + biztonsági védelem
app.post('/api/add-credits', verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { packageId } = req.body;

    // 1. Whitelist ellenőrzés – csak előre definiált csomagok fogadhatók
    const pkg = CREDIT_PACKAGES[packageId];
    if (!pkg) {
      return res.status(400).json({ success: false, message: 'Érvénytelen kredit csomag' });
    }

    const userRef = db.collection('users').doc(userId);

    // 2. INGYENES csomag: csak egyszer igényelhető (Firestore transaction)
    if (pkg.id === 'starter') {
      let alreadyClaimed = false;

      await db.runTransaction(async (tx) => {
        const userSnap = await tx.get(userRef);
        const data = userSnap.exists ? userSnap.data() : {};

        if (data.hasClaimedFreeCredits === true) {
          alreadyClaimed = true;
          return; // transaction abort – nem írunk semmit
        }

        // Első és egyetlen alkalom – atomikusan jelöljük meg és adjuk hozzá
        tx.set(userRef, {
          credits: admin.firestore.FieldValue.increment(pkg.amount),
          hasClaimedFreeCredits: true,
        }, { merge: true });
      });

      if (alreadyClaimed) {
        return res.status(403).json({
          success: false,
          message: 'Az ingyenes Starter csomagot már egyszer felhasználtad',
        });
      }

    } else {
      // 3. FIZETŐS csomagok: rate-limit – max 10 tranzakció az elmúlt 1 órában
      // ⚠️ Firestore NEM támogat két különböző mezőn inequality filtert egyszerre,
      //    ezért csak createdAt>=... alapján kérdezünk, majd memóriában szűrjük a startert.
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      const recentTxSnap = await userRef
        .collection('creditTransactions')
        .where('createdAt', '>=', admin.firestore.Timestamp.fromDate(oneHourAgo))
        .get();

      // Memóriában szűrjük ki az ingyenes (starter) tranzakciókat
      const paidTxCount = recentTxSnap.docs.filter(
        d => d.data().packageId !== 'starter'
      ).length;

      if (paidTxCount >= 10) {
        console.warn(`⚠️ Rate limit hit for user ${userId}: ${paidTxCount} paid transactions in 1 hour`);
        return res.status(429).json({
          success: false,
          message: 'Túl sok kredit feltöltés egy órán belül. Kérlek próbáld újra később.',
        });
      }

      // Atomikus növelés
      await userRef.set(
        { credits: admin.firestore.FieldValue.increment(pkg.amount) },
        { merge: true }
      );
    }

    // Tranzakció előzmény mentése (mindkét esetben, ha idáig jutottunk)
    await userRef.collection('creditTransactions').add({
      packageId: pkg.id,
      packageName: pkg.name,
      amount: pkg.amount,
      price: pkg.price,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Friss egyenleg visszaadása
    const updatedDoc = await userRef.get();
    const newBalance = updatedDoc.data().credits;

    console.log(`✅ Credits added: ${pkg.amount} (${pkg.id}) → user ${userId}, balance: ${newBalance}`);
    res.json({ success: true, credits: newBalance, added: pkg.amount, package: pkg });

  } catch (error) {
    console.error('❌ add-credits error:', error);
    res.status(500).json({ success: false, message: 'Szerver hiba' });
  }
});


// GET /api/credit-history – utolsó 20 tranzakció
app.get('/api/credit-history', verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const snap = await db
      .collection('users').doc(userId)
      .collection('creditTransactions')
      .orderBy('createdAt', 'desc')
      .limit(20)
      .get();

    const transactions = snap.docs.map(d => {
      const data = d.data();
      return {
        id: d.id,
        ...data,
        // Firestore Timestamp → ISO string a frontendnek
        createdAt: data.createdAt?.toDate?.()?.toISOString() ?? null,
      };
    });

    res.json({ success: true, transactions });
  } catch (error) {
    console.error('❌ credit-history error:', error);
    res.status(500).json({ success: false, message: 'Szerver hiba' });
  }
});

// 4. Tripo router — after bodyParser, after aiRoutes
const tripoRouter = createTripoRouter(verifyFirebaseToken);
app.use("/api", tripoRouter);

// 5. Background task recovery — polls pending tasks and saves to history
startTaskRecovery();

// ==================== SERVER START ====================

const PORT = Number(process.env.PORT || 3001);
const server = app.listen(PORT, () => console.log(`🚀 Backend fut a ${PORT}-es porton (Nodemailer + Speakeasy)`));

server.on("error", (error) => {
  stopTaskRecovery();
  if (error.code === "EADDRINUSE") {
    console.error(`Backend inditas sikertelen: a ${PORT}-es port mar hasznalatban van. Allitsd le a masik backend folyamatot, vagy inditsd masik PORT ertekkel.`);
    process.exit(1);
  }
  throw error;
});

// Graceful shutdown — stop background recovery
process.on("SIGINT", () => { stopTaskRecovery(); server.close(); });
process.on("SIGTERM", () => { stopTaskRecovery(); server.close(); });

