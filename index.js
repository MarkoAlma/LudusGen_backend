import speakeasy from "speakeasy";
import QRCode from "qrcode";
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import admin from "firebase-admin";
import { readFileSync } from "fs";
import nodemailer from "nodemailer";
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

console.log('🔐 Using Speakeasy for TOTP (more reliable than otplib)');

// ==================== CLOUDINARY CONFIG ====================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

console.log('☁️ Cloudinary configured:', process.env.CLOUDINARY_CLOUD_NAME ? '✅' : '❌ Missing credentials');

// ==================== FIREBASE ADMIN INIT ====================
try {
  const serviceAccount = JSON.parse(readFileSync("./serviceAccountKey.json"));
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log("✅ Firebase Admin inicializálva");
} catch (error) {
  console.error("❌ Firebase Admin init hiba:", error.message);
  console.log("Győződj meg róla, hogy a serviceAccountKey.json létezik!");
}

const db = admin.firestore();

// ==================== NODEMAILER SETUP ====================
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
  tls: {
    rejectUnauthorized: false
  }
});

// ✅ VERIFY CONNECTION
transporter.verify(function (error, success) {
  if (error) {
    console.log('❌ SMTP connection error:', error);
  } else {
    console.log('✅ SMTP server is ready to send emails');
  }
});

// Email küldő függvény
async function sendVerificationEmail(email, verificationLink, displayName) {
  const mailOptions = {
    from: {
      name: 'LudusGen',
      address: process.env.EMAIL_USER
    },
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

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Verification email sent to:', email);
    console.log('📧 Message ID:', info.messageId);
    console.log('📬 Preview URL:', nodemailer.getTestMessageUrl(info)); // Ha Ethereal-t használnál
    return true;
  } catch (error) {
    console.error('❌ Email sending failed:', error);
    console.error('Error details:', error.message);
    return false;
  }
}

// ==================== MIDDLEWARE: Firebase Auth Token ellenőrzés ====================
const verifyFirebaseToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split("Bearer ")[1];
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: "Nincs autentikációs token" 
      });
    }

    const decodedToken = await admin.auth().verifyIdToken(token);
    
    // Email verifikáció ellenőrzése
    const userRecord = await admin.auth().getUser(decodedToken.uid);
    if (!userRecord.emailVerified) {
      return res.status(403).json({ 
        success: false, 
        message: "Email nincs megerősítve" 
      });
    }
    
    req.userId = decodedToken.uid;
    req.userEmail = decodedToken.email;
    next();
  } catch (error) {
    console.error("Token verify error:", error);
    return res.status(401).json({ 
      success: false, 
      message: "Érvénytelen token" 
    });
  }
};

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
    
    if (displayName.trim().length < 2) {
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
      url: 'http://localhost:5173', // Ide irányít az email link után
    });
    console.log(verificationLink);
    
    
    console.log("📧 Email verification link generated");
    
    // 3. Email küldése Nodemailer-rel
    const emailSent = await sendVerificationEmail(email, verificationLink, displayName);
    
    if (!emailSent) {
      console.warn('⚠️ Email sending failed, but user created');
      // Opcionális: törölheted a usert, ha az email küldés sikertelen
      // await admin.auth().deleteUser(userRecord.uid);
      // return res.status(500).json({ success: false, message: "Email küldése sikertelen" });
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
        message: "Érvénytelen email cím formátum" 
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

app.get("/api/get-user/:uid", verifyFirebaseToken, async (req, res) => {
  try {
    const { uid } = req.params;
    
    // Csak a saját adatait kérheti le
    if (uid !== req.userId) {
      return res.status(403).json({ 
        success: false, 
        message: "Nincs jogosultság" 
      });
    }
    
    const doc = await db.collection("users").doc(uid).get();
    
    if (!doc.exists) {
      return res.status(404).json({ 
        success: false, 
        message: "User nem található" 
      });
    }
    
    res.json({ 
      success: true,
      user: doc.data()
    });
  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
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

    if (displayName !== undefined && (!displayName || displayName.trim().length < 2)) {
      return res.status(400).json({ 
        success: false, 
        message: "A név legalább 2 karakter hosszú legyen" 
      });
    }

    const updateData = {};
    
    if (name !== undefined) updateData.name = name.trim();
    if (displayName !== undefined) updateData.displayName = displayName.trim();
    if (bio !== undefined) updateData.bio = bio.trim();

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ 
        success: false, 
        message: "Nincs frissítendő adat" 
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

// ==================== SERVER START ====================

app.listen(3001, () => console.log("🚀 Backend fut a 3001-es porton (Nodemailer + Speakeasy)"));