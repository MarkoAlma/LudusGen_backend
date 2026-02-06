import speakeasy from "speakeasy";
import QRCode from "qrcode";
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import admin from "firebase-admin";
import { readFileSync } from "fs";
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

console.log('🔐 Using Speakeasy for TOTP (more reliable than otplib)');

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

// ==================== PUBLIC ENDPOINTS ====================

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

// ✅ ÚJ: Validate password endpoint (NEM jelentkeztet be!)
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

    // Firebase Admin SDK-val nem tudjuk közvetlenül ellenőrizni a jelszót
    // Ezért a Firebase Auth REST API-t használjuk
    // Ez NEM hoz létre session-t, csak ellenőrzi a credentials-t
    
    // FONTOS: Add hozzá a FIREBASE_API_KEY-t a .env fájlhoz!
    // Megtalálod: Firebase Console -> Project Settings -> Web API Key
    const firebaseApiKey = process.env.FIREBASE_API_KEY || "AIzaSyDummyKeyReplaceThis";
    
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
          returnSecureToken: true, // Kell token, de nem fogjuk használni
        }),
      }
    );

    const data = await response.json();

    if (response.ok) {
      console.log("✅ Password is valid for:", email);
      
      // Ellenőrizzük az email verifikációt
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
    
    if (!email || !code) {
      return res.status(400).json({ 
        success: false, 
        message: "Email és kód szükséges" 
      });
    }

    const userRecord = await admin.auth().getUserByEmail(email);
    const userId = userRecord.uid;
    const twoFAData = await get2FAData(userId);

    if (!twoFAData || !twoFAData.is2FAEnabled) {
      return res.status(400).json({ 
        success: false, 
        message: "2FA nincs engedélyezve" 
      });
    }

    // Speakeasy verify with window
    let isValid = speakeasy.totp.verify({
      secret: twoFAData.secret,
      encoding: 'base32',
      token: code,
      window: 2
    });

    // Backup kód check
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

// ==================== PROTECTED ENDPOINTS ====================

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
      
      // Speakeasy secret generation
      const secretObj = speakeasy.generateSecret({
        name: `LudusGen (${userEmail})`,
        issuer: 'LudusGen',
        length: 32
      });
      
      secret = secretObj.base32; // ⚠️ FONTOS: base32 encoding!
      backupCodes = generateBackupCodes();

      console.log('💾 Saving new secret to DB...');
      console.log('Secret (base32):', secret);
      console.log('Secret length:', secret?.length);

      await save2FAData(userId, {
        secret,
        is2FAEnabled: false,
        backupCodes,
      });

      // Verification
      const verification = await get2FAData(userId);
      console.log('✅ Secrets match:', verification?.secret === secret);
    }

    console.log('📝 Final secret length:', secret?.length);
    
    // Test token generation
    const testToken = speakeasy.totp({
      secret: secret,
      encoding: 'base32'
    });
    console.log('🧪 Test token generated:', testToken);

    // QR Code generation with otpauth URL
    const otpauthUrl = speakeasy.otpauthURL({
      secret: secret,
      label: userEmail,
      issuer: 'LudusGen',
      encoding: 'base32'
    });

    console.log('🔗 OTPAuth URL:', otpauthUrl);

    const qr = await QRCode.toDataURL(otpauthUrl);

    console.log('✅ MFA setup data prepared');

    res.json({
      qr,
      secret,  // Dev only
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
    console.log('Code length:', code?.length);

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

    console.log('📝 Secret from DB:', twoFAData.secret);
    console.log('Secret length:', twoFAData.secret?.length);

    // ⚠️ KRITIKUS: Speakeasy verify with window: 2
    const verified = speakeasy.totp.verify({
      secret: twoFAData.secret,
      encoding: 'base32',
      token: code,
      window: 2  // ±60 másodperc tolerancia
    });

    console.log('🔍 Code being checked:', code);
    console.log('🔍 Verification result:', verified);

    if (!verified) {
      // Debug: mi lenne a helyes kód
      const currentToken = speakeasy.totp({
        secret: twoFAData.secret,
        encoding: 'base32'
      });
      console.log('❓ Current valid token would be:', currentToken);
      console.log('⚠️ User entered:', code, '(did not match)');
      
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



// Add ezt az endpoint-ot a PROTECTED ENDPOINTS részhez a backend-en

app.get("/api/get-user/:userId", verifyFirebaseToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Csak a saját adatait kérheti le
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
});// ==================== PROTECTED ENDPOINTS ====================
// ...előző kód...

// ==================== PROTECTED ENDPOINTS ====================
// Cseréld le a régi app.post("/api/update-profile"...) endpoint-ot erre:

// ==================== PROTECTED ENDPOINTS ====================
// Cseréld le a régi app.post("/api/update-profile"...) endpoint-ot erre:

// ==================== PROTECTED ENDPOINTS ====================
// Cseréld le a régi app.post("/api/update-profile"...) endpoint-ot erre:

// ==================== PROTECTED ENDPOINTS - JAVÍTOTT VERZIÓ ====================

// Cseréld le a meglévő app.post("/api/update-profile"...) kódot erre:

app.post("/api/update-profile", verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { name, displayName, bio } = req.body;

    console.log('📥 Update profile request for user:', userId);
    console.log('📥 Received data:', { name, displayName, bio });

    // Validáció
    if (displayName !== undefined && (!displayName || displayName.trim().length < 2)) {
      return res.status(400).json({ 
        success: false, 
        message: "A név legalább 2 karakter hosszú legyen" 
      });
    }

    // Csak azokat az adatokat mentjük, amik jöttek a request-ben
    const updateData = {};
    
    if (name !== undefined) updateData.name = name.trim();
    if (displayName !== undefined) updateData.displayName = displayName.trim();
    if (bio !== undefined) updateData.bio = bio.trim();

    // Ha nincs semmi frissítés
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

    // Visszaküldjük a teljes frissített user adatokat
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
// ==================== SERVER START ====================

app.listen(3001, () => console.log("🚀 Backend fut a 3001-es porton (Speakeasy TOTP)"));