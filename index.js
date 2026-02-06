import { authenticator } from "@otplib/preset-v11";
import QRCode from "qrcode";
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import admin from "firebase-admin";
import { readFileSync } from "fs";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ==================== FIREBASE ADMIN INIT ====================
// A serviceAccountKey.json fájlt a projekt gyökerébe kell helyezni
// Firebase Console -> Project Settings -> Service Accounts -> Generate new private key
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
    req.userId = decodedToken.uid; // Ez lesz a user ID minden requestben
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

// User 2FA adatok lekérése Firestore-ból
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

// User 2FA adatok mentése Firestore-ba
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

// Backup kódok generálása
function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    codes.push(code);
  }
  return codes;
}

// ==================== PUBLIC ENDPOINTS (nem kell token) ====================

// Check if user needs 2FA for login (by email)
app.post("/api/check-2fa-required", async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: "Email cím szükséges" 
      });
    }

    // Firebase Auth user lekérése email alapján
    const userRecord = await admin.auth().getUserByEmail(email);
    
    // Firestore-ból lekérjük a 2FA státuszt
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

// Login endpoint 2FA-val (NEM kell Firebase token, mert még nem vagyunk bejelentkezve)
app.post("/api/login-with-2fa", async (req, res) => {
  try {
    const { email, code } = req.body;
    
    if (!email || !code) {
      return res.status(400).json({ 
        success: false, 
        message: "Email és kód szükséges" 
      });
    }

    // User lekérése email alapján
    const userRecord = await admin.auth().getUserByEmail(email);
    const userId = userRecord.uid;
    
    // 2FA adatok lekérése
    const twoFAData = await get2FAData(userId);

    if (!twoFAData || !twoFAData.is2FAEnabled) {
      return res.status(400).json({ 
        success: false, 
        message: "2FA nincs engedélyezve ennél a felhasználónál" 
      });
    }

    // Ellenőrizzük normál kódot
    let isValid = authenticator.check(code, twoFAData.secret);

    // Ha nem valid, ellenőrizzük backup kódokat
    if (!isValid && twoFAData.backupCodes.includes(code)) {
      isValid = true;
      // Backup kód egyszeri használat után törlődik
      const updatedBackupCodes = twoFAData.backupCodes.filter(bc => bc !== code);
      await save2FAData(userId, {
        ...twoFAData,
        backupCodes: updatedBackupCodes,
      });
      console.log(`✅ Backup kód használva (${userId}). Megmaradt: ${updatedBackupCodes.length}`);
    }

    if (isValid) {
      // ✅ FONTOS: Generálunk egy Firebase Custom Token-t
      const customToken = await admin.auth().createCustomToken(userId);
      
      res.json({ 
        success: true,
        message: "Sikeres 2FA validáció",
        customToken: customToken, // ✅ Ezt küldjük a frontend-nek
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

// ==================== PROTECTED ENDPOINTS (Firebase token kell) ====================

// Check 2FA status
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

// Setup endpoint - QR kód generálás
app.get("/api/setup-mfa", verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const userEmail = req.userEmail;
    
    const secret = authenticator.generateSecret();
    const backupCodes = generateBackupCodes();
    
    // Tároljuk a secret-et és backup kódokat, de még nem engedélyezzük a 2FA-t
    await save2FAData(userId, {
      secret: secret,
      is2FAEnabled: false,
      backupCodes: backupCodes,
    });

    const otpauth = authenticator.keyuri(
      userEmail, 
      "LudusGen", 
      secret
    );
    const qr = await QRCode.toDataURL(otpauth);

    res.json({ 
      qr,
      secret,
      backupCodes,
    });
  } catch (error) {
    console.error("Setup MFA error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

// Verify endpoint - Kód ellenőrzés és aktiválás
app.post("/api/verify-mfa", verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { code } = req.body;
    
    const twoFAData = await get2FAData(userId);

    if (!twoFAData || !twoFAData.secret) {
      return res.status(400).json({ 
        success: false, 
        message: "Nincs inicializált 2FA session" 
      });
    }

    // Ellenőrizzük a kódot
    const isValid = authenticator.check(code, twoFAData.secret);

    if (isValid) {
      // Aktiváljuk a 2FA-t
      await save2FAData(userId, {
        ...twoFAData,
        is2FAEnabled: true,
      });
      
      res.json({ 
        success: true,
        backupCodes: twoFAData.backupCodes,
        message: "2FA sikeresen aktiválva"
      });
    } else {
      res.status(400).json({ 
        success: false, 
        message: "Érvénytelen kód" 
      });
    }
  } catch (error) {
    console.error("Verify MFA error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

// Disable 2FA
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

    const isValid = authenticator.check(code, twoFAData.secret);

    if (isValid) {
      await save2FAData(userId, {
        secret: null,
        is2FAEnabled: false,
        backupCodes: [],
      });
      
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

// Update profile (ha van ilyen endpoint)
app.post("/api/update-profile", verifyFirebaseToken, async (req, res) => {
  try {
    const userId = req.userId;
    const { name, displayName, email, phone, location, bio } = req.body;

    // Validáció
    if (!name || name.trim().length < 2) {
      return res.status(400).json({ 
        success: false, 
        message: "A név legalább 2 karakter hosszú legyen" 
      });
    }

    if (!email || !email.includes('@')) {
      return res.status(400).json({ 
        success: false, 
        message: "Érvényes email címet adj meg" 
      });
    }

    // Firestore frissítés
    await db.collection("users").doc(userId).set(
      {
        name: name.trim(),
        displayName: displayName.trim(),
        email: email.trim(),
        phone: phone?.trim() || "",
        location: location?.trim() || "",
        bio: bio?.trim() || "",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    res.json({ 
      success: true,
      message: "Profil sikeresen frissítve",
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

// Create user endpoint (signup-kor hívódik)
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

// ==================== SERVER START ====================

app.listen(3001, () => console.log("🚀 Backend fut a 3001-es porton"));