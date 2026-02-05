import { authenticator } from "@otplib/preset-v11";
import QRCode from "qrcode";
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Felhasználó adatok tárolása (valós appban DB-ben lenne)
const users = {
  "user123": {
    name: "Demo Felhasználó",
    displayName: "Demo",
    email: "demo@example.com",
    phone: "+36 30 123 4567",
    location: "Budapest, Magyarország",
    bio: "Szia! Én vagyok a demo felhasználó.",
    createdAt: new Date("2024-01-15"),
    accountType: "Standard",
    id: "user123",
  }
};

// ==================== PROFILE ENDPOINTS ====================

// Check 2FA status
app.get("/api/check-2fa-status", (req, res) => {
  try {
    const userId = "user123"; // Valós appban session-ből
    const user = users[userId];
    
    res.json({ 
      success: true,
      is2FAEnabled: user?.is2FAEnabled || false 
    });
  } catch (error) {
    console.error("Check 2FA status error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

// Check if user needs 2FA for login (by email)
app.post("/api/check-2fa-required", (req, res) => {
  try {
    const { email } = req.body;
    
    // Valós appban itt az email alapján néznénk meg a user-t a DB-ben
    // Most demo céljából mindig a user123-at nézzük
    const userId = "user123";
    const user = users[userId];
    
    if (!user) {
      return res.json({ 
        success: true,
        requires2FA: false 
      });
    }
    
    res.json({ 
      success: true,
      requires2FA: user.is2FAEnabled || false,
      userId: userId // Ezt session-ben tárolnánk
    });
  } catch (error) {
    console.error("Check 2FA required error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

// Update profile
app.post("/api/update-profile", (req, res) => {
  try {
    const userId = "user123"; // Valós appban session-ből
    const { name, displayName, email, phone, location, bio } = req.body;
    
    if (!users[userId]) {
      return res.status(404).json({ 
        success: false, 
        message: "Felhasználó nem található" 
      });
    }

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

    // Frissítés
    users[userId] = {
      ...users[userId],
      name: name.trim(),
      displayName: displayName.trim(),
      email: email.trim(),
      phone: phone?.trim() || "",
      location: location?.trim() || "",
      bio: bio?.trim() || "",
    };

    res.json({ 
      success: true,
      message: "Profil sikeresen frissítve",
      user: users[userId]
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

// ==================== 2FA ENDPOINTS ====================

// Setup endpoint - QR kód generálás
app.get("/api/setup-mfa", async (req, res) => {
  try {
    const userId = "user123"; // Valós appban ez session-ből jönne
    const secret = authenticator.generateSecret();
    
    // Inicializáljuk a user objektumot ha nem létezik
    if (!users[userId]) {
      users[userId] = {
        name: "Demo User",
        email: "demo@example.com",
        displayName: "Demo",
      };
    }
    
    // Tároljuk a secret-et, de még nem engedélyezzük a 2FA-t
    users[userId].secret = secret;
    users[userId].is2FAEnabled = false;
    users[userId].backupCodes = generateBackupCodes();

    const otpauth = authenticator.keyuri(
      users[userId].email, 
      "LudusGen", 
      secret
    );
    const qr = await QRCode.toDataURL(otpauth);

    res.json({ 
      qr,
      secret, // Opcionális: manual entry-hez
      backupCodes: users[userId].backupCodes
    });
  } catch (error) {
    console.error("Setup MFA error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

// Verify endpoint - Kód ellenőrzés és aktiválás
app.post("/api/verify-mfa", (req, res) => {
  try {
    const userId = "user123";
    const { code } = req.body;
    const user = users[userId];

    if (!user || !user.secret) {
      return res.status(400).json({ 
        success: false, 
        message: "Nincs inicializált 2FA session" 
      });
    }

    // Ellenőrizzük a kódot
    const isValid = authenticator.check(code, user.secret);

    if (isValid) {
      // Aktiváljuk a 2FA-t
      user.is2FAEnabled = true;
      
      res.json({ 
        success: true,
        backupCodes: user.backupCodes,
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

// Login endpoint 2FA-val
app.post("/api/login-with-2fa", (req, res) => {
  try {
    const userId = "user123";
    const { code } = req.body;
    const user = users[userId];

    if (!user || !user.is2FAEnabled) {
      return res.status(400).json({ 
        success: false, 
        message: "2FA nincs engedélyezve" 
      });
    }

    // Ellenőrizzük normál kódot
    let isValid = authenticator.check(code, user.secret);

    // Ha nem valid, ellenőrizzük backup kódokat
    if (!isValid && user.backupCodes && user.backupCodes.includes(code)) {
      isValid = true;
      // Backup kód egyszeri használat után törlődik
      user.backupCodes = user.backupCodes.filter(bc => bc !== code);
      console.log(`✅ Backup kód használva. Megmaradt: ${user.backupCodes.length}`);
    }

    if (isValid) {
      res.json({ 
        success: true,
        message: "Sikeres bejelentkezés 2FA-val",
        remainingBackupCodes: user.backupCodes?.length || 0,
        user: {
          email: user.email,
          name: user.name,
          displayName: user.displayName,
        }
      });
    } else {
      res.status(400).json({ 
        success: false, 
        message: "Érvénytelen kód" 
      });
    }
  } catch (error) {
    console.error("Login 2FA error:", error);
    res.status(500).json({ success: false, message: "Szerver hiba" });
  }
});

// Disable 2FA
app.post("/api/disable-2fa", (req, res) => {
  try {
    const userId = "user123";
    const { code } = req.body;
    const user = users[userId];

    if (!user || !user.is2FAEnabled) {
      return res.status(400).json({ 
        success: false, 
        message: "2FA nincs engedélyezve" 
      });
    }

    const isValid = authenticator.check(code, user.secret);

    if (isValid) {
      user.is2FAEnabled = false;
      user.secret = null;
      user.backupCodes = [];
      
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

// ==================== HELPER FUNCTIONS ====================

// Backup kódok generálása
function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = Math.random().toString(36).substring(2, 10).toUpperCase();
    codes.push(code);
  }
  return codes;
}

// ==================== SERVER START ====================

app.listen(3001, () => console.log("Backend fut a 3001-es porton"));