import admin from "firebase-admin";

function parseAdminEmailAllowlist() {
  const raw = process.env.TRIPO_ADMIN_EMAILS || process.env.ADMIN_EMAILS || "";
  return new Set(
    raw
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  );
}

export const verifyFirebaseToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split("Bearer ")[1];
    if (!token) {
      return res.status(401).json({ success: false, message: "Nincs autentikacios token" });
    }

    const decoded = await admin.auth().verifyIdToken(token);
    const user = await admin.auth().getUser(decoded.uid);
    const claims = {
      ...(decoded || {}),
      ...(user.customClaims || {}),
    };
    const email = decoded.email || user.email || null;
    const normalizedEmail = typeof email === "string" ? email.trim().toLowerCase() : "";
    const adminEmailAllowlist = parseAdminEmailAllowlist();
    const isAdmin = claims.admin === true
      || claims.isAdmin === true
      || claims.role === "admin"
      || (normalizedEmail && adminEmailAllowlist.has(normalizedEmail));

    if (!user.emailVerified) {
      return res.status(403).json({ success: false, message: "Email nincs megerositve" });
    }

    req.userId = decoded.uid;
    req.userEmail = email;
    req.userClaims = claims;
    req.user = {
      uid: decoded.uid,
      email,
      claims,
      isAdmin,
    };
    next();
  } catch {
    return res.status(401).json({ success: false, message: "Ervenytelen token" });
  }
};
