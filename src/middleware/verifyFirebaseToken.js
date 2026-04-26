import admin from "firebase-admin";

export const verifyFirebaseToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split("Bearer ")[1];
    if (!token) {
      return res.status(401).json({ success: false, message: "Nincs autentikációs token" });
    }

    const decoded = await admin.auth().verifyIdToken(token);
    const user = await admin.auth().getUser(decoded.uid);

    if (!user.emailVerified) {
      return res.status(403).json({ success: false, message: "Email nincs megerősítve" });
    }

    req.userId = decoded.uid;
    req.userEmail = decoded.email;
    req.user = { uid: decoded.uid, email: decoded.email };
    next();
  } catch {
    return res.status(401).json({ success: false, message: "Érvénytelen token" });
  }
};
