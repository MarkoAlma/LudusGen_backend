import admin from "firebase-admin";

const REPORTS_COLLECTION = "reports";
const ADMIN_EMAIL = "ludusgen@gmail.com";
const ALLOWED_SOURCE_TYPES = new Set([
  "forum_post",
  "forum_comment",
  "marketplace_asset",
]);
const ALLOWED_STATUSES = new Set(["open", "reviewed", "resolved", "dismissed"]);
const CONTENT_ACTIONS = new Set(["hide_content", "restore_content"]);

function cleanText(value, maxLength = 500) {
  return String(value || "").trim().slice(0, maxLength);
}

function cleanOptionalText(value, maxLength = 500) {
  const text = cleanText(value, maxLength);
  return text || "";
}

function cleanMetadata(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};

  const output = {};
  for (const [rawKey, rawValue] of Object.entries(input).slice(0, 24)) {
    const key = cleanText(rawKey, 64);
    if (!key) continue;

    if (typeof rawValue === "string") {
      output[key] = cleanText(rawValue, 1200);
    } else if (typeof rawValue === "number" && Number.isFinite(rawValue)) {
      output[key] = rawValue;
    } else if (typeof rawValue === "boolean") {
      output[key] = rawValue;
    } else if (Array.isArray(rawValue)) {
      output[key] = rawValue
        .slice(0, 16)
        .map((item) => cleanText(item, 160))
        .filter(Boolean);
    }
  }
  return output;
}

function serializeTimestamp(value) {
  if (!value) return null;
  if (typeof value.toDate === "function") return value.toDate().toISOString();
  if (typeof value._seconds === "number") return new Date(value._seconds * 1000).toISOString();
  return null;
}

function reportForClient(doc) {
  const data = doc.data();
  return {
    id: doc.id,
    ...data,
    createdAt: serializeTimestamp(data.createdAt),
    updatedAt: serializeTimestamp(data.updatedAt),
    reviewedAt: serializeTimestamp(data.reviewedAt),
    contentActionAt: serializeTimestamp(data.contentActionAt),
  };
}

function targetRefForReport(db, report) {
  if (report.sourceType === "marketplace_asset") {
    return db.collection("marketplace_assets").doc(report.targetId);
  }
  if (report.sourceType === "forum_post") {
    return db.collection("forum_posts").doc(report.targetId);
  }
  if (report.sourceType === "forum_comment") {
    return db.collection("forum_comments").doc(report.targetId);
  }
  return null;
}

export function isLudusgenAdminEmail(email) {
  return typeof email === "string" && email.trim().toLowerCase() === ADMIN_EMAIL;
}

export function requireLudusgenAdmin(req, res, next) {
  if (isLudusgenAdminEmail(req.user?.email || req.userEmail)) return next();
  return res.status(403).json({
    success: false,
    message: "Admin access requires the LudusGen admin account",
  });
}

export async function createReport(req, res) {
  try {
    const body = req.body || {};
    const sourceType = cleanText(body.sourceType, 40);
    const targetId = cleanText(body.targetId, 180);
    const reason = cleanText(body.reason, 180);

    if (!ALLOWED_SOURCE_TYPES.has(sourceType)) {
      return res.status(400).json({ success: false, message: "Invalid report source" });
    }
    if (!targetId) {
      return res.status(400).json({ success: false, message: "Missing reported item" });
    }
    if (!reason) {
      return res.status(400).json({ success: false, message: "Missing report reason" });
    }

    const reportRef = admin.firestore().collection(REPORTS_COLLECTION).doc();
    const now = admin.firestore.FieldValue.serverTimestamp();

    await reportRef.set({
      sourceType,
      targetId,
      targetPath: cleanOptionalText(body.targetPath, 500),
      targetTitle: cleanOptionalText(body.targetTitle, 240),
      targetOwnerId: cleanOptionalText(body.targetOwnerId, 180),
      reason,
      details: cleanOptionalText(body.details, 1200),
      metadata: cleanMetadata(body.metadata),
      reporterId: req.user?.uid || req.userId || "",
      reporterEmail: req.user?.email || req.userEmail || "",
      status: "open",
      createdAt: now,
      updatedAt: now,
    });

    res.status(201).json({ success: true, id: reportRef.id });
  } catch (err) {
    console.error("[Reports] create error:", err);
    res.status(500).json({ success: false, message: err.message || "Failed to submit report" });
  }
}

export async function listReports(req, res) {
  try {
    const requestedStatus = cleanText(req.query.status || "all", 40).toLowerCase();
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 200);

    const snap = await admin.firestore()
      .collection(REPORTS_COLLECTION)
      .orderBy("createdAt", "desc")
      .limit(limit)
      .get();

    let reports = snap.docs.map(reportForClient);
    if (requestedStatus !== "all") {
      reports = reports.filter((report) => report.status === requestedStatus);
    }

    res.json({
      success: true,
      reports,
      stats: {
        total: reports.length,
        open: reports.filter((report) => report.status === "open").length,
        reviewed: reports.filter((report) => report.status === "reviewed").length,
        resolved: reports.filter((report) => report.status === "resolved").length,
        dismissed: reports.filter((report) => report.status === "dismissed").length,
      },
    });
  } catch (err) {
    console.error("[Reports] list error:", err);
    res.status(500).json({ success: false, message: err.message || "Failed to load reports" });
  }
}

export async function updateReportStatus(req, res) {
  try {
    const status = cleanText(req.body?.status, 40).toLowerCase();
    if (!ALLOWED_STATUSES.has(status)) {
      return res.status(400).json({ success: false, message: "Invalid report status" });
    }

    const ref = admin.firestore().collection(REPORTS_COLLECTION).doc(req.params.id);
    const snap = await ref.get();
    if (!snap.exists) {
      return res.status(404).json({ success: false, message: "Report not found" });
    }

    await ref.update({
      status,
      reviewedBy: req.user?.uid || req.userId || "",
      reviewedByEmail: req.user?.email || req.userEmail || "",
      reviewedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const updated = await ref.get();
    res.json({ success: true, report: reportForClient(updated) });
  } catch (err) {
    console.error("[Reports] update error:", err);
    res.status(500).json({ success: false, message: err.message || "Failed to update report" });
  }
}

export async function moderateReportedContent(req, res) {
  try {
    const action = cleanText(req.body?.action, 40).toLowerCase();
    if (!CONTENT_ACTIONS.has(action)) {
      return res.status(400).json({ success: false, message: "Invalid moderation action" });
    }

    const db = admin.firestore();
    const reportRef = db.collection(REPORTS_COLLECTION).doc(req.params.id);
    const reportSnap = await reportRef.get();
    if (!reportSnap.exists) {
      return res.status(404).json({ success: false, message: "Report not found" });
    }

    const report = { id: reportSnap.id, ...reportSnap.data() };
    const targetRef = targetRefForReport(db, report);
    if (!targetRef) {
      return res.status(400).json({ success: false, message: "Unsupported report target" });
    }

    const targetSnap = await targetRef.get();
    if (!targetSnap.exists) {
      await reportRef.update({
        status: "reviewed",
        contentAction: "target_missing",
        contentActionAt: admin.firestore.FieldValue.serverTimestamp(),
        contentActionBy: req.user?.uid || req.userId || "",
        contentActionByEmail: req.user?.email || req.userEmail || "",
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      const updatedMissing = await reportRef.get();
      return res.status(404).json({
        success: false,
        message: "Reported content was not found",
        report: reportForClient(updatedMissing),
      });
    }

    const now = admin.firestore.FieldValue.serverTimestamp();
    const moderatorId = req.user?.uid || req.userId || "";
    const moderatorEmail = req.user?.email || req.userEmail || "";

    if (action === "hide_content") {
      await targetRef.update({
        status: "hidden",
        isHidden: true,
        hiddenAt: now,
        hiddenBy: moderatorId,
        hiddenByEmail: moderatorEmail,
        hiddenFromReport: report.id,
        updatedAt: now,
      });

      await reportRef.update({
        status: "resolved",
        contentAction: "hidden",
        contentActionAt: now,
        contentActionBy: moderatorId,
        contentActionByEmail: moderatorEmail,
        reviewedBy: moderatorId,
        reviewedByEmail: moderatorEmail,
        reviewedAt: now,
        updatedAt: now,
      });
    } else {
      const restoredStatus = report.sourceType === "marketplace_asset" ? "published" : "active";
      await targetRef.update({
        status: restoredStatus,
        isHidden: false,
        restoredAt: now,
        restoredBy: moderatorId,
        restoredByEmail: moderatorEmail,
        updatedAt: now,
      });

      await reportRef.update({
        status: "reviewed",
        contentAction: "restored",
        contentActionAt: now,
        contentActionBy: moderatorId,
        contentActionByEmail: moderatorEmail,
        reviewedBy: moderatorId,
        reviewedByEmail: moderatorEmail,
        reviewedAt: now,
        updatedAt: now,
      });
    }

    const updated = await reportRef.get();
    res.json({ success: true, report: reportForClient(updated) });
  } catch (err) {
    console.error("[Reports] moderation error:", err);
    res.status(500).json({ success: false, message: err.message || "Failed to moderate content" });
  }
}
