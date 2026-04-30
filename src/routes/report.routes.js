import express from "express";
import {
  createReport,
  listReports,
  moderateReportedContent,
  requireLudusgenAdmin,
  updateReportStatus,
} from "../controllers/reportController.js";

export function createReportRouter(verifyFirebaseToken) {
  const router = express.Router();

  router.post("/reports", verifyFirebaseToken, createReport);
  router.get("/admin/reports", verifyFirebaseToken, requireLudusgenAdmin, listReports);
  router.patch("/admin/reports/:id", verifyFirebaseToken, requireLudusgenAdmin, updateReportStatus);
  router.post("/admin/reports/:id/action", verifyFirebaseToken, requireLudusgenAdmin, moderateReportedContent);

  return router;
}
