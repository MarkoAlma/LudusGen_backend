// src/controllers/analyticsController.js
import { analyticsService } from "../services/analyticsService.js";

export async function getSummary(req, res) {
  try {
    const summary = analyticsService.getSummary();
    res.json({ success: true, ...summary });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
}

export async function getDailyCredits(req, res) {
  const days = Math.min(30, parseInt(req.query.days ?? "7", 10));
  const data = analyticsService.getDailyCredits(days);
  res.json({ success: true, days: data });
}

export async function getRecentTasks(req, res) {
  const limit = Math.min(100, parseInt(req.query.limit ?? "20", 10));
  const tasks = analyticsService.getRecentTasks(limit);
  res.json({ success: true, tasks });
}