// src/services/analyticsService.js
import { ANALYTICS_RETENTION_DAYS, MAX_RECENT_ERRORS, CREDIT_COSTS } from "../config/tripo.config.js";

class AnalyticsService {
  constructor() {
    /** @type {Map<string, object>} taskId → record */
    this._records     = new Map();
    /** @type {Map<string, object>} "YYYY-MM-DD" → DailyStats */
    this._daily       = new Map();
    /** @type {object[]} */
    this._recentErrors = [];
  }

  recordTaskStart(taskId, type, modelVersion) {
    this._records.set(taskId, { taskId, type, modelVersion, startedAt: Date.now(), status: "queued" });
  }

  recordTaskEnd(taskId, status, durationMs) {
    const rec = this._records.get(taskId);
    const now = Date.now();
    if (rec) {
      rec.status     = status;
      rec.finishedAt = now;
    }
    const actualDuration = durationMs || (rec ? now - rec.startedAt : 0);
    this._updateDailyStats(rec?.type ?? "unknown", status, actualDuration);
    if (this._records.size > 10_000) this._pruneRecords();
  }

  recordTaskError(taskId, type, error) {
    const rec = this._records.get(taskId);
    if (rec) rec.error = error;
    const metric = {
      taskId, type, status: "failed",
      durationMs: rec ? Date.now() - rec.startedAt : 0,
      modelVersion: rec?.modelVersion,
      createdAt: rec?.startedAt ?? Date.now(),
      error,
    };
    this._recentErrors.unshift(metric);
    if (this._recentErrors.length > MAX_RECENT_ERRORS)
      this._recentErrors = this._recentErrors.slice(0, MAX_RECENT_ERRORS);
    this._updateDailyStats(type, "failed", metric.durationMs);
  }

  getSummary() {
    const today    = this._getOrCreateDay(this._todayKey());
    const last7    = Array.from({ length: 7 }, (_, i) => {
      const d = new Date(); d.setDate(d.getDate() - i);
      return this._getOrCreateDay(this._dateKey(d));
    });

    const durations = [...this._records.values()]
      .filter(r => r.finishedAt)
      .map(r => r.finishedAt - r.startedAt)
      .sort((a, b) => a - b);

    const p50 = durations[Math.floor(durations.length * 0.5)] ?? 0;
    const p95 = durations[Math.floor(durations.length * 0.95)] ?? 0;
    const errorRate = today.tasksTotal > 0 ? today.tasksFailed / today.tasksTotal : 0;

    return { today, last7Days: last7, errorRate, p50DurationMs: p50, p95DurationMs: p95, recentErrors: this._recentErrors.slice(0, 10) };
  }

  getDailyCredits(days = 7) {
    return Array.from({ length: days }, (_, i) => {
      const d = new Date(); d.setDate(d.getDate() - i);
      const key = this._dateKey(d);
      return { date: key, credits: this._daily.get(key)?.creditsUsed ?? 0 };
    });
  }

  getRecentTasks(limit = 50) {
    return [...this._records.values()].sort((a, b) => b.startedAt - a.startedAt).slice(0, limit);
  }

  _updateDailyStats(type, status, durationMs) {
    const day = this._getOrCreateDay(this._todayKey());
    day.tasksTotal++;
    if (status === "success") { day.tasksSuccess++; day.creditsUsed += CREDIT_COSTS[type] ?? 0; }
    if (status === "failed")  day.tasksFailed++;
    day.avgDurationMs = day.tasksTotal > 1
      ? (day.avgDurationMs * (day.tasksTotal - 1) + durationMs) / day.tasksTotal
      : durationMs;
    day.byType[type] = (day.byType[type] ?? 0) + 1;
    this._pruneOldDays();
  }

  _getOrCreateDay(key) {
    if (!this._daily.has(key))
      this._daily.set(key, { date: key, creditsUsed: 0, tasksTotal: 0, tasksSuccess: 0, tasksFailed: 0, avgDurationMs: 0, byType: {} });
    return this._daily.get(key);
  }

  _pruneOldDays() {
    const cutoff = new Date(); cutoff.setDate(cutoff.getDate() - ANALYTICS_RETENTION_DAYS);
    const cutoffKey = this._dateKey(cutoff);
    for (const key of this._daily.keys()) if (key < cutoffKey) this._daily.delete(key);
  }

  _pruneRecords() {
    const oldest = [...this._records.entries()].sort((a, b) => a[1].startedAt - b[1].startedAt).slice(0, 1_000);
    oldest.forEach(([k]) => this._records.delete(k));
  }

  _todayKey()     { return this._dateKey(new Date()); }
  _dateKey(d)     { return d.toISOString().slice(0, 10); }
}

export const analyticsService = new AnalyticsService();