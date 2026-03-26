/**
 * Simple rate limiter using in-memory store.
 * In production, replace with Upstash Redis for persistence across serverless invocations.
 *
 * Tier limits:
 * - free: 10 scans/day, deterministic only (no AI)
 * - pro: 500 scans/day, 50 deep scans/month
 * - ultra: 2000 scans/day, 300 deep scans/month
 */

const TIERS = {
  free: { dailyScans: 10, monthlyDeepScans: 0 },
  pro: { dailyScans: 500, monthlyDeepScans: 50 },
  ultra: { dailyScans: 2000, monthlyDeepScans: 300 },
};

// In-memory store (resets on cold start — fine for MVP, use Redis later)
const usage = new Map();

function getKey(apiKey, period) {
  const now = new Date();
  const dateStr = period === 'daily'
    ? now.toISOString().slice(0, 10)
    : now.toISOString().slice(0, 7);
  return `${apiKey}:${period}:${dateStr}`;
}

export function checkRateLimit(apiKey, tier = 'free', isDeepScan = false) {
  const limits = TIERS[tier] || TIERS.free;

  // Check daily scan limit
  const dailyKey = getKey(apiKey, 'daily');
  const dailyCount = usage.get(dailyKey) || 0;
  if (dailyCount >= limits.dailyScans) {
    return { allowed: false, reason: `Daily scan limit reached (${limits.dailyScans}). Upgrade for more.` };
  }

  // Check monthly deep scan limit
  if (isDeepScan) {
    if (limits.monthlyDeepScans === 0) {
      return { allowed: false, reason: 'Deep scans (AI-powered) require Pro or Ultra plan.' };
    }
    const monthlyKey = getKey(apiKey, 'monthly');
    const monthlyCount = usage.get(monthlyKey) || 0;
    if (monthlyCount >= limits.monthlyDeepScans) {
      return { allowed: false, reason: `Monthly deep scan limit reached (${limits.monthlyDeepScans}). Upgrade for more.` };
    }
  }

  return { allowed: true };
}

export function recordUsage(apiKey, isDeepScan = false) {
  const dailyKey = getKey(apiKey, 'daily');
  usage.set(dailyKey, (usage.get(dailyKey) || 0) + 1);

  if (isDeepScan) {
    const monthlyKey = getKey(apiKey, 'monthly');
    usage.set(monthlyKey, (usage.get(monthlyKey) || 0) + 1);
  }
}

export function getUsage(apiKey) {
  const dailyKey = getKey(apiKey, 'daily');
  const monthlyKey = getKey(apiKey, 'monthly');
  return {
    dailyScans: usage.get(dailyKey) || 0,
    monthlyDeepScans: usage.get(monthlyKey) || 0,
  };
}
