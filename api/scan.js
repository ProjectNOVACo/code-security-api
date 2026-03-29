/**
 * POST /api/scan — Main security scan endpoint
 *
 * Body: { code: string, filename?: string, deep?: boolean }
 * Headers: X-API-Key or X-RapidAPI-Key
 *
 * Returns: { score, findings[], stats, compliance }
 */

import { scanCode, COMPLIANCE_MAP } from '../lib/patterns.js';
import { deepScan } from '../lib/claude-scan.js';
import { checkRateLimit, recordUsage } from '../lib/rate-limit.js';

const CONFIDENCE_THRESHOLDS = { critical: 0.6, high: 0.7, medium: 0.8, low: 0.85 };
const MAX_CODE_LENGTH = 50000; // 50KB max per scan
const MAX_FINDINGS = 10;

function getApiKey(req) {
  return req.headers['x-rapidapi-key']
    || req.headers['x-api-key']
    || req.query?.api_key
    || null;
}

function getTier(req) {
  // RapidAPI sends subscription info in headers
  const sub = req.headers['x-rapidapi-subscription'];
  if (sub === 'ULTRA' || sub === 'MEGA') return 'ultra';
  if (sub === 'PRO') return 'pro';
  return 'free';
}

function calculateScore(findings) {
  if (findings.length === 0) return 100;
  let penalty = 0;
  for (const f of findings) {
    if (f.severity === 'critical') penalty += 30;
    else if (f.severity === 'high') penalty += 20;
    else if (f.severity === 'medium') penalty += 10;
    else penalty += 5;
  }
  return Math.max(0, 100 - penalty);
}

export default async function handler(req, res) {
  // CORS preflight
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  const apiKey = getApiKey(req);
  if (!apiKey) return res.status(401).json({ error: 'API key required. Set X-API-Key or X-RapidAPI-Key header.' });

  let { code, filename, language, deep = false } = req.body || {};

  // If language provided but no filename, create a filename with the right extension
  if (language && !filename) {
    const langToExt = { python: 'py', javascript: 'js', typescript: 'ts', ruby: 'rb', go: 'go', rust: 'rs', java: 'java', php: 'php', csharp: 'cs', swift: 'swift', shell: 'sh' };
    filename = `input.${langToExt[language.toLowerCase()] || 'js'}`;
  }
  filename = filename || 'input.js';

  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Missing "code" field. Send { "code": "your code here", "filename": "app.py" }' });
  }

  if (code.length > MAX_CODE_LENGTH) {
    return res.status(400).json({ error: `Code too large. Max ${MAX_CODE_LENGTH} characters.` });
  }

  // Rate limit check
  const tier = getTier(req);
  const rateCheck = checkRateLimit(apiKey, tier, deep);
  if (!rateCheck.allowed) {
    return res.status(429).json({ error: rateCheck.reason });
  }

  const startTime = Date.now();

  // === DETERMINISTIC SCAN (always runs) ===
  const deterministicFindings = scanCode(code, filename);

  // === DEEP SCAN (AI-powered, only if requested + allowed) ===
  let aiFindings = [];
  let aiError = null;
  let tokensUsed = null;

  if (deep) {
    const result = await deepScan(code, filename, deterministicFindings);
    aiFindings = result.findings || [];
    aiError = result.error || null;
    tokensUsed = result.tokens || null;
  }

  // === MERGE & VALIDATE ===
  const allFindings = [...deterministicFindings];

  // Add AI findings that aren't duplicates of deterministic ones
  for (const af of aiFindings) {
    const isDuplicate = deterministicFindings.some(
      df => df.line === af.line && df.category === af.category
    );
    if (!isDuplicate) {
      allFindings.push(af);
    } else {
      // Boost confidence of matching deterministic finding
      const match = allFindings.find(f => f.line === af.line && f.category === af.category);
      if (match) {
        match.confidence = Math.min(1.0, (match.confidence + (af.confidence || 0.8)) / 2 + 0.1);
        match.fix = af.fix || match.fix;
        match.source = 'confirmed';
      }
    }
  }

  // Filter by confidence threshold
  const verified = allFindings.filter(f =>
    f.confidence >= (CONFIDENCE_THRESHOLDS[f.severity] || 0.7)
  );

  // Sort by severity then confidence
  const severityOrder = ['critical', 'high', 'medium', 'low'];
  verified.sort((a, b) => {
    const sevDiff = severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
    return sevDiff !== 0 ? sevDiff : b.confidence - a.confidence;
  });

  // Cap findings
  const capped = verified.slice(0, MAX_FINDINGS);
  const score = calculateScore(capped);

  // Record usage
  recordUsage(apiKey, deep);

  // Collect unique compliance controls
  const complianceControls = {};
  for (const f of capped) {
    if (f.compliance) {
      for (const [standard, control] of Object.entries(f.compliance)) {
        if (!complianceControls[standard]) complianceControls[standard] = new Set();
        complianceControls[standard].add(control);
      }
    }
  }
  // Convert sets to arrays for JSON
  for (const key of Object.keys(complianceControls)) {
    complianceControls[key] = [...complianceControls[key]];
  }

  const elapsed = Date.now() - startTime;

  return res.status(200).json({
    score,
    grade: score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F',
    findings: capped,
    compliance: complianceControls,
    stats: {
      scan_type: deep ? 'deep' : 'quick',
      patterns_checked: 30,
      findings_total: allFindings.length,
      findings_verified: verified.length,
      findings_reported: capped.length,
      findings_omitted: verified.length - capped.length,
      scan_time_ms: elapsed,
      ...(tokensUsed ? { ai_tokens: tokensUsed } : {}),
    },
    ...(aiError ? { ai_warning: `AI analysis incomplete: ${aiError}` } : {}),
  });
}
