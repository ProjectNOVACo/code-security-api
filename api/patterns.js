/**
 * GET /api/patterns — List all detection patterns (public, no auth required)
 */
import { PATTERNS, COMPLIANCE_MAP } from '../lib/patterns.js';

export default function handler(req, res) {
  const patterns = PATTERNS.map(p => ({
    id: p.id,
    name: p.name,
    severity: p.severity,
    category: p.category,
    languages: p.languages || 'all',
    compliance: COMPLIANCE_MAP[p.category] || {},
  }));

  res.status(200).json({
    total: patterns.length,
    patterns,
    categories: [...new Set(patterns.map(p => p.category))],
  });
}
