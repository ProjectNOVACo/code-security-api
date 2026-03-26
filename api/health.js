/**
 * GET /api/health — Health check + API info
 */
export default function handler(req, res) {
  res.status(200).json({
    status: 'ok',
    service: 'Code Security Scanner API',
    version: '1.0.0',
    endpoints: {
      'POST /api/scan': 'Scan code for security vulnerabilities',
      'GET /api/health': 'Health check and API info',
      'GET /api/patterns': 'List all detection patterns',
    },
    tiers: {
      free: { daily_scans: 10, deep_scans: 0, price: '$0' },
      pro: { daily_scans: 500, deep_scans: '50/month', price: '$29/month' },
      ultra: { daily_scans: 2000, deep_scans: '300/month', price: '$99/month' },
    },
    supported_languages: [
      'JavaScript', 'TypeScript', 'Python', 'Ruby', 'Go', 'Rust',
      'Java', 'PHP', 'C#', 'Swift', 'Shell', 'SQL',
    ],
    compliance_frameworks: ['OWASP Top 10', 'SOC2', 'GDPR', 'PCI-DSS'],
  });
}
