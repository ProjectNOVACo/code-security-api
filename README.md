# Code Security Scanner API

AI-powered code security scanner. Find vulnerabilities, map compliance controls, and get actionable fixes — via API.

## Quick Start

```bash
curl -X POST https://your-url.vercel.app/api/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{
    "code": "password = \"admin123\"",
    "filename": "config.py"
  }'
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | Scan code for vulnerabilities |
| `GET` | `/api/health` | Health check + API info |
| `GET` | `/api/patterns` | List all 30+ detection patterns |

## Scan Request

```json
{
  "code": "your code here",
  "filename": "app.py",
  "deep": false
}
```

- `code` (required) — The code to scan (max 50KB)
- `filename` (optional) — Helps detect language for language-specific patterns
- `deep` (optional) — Enable AI-powered deep analysis (Pro/Ultra only)

## Scan Response

```json
{
  "score": 55,
  "grade": "D",
  "findings": [
    {
      "name": "Hardcoded Password",
      "line": 3,
      "snippet": "password = \"admin123\"",
      "severity": "high",
      "category": "hardcoded_secret",
      "message": "Possible hardcoded password. Use a secrets manager.",
      "confidence": 0.9,
      "compliance": {
        "soc2": "CC6.1",
        "gdpr": "Art.32",
        "pci": "2.1",
        "owasp": "A07:2021"
      }
    }
  ],
  "compliance": {
    "owasp": ["A07:2021"],
    "soc2": ["CC6.1"],
    "pci": ["2.1"]
  },
  "stats": {
    "scan_type": "quick",
    "patterns_checked": 30,
    "findings_reported": 1,
    "scan_time_ms": 12
  }
}
```

## Pricing

| Plan | Scans/Day | Deep Scans/Mo | Price |
|------|-----------|---------------|-------|
| Free | 10 | 0 | $0 |
| Pro | 500 | 50 | $29/mo |
| Ultra | 2,000 | 300 | $99/mo |

## What It Detects

30+ vulnerability patterns across 12 categories:
- Hardcoded secrets (AWS keys, API keys, passwords, JWT tokens, connection strings)
- SQL injection (f-strings, concatenation, template literals, .format)
- Command injection (exec, os.system, subprocess, eval)
- XSS (innerHTML, dangerouslySetInnerHTML, document.write)
- Path traversal
- Weak cryptography (MD5, SHA-1, Math.random)
- JWT misconfig (algorithm none, verify disabled)
- CORS wildcard
- SSRF
- Insecure deserialization (pickle, yaml.load)
- Open redirects

## Compliance Mapping

Every finding maps to: **OWASP Top 10**, **SOC2**, **GDPR**, **PCI-DSS**

## License

MIT — Project NOVA Co LLC
