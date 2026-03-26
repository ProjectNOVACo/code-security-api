/**
 * Claude deep scan — AI-powered contextual security analysis.
 * Only called when deterministic scan finds issues OR code is high-risk.
 */

import Anthropic from '@anthropic-ai/sdk';
import { COMPLIANCE_MAP, detectLanguage } from './patterns.js';

const SYSTEM_PROMPT = `You are a senior application security engineer. Analyze code for security vulnerabilities.

RULES:
1. Only report REAL vulnerabilities with HIGH confidence. No speculation.
2. Each finding MUST reference an exact line number and code snippet.
3. If code is safe (parameterized queries, sanitized input), do NOT flag it.
4. Consider full context — a vulnerability in isolation might be mitigated elsewhere.
5. Map findings to compliance controls (SOC2, GDPR, PCI-DSS, OWASP).
6. Provide concrete, actionable fixes.

OUTPUT: Return a JSON array. Each finding:
{
  "name": "Short name",
  "line": 42,
  "snippet": "the vulnerable code",
  "severity": "critical|high|medium|low",
  "category": "category_key",
  "message": "What's wrong and why",
  "fix": "Concrete code fix",
  "confidence": 0.0-1.0,
  "compliance": { "soc2": "...", "pci": "...", "owasp": "..." }
}

If code is CLEAN, return: []
Do NOT invent findings. False positives erode trust.`;

export async function deepScan(code, filename, deterministicFindings = []) {
  const client = new Anthropic();
  const lang = detectLanguage(filename) || 'unknown';

  let prompt = `## Code Security Review\n\n`;
  prompt += `**File:** ${filename}\n**Language:** ${lang}\n\n`;

  if (deterministicFindings.length > 0) {
    prompt += `### Pattern Scanner Results (verify these)\n`;
    for (const f of deterministicFindings) {
      prompt += `- **${f.name}** at line ${f.line}: \`${f.snippet}\`\n`;
    }
    prompt += `\n`;
  }

  prompt += `### Code\n\`\`\`${lang}\n`;
  const lines = code.split('\n');
  for (let i = 0; i < lines.length; i++) {
    prompt += `${i + 1}: ${lines[i]}\n`;
  }
  prompt += `\`\`\`\n\nAnalyze for security vulnerabilities. Return JSON array only.`;

  try {
    const response = await Promise.race([
      client.messages.create({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 4096,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: prompt }],
      }),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 25000)),
    ]);

    const text = response.content[0]?.text || '[]';
    const jsonMatch = text.match(/\[[\s\S]*\]/);
    if (!jsonMatch) return { findings: [], tokens: response.usage };

    const findings = JSON.parse(jsonMatch[0]);
    return {
      findings: findings.map(f => ({
        ...f,
        file: filename,
        compliance: f.compliance || COMPLIANCE_MAP[f.category] || {},
        source: 'ai',
      })),
      tokens: response.usage,
    };
  } catch (err) {
    return { findings: [], error: err.message, tokens: null };
  }
}
