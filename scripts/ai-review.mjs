/**
 * Generate a short AI review verdict for a finished Shannon run and expose it as the
 * `comment` step output for the PR comment. Reads report.json, asks the configured AI model
 * for a concise verdict, and falls back to a deterministic sentence when the model is not
 * reachable or the provider is not supported.
 *
 * Output is plain text with no emojis and no em dashes, by design.
 *
 * Usage: node ai-review.mjs <runDir>
 */
import fs from 'node:fs';
import path from 'node:path';

const runDir = process.argv[2];
const MARKER = '<!-- shannon-action -->';
const RANK = { info: 0, informational: 0, none: 0, low: 1, medium: 2, moderate: 2, high: 3, critical: 4 };

function findFile(root, name) {
  if (!root || !fs.existsSync(root)) return undefined;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) stack.push(p);
      else if (e.name === name) return p;
    }
  }
  return undefined;
}

function setOutput(key, value) {
  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${key}<<SHANNON_EOF\n${value}\nSHANNON_EOF\n`);
  }
}

function summarize(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let highest = 'none';
  for (const f of findings) {
    const s = String(f.severity || 'info').toLowerCase();
    if (s in c) c[s]++;
    if ((RANK[s] ?? -1) > (RANK[highest] ?? -1)) highest = s;
  }
  return { c, highest };
}

async function anthropicVerdict(apiKey, modelId, findings, target) {
  const list = findings
    .slice(0, 25)
    .map((f) => {
      const loc = f.http_location ? ` (${f.http_location.method || ''} ${f.http_location.url || ''})` : '';
      return `- [${f.severity}] ${f.title}${loc}`;
    })
    .join('\n');
  const prompt =
    'You are Shannon, an autonomous AI penetration tester leaving a short review on a pull request.\n' +
    `Target: ${target}\n` +
    `Findings:\n${list || '(none confirmed)'}\n\n` +
    'Write a 1 to 2 sentence verdict for the pull request. Be direct and professional. ' +
    'State the overall risk and the single most important action to take. ' +
    'Plain text only: no markdown headings, no bullet lists, no emojis, no em dashes.';
  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({ model: modelId, max_tokens: 300, messages: [{ role: 'user', content: prompt }] }),
  });
  if (!res.ok) throw new Error(`anthropic ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const data = await res.json();
  const text = (data.content || []).map((b) => b.text || '').join('').trim();
  if (!text) throw new Error('empty model response');
  return text;
}

function deterministicVerdict(summary, n) {
  if (n === 0) {
    return 'Shannon completed the scan and did not confirm any exploitable vulnerabilities on this target.';
  }
  return (
    `Shannon confirmed ${n} exploitable finding(s), highest severity ${summary.highest} ` +
    `(${summary.c.critical} critical, ${summary.c.high} high). ` +
    'Address the critical and high issues before release.'
  );
}

async function main() {
  const reportPath = findFile(runDir, 'report.json');
  let findings = [];
  let target = '(unknown)';
  if (reportPath) {
    try {
      const parsed = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
      findings = Array.isArray(parsed.findings) ? parsed.findings : [];
      target = (parsed.report_meta && parsed.report_meta.target) || target;
    } catch {
      // leave defaults
    }
  }
  const summary = summarize(findings);
  const n = findings.length;

  const spec = String(process.env.SHANNON_AI_MODEL || '').trim();
  const provider = spec.includes(':') ? spec.slice(0, spec.indexOf(':')) : spec || 'anthropic';
  const modelId = spec.includes(':') ? spec.slice(spec.indexOf(':') + 1) : 'claude-sonnet-4-6';
  const apiKey = process.env.SHANNON_AI_API_KEY || '';

  let verdict;
  try {
    if (provider === 'anthropic' && apiKey) {
      verdict = await anthropicVerdict(apiKey, modelId, findings, target);
    } else {
      // The AI review currently supports Anthropic. Other providers fall back to a
      // deterministic verdict so the comment is still posted.
      verdict = deterministicVerdict(summary, n);
    }
  } catch (err) {
    console.log(`AI review unavailable, using deterministic verdict: ${err.message}`);
    verdict = deterministicVerdict(summary, n);
  }

  const footer =
    `Findings: ${n} (${summary.c.critical} critical, ${summary.c.high} high, ${summary.c.medium} medium). ` +
    'Full report in the run artifacts.';
  const body = `${MARKER}\n**Shannon AI Pentest**\n\n${verdict}\n\n${footer}`;
  setOutput('comment', body);
  console.log(`AI review generated via ${provider}:${modelId} for ${n} finding(s).`);
}

main();
