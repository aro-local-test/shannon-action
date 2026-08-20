/**
 * Post-process a finished Shannon run (GitHub): gate math, step outputs, a PR-comment
 * body, and a job summary. No SARIF is generated - Shannon emits report.sarif natively.
 *
 * Usage: node postprocess.mjs <runDir> <failOn>
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const [runDir, failOnRaw = 'none'] = process.argv.slice(2);
const failOn = String(failOnRaw).trim().toLowerCase();

const RANK = { none: 0, info: 0, informational: 0, low: 1, medium: 2, moderate: 2, high: 3, critical: 4 };
const ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// Fail loud on an unknown fail-on rather than silently disabling the gate. A typo or a stray space
// would otherwise make the threshold Infinity, so nothing counts as blocking and the gate passes.
if (!(failOn in RANK)) {
  console.log(`::error::Invalid fail-on value '${failOnRaw}'. Use one of: none, info, low, medium, high, critical.`);
  process.exit(1);
}
const threshold = failOn === 'none' ? Infinity : RANK[failOn];

// Collapse severity synonyms to canonical buckets so the counts table and the gate agree.
function canonicalSeverity(raw) {
  const s = String(raw || 'info').trim().toLowerCase();
  if (s === 'moderate') return 'medium';
  if (s === 'informational' || s === 'none' || s === '') return 'info';
  return s;
}

// Strip characters that would break the markdown table or the GITHUB_OUTPUT block. Finding fields
// are model output derived from the scanned target, so they are untrusted here.
function clean(value) {
  return String(value ?? '')
    .replace(/[\r\n]+/g, ' ')
    .replace(/\|/g, '\\|');
}

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
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${String(value).replace(/[\r\n]/g, ' ')}\n`);
  }
}

function setMultiline(key, value) {
  if (!process.env.GITHUB_OUTPUT) return;
  // Random, unguessable delimiter so finding content cannot forge a delimiter line and inject
  // further outputs (which, with last-write-wins, could override the gate values).
  const delim = `SHANNON_EOF_${crypto.randomBytes(16).toString('hex')}`;
  const safe = String(value)
    .split('\n')
    .filter((line) => line.trim() !== delim)
    .join('\n');
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `${key}<<${delim}\n${safe}\n${delim}\n`);
}

function httpLocationText(f) {
  if (f.http_location) {
    const { method = '', url = '', parameter } = f.http_location;
    return `${method} ${url}${parameter ? ` (param: ${parameter})` : ''}`.trim();
  }
  return f.vulnerable_location || '';
}

// Count exploit candidates the vulnerability agents queued for the exploitation phase.
function countQueuedExploits(root) {
  if (!root || !fs.existsSync(root)) return 0;
  let total = 0;
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
      if (e.isDirectory()) {
        stack.push(p);
      } else if (/_exploitation_queue\.json$/.test(e.name)) {
        try {
          const data = JSON.parse(fs.readFileSync(p, 'utf8'));
          const list = Array.isArray(data) ? data : data.vulnerabilities || data.queue || [];
          if (Array.isArray(list)) total += list.length;
        } catch {
          // ignore unparseable queue files
        }
      }
    }
  }
  return total;
}

// Findings. A report.json that is missing or corrupt must never read as a clean pass.
const reportJsonPath = findFile(runDir, 'report.json');
let findings = [];
let meta = {};
let parseFailed = false;
if (reportJsonPath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(reportJsonPath, 'utf8'));
    findings = Array.isArray(parsed.findings) ? parsed.findings : [];
    meta = parsed.report_meta || {};
  } catch {
    parseFailed = true;
  }
}

const queued = countQueuedExploits(runDir);
let incomplete = false;
let incompleteReason = '';
if (!reportJsonPath) {
  incomplete = true;
  incompleteReason = 'no report.json was produced (the scan did not reach the reporting phase)';
} else if (parseFailed) {
  incomplete = true;
  incompleteReason = 'report.json was produced but is corrupt or unparseable';
}
// Queued candidates with zero confirmed findings is NOT incomplete: a hardened target legitimately
// produces exploit candidates that all get dropped as non-exploitable. A genuinely cut-off scan is
// caught by the action gate's `steps.scan.outcome != success` check and by the checks above.
const result = incomplete ? 'failed' : 'completed';

const counts = Object.fromEntries(ORDER.map((s) => [s, 0]));
let blocking = 0;
let highest = 'none';
for (const f of findings) {
  const sev = canonicalSeverity(f.severity);
  if (sev in counts) counts[sev]++;
  const rank = RANK[sev] ?? -1;
  if (rank >= threshold) blocking++;
  if (rank > (RANK[highest] ?? -1)) highest = sev;
}

// Human summary (shared by the job summary and the optional PR comment)
const badge = blocking > 0 ? `${blocking} blocking` : 'passed';
let md = `<!-- shannon-action -->\n## Shannon AI Pentest - ${badge}\n\n`;
md += `**Target:** ${clean(meta.target) || '(unknown)'} | **Findings:** ${findings.length} | **Highest:** ${highest}\n\n`;
md += `| Critical | High | Medium | Low | Info |\n|:-:|:-:|:-:|:-:|:-:|\n| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |\n\n`;
if (findings.length) {
  const top = [...findings]
    .sort((a, b) => (RANK[canonicalSeverity(b.severity)] ?? -1) - (RANK[canonicalSeverity(a.severity)] ?? -1))
    .slice(0, 20);
  md += `<details><summary>Top findings (${Math.min(findings.length, 20)} of ${findings.length})</summary>\n\n`;
  md += `| Severity | ID | Title | Location |\n|---|---|---|---|\n`;
  for (const f of top) {
    md += `| ${clean(f.severity)} | ${clean(f.finding_id)} | ${clean(f.title)} | ${clean(httpLocationText(f))} |\n`;
  }
  md += `\n</details>\n`;
}
md += `\n_Full report is in the run artifacts._\n`;

if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);

setOutput('result', result);
setOutput('findings-count', String(findings.length));
setOutput('blocking-count', String(blocking));
setOutput('highest-severity', highest);
setOutput('scan-complete', incomplete ? 'false' : 'true');
setMultiline('comment', md);

if (incomplete) {
  console.log(`::error::Shannon scan is incomplete: ${incompleteReason}.`);
}
console.log(
  `result=${result} scan-complete=${!incomplete} findings=${findings.length} queued=${queued} blocking(>=${failOn})=${blocking} highest=${highest}`,
);
