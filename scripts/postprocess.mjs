/**
 * Post-process a finished Shannon run (GitHub): gate math, step outputs, a PR-comment
 * body, and a job summary. No SARIF is generated - Shannon emits report.sarif natively.
 *
 * Usage: node postprocess.mjs <runDir> <failOn>
 */
import fs from 'node:fs';
import path from 'node:path';

const [runDir, failOnRaw = 'none'] = process.argv.slice(2);
const failOn = String(failOnRaw).toLowerCase();

const RANK = { info: 0, informational: 0, none: 0, low: 1, medium: 2, moderate: 2, high: 3, critical: 4 };
const threshold = failOn === 'none' ? Infinity : (RANK[failOn] ?? Infinity);
const ORDER = ['critical', 'high', 'medium', 'low', 'info'];

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
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${key}=${value}\n`);
}
function setMultiline(key, value) {
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `${key}<<SHANNON_EOF\n${value}\nSHANNON_EOF\n`);
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

// Findings. With -f, reaching here means the scan ran, but a scan cut off by a job timeout can
// still leave a partial report.json with an empty findings array. That must never read as a pass.
const reportJsonPath = findFile(runDir, 'report.json');
let findings = [];
let meta = {};
if (reportJsonPath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(reportJsonPath, 'utf8'));
    findings = Array.isArray(parsed.findings) ? parsed.findings : [];
    meta = parsed.report_meta || {};
  } catch {
    // leave empty
  }
}

// Completeness check. If exploit candidates were queued but the report has zero findings, the
// exploitation or reporting phase did not finish (typically a timeout): the report is incomplete
// and the run must fail rather than be reported as clean.
const queued = countQueuedExploits(runDir);
let incomplete = false;
let incompleteReason = '';
if (!reportJsonPath) {
  incomplete = true;
  incompleteReason = 'no report.json was produced (the scan did not reach the reporting phase)';
} else if (queued > 0 && findings.length === 0) {
  incomplete = true;
  incompleteReason = `${queued} exploit candidate(s) were queued but the report has 0 findings, so the scan was cut off before it finished`;
}
const result = incomplete ? 'failed' : 'completed';

const counts = Object.fromEntries(ORDER.map((s) => [s, 0]));
let blocking = 0;
let highest = 'none';
for (const f of findings) {
  const sev = String(f.severity || 'info').toLowerCase();
  if (sev in counts) counts[sev]++;
  const rank = RANK[sev] ?? -1;
  if (rank >= threshold) blocking++;
  if (rank > (RANK[highest] ?? -1)) highest = sev;
}

// Human summary (shared by the job summary and the optional PR comment)
const badge = blocking > 0 ? `${blocking} blocking` : 'passed';
let md = `<!-- shannon-action -->\n## Shannon AI Pentest - ${badge}\n\n`;
md += `**Target:** ${meta.target || '(unknown)'} | **Findings:** ${findings.length} | **Highest:** ${highest}\n\n`;
md += `| Critical | High | Medium | Low | Info |\n|:-:|:-:|:-:|:-:|:-:|\n| ${counts.critical} | ${counts.high} | ${counts.medium} | ${counts.low} | ${counts.info} |\n\n`;
if (findings.length) {
  const top = [...findings]
    .sort((a, b) => (RANK[String(b.severity).toLowerCase()] ?? -1) - (RANK[String(a.severity).toLowerCase()] ?? -1))
    .slice(0, 20);
  md += `<details><summary>Top findings (${Math.min(findings.length, 20)} of ${findings.length})</summary>\n\n`;
  md += `| Severity | ID | Title | Location |\n|---|---|---|---|\n`;
  for (const f of top) {
    const esc = (s) => String(s || '').replace(/\|/g, '\\|');
    md += `| ${esc(f.severity)} | ${esc(f.finding_id)} | ${esc(f.title)} | ${esc(httpLocationText(f))} |\n`;
  }
  md += `\n</details>\n`;
}
md += `\n_Full report is in the run artifact._\n`;

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
