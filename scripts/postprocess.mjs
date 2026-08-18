/**
 * Post-process a finished Shannon run:
 *   - determine pass/fail from workflow.log
 *   - read the structured findings from report.json
 *   - emit a SARIF 2.1.0 file for GitHub code scanning
 *   - write a job-summary table and a PR-comment body
 *   - set step outputs (result, findings-count, blocking-count, highest-severity, paths)
 *
 * This never exits non-zero — the action's "Enforce gate" step owns failing the build,
 * so that SARIF/artifact uploads still run when there are blocking findings.
 *
 * Usage: node postprocess.mjs <runDir> <failOn> <sarifOut>
 */
import fs from 'node:fs';
import path from 'node:path';

const [runDir, failOnRaw = 'none', sarifOut] = process.argv.slice(2);
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

function sarifLevel(sev) {
  const r = RANK[sev] ?? 0;
  if (r >= 3) return 'error';
  if (r === 2) return 'warning';
  return 'note';
}

// GitHub sorts code-scanning alerts by this numeric property.
function securitySeverity(sev) {
  return { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.5' }[sev] ?? '0.0';
}

function httpLocationText(f) {
  if (f.http_location) {
    const { method = '', url = '', parameter } = f.http_location;
    return `${method} ${url}${parameter ? ` (param: ${parameter})` : ''}`.trim();
  }
  return f.vulnerable_location || '';
}

// 1. Outcome from the run log
const log = findFile(runDir, 'workflow.log');
const logText = log ? fs.readFileSync(log, 'utf8') : '';
const result = /^Scan COMPLETED$/m.test(logText) && !/^Scan FAILED$/m.test(logText) ? 'completed' : 'failed';

// 2. Structured findings
const reportJsonPath = findFile(runDir, 'report.json');
const humanReport = findFile(runDir, 'Security-Assessment-Report.md');
let findings = [];
let meta = {};
if (reportJsonPath) {
  try {
    const parsed = JSON.parse(fs.readFileSync(reportJsonPath, 'utf8'));
    findings = Array.isArray(parsed.findings) ? parsed.findings : [];
    meta = parsed.report_meta || {};
  } catch {
    // leave findings empty
  }
}

// 3. Counts / gate math
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

// 4. SARIF
const rules = new Map();
const results = [];
for (const f of findings) {
  const sev = String(f.severity || 'info').toLowerCase();
  const ruleId = f.finding_id || f.category || 'shannon-finding';
  if (!rules.has(ruleId)) {
    rules.set(ruleId, {
      id: ruleId,
      name: String(f.category || 'Finding').replace(/\s+/g, ''),
      shortDescription: { text: f.title || ruleId },
      fullDescription: { text: String(f.overview || f.title || '').slice(0, 1000) },
      helpUri: 'https://github.com/KeygraphHQ/shannon',
      properties: {
        'security-severity': securitySeverity(sev),
        tags: ['security', f.category].filter(Boolean),
      },
    });
  }
  const httpText = httpLocationText(f);
  const entry = {
    ruleId,
    level: sarifLevel(sev),
    message: { text: `${f.title || ruleId}${httpText ? ` — ${httpText}` : ''}` },
  };
  const loc = Array.isArray(f.code_locations) ? f.code_locations.find((c) => c && c.file) : undefined;
  if (loc) {
    const startLine = Math.max(1, parseInt(loc.start_line ?? loc.line ?? 1, 10) || 1);
    entry.locations = [
      {
        physicalLocation: {
          artifactLocation: { uri: String(loc.file).replace(/^\.?\//, '') },
          region: { startLine },
        },
      },
    ];
  }
  results.push(entry);
}
const sarif = {
  $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
  version: '2.1.0',
  runs: [
    {
      tool: {
        driver: {
          name: 'Shannon',
          informationUri: 'https://github.com/KeygraphHQ/shannon',
          rules: [...rules.values()],
        },
      },
      results,
    },
  ],
};
let sarifWritten = '';
if (sarifOut) {
  fs.writeFileSync(sarifOut, JSON.stringify(sarif, null, 2));
  sarifWritten = sarifOut;
}

// 5. Human summary (job summary + PR comment body share the same markdown)
const badge = result === 'failed' ? '❌ scan failed' : blocking > 0 ? `⛔ ${blocking} blocking` : '✅ passed';
let md = `<!-- shannon-action -->\n## 🛡️ Shannon AI Pentest — ${badge}\n\n`;
md += `**Target:** ${meta.target || '(unknown)'}  •  **Result:** ${result}  •  **Findings:** ${findings.length}  •  **Highest:** ${highest}\n\n`;
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
md += `\n_Full report is attached as a run artifact._\n`;

if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md);
if (process.env.RUNNER_TEMP) fs.writeFileSync(path.join(process.env.RUNNER_TEMP, 'shannon-comment.md'), md);

// 6. Inline annotations for blocking findings
for (const f of findings) {
  const sev = String(f.severity || 'info').toLowerCase();
  if ((RANK[sev] ?? -1) >= threshold) {
    console.log(`::error::[${sev}] ${f.finding_id || ''} ${f.title || ''}`);
  }
}

// 7. Outputs
setOutput('result', result);
setOutput('findings-count', String(findings.length));
setOutput('blocking-count', String(blocking));
setOutput('highest-severity', highest);
setOutput('report-path', humanReport || '');
setOutput('report-json', reportJsonPath || '');
setOutput('sarif-path', sarifWritten);

console.log(`result=${result} findings=${findings.length} blocking(>=${failOn})=${blocking} highest=${highest}`);
