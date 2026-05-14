#!/usr/bin/env node

/**
 * merge-security-reports.js
 * Merges Semgrep JSON output and CodeQL SARIF output into a single Markdown report.
 * Usage: node scripts/merge-security-reports.js
 */

const fs = require("fs");
const path = require("path");

const SEMGREP_PATH = path.join(process.cwd(), "semgrep-results.json");
const CODEQL_DIR = path.join(process.cwd(), "codeql-sarif");
const OUTPUT_PATH = path.join(process.cwd(), "security-report.md");

// ─── Severity helpers ────────────────────────────────────────────────────────

const SEVERITY_EMOJI = {
  ERROR: "🔴",
  WARNING: "🟡",
  INFO: "🔵",
  error: "🔴",
  warning: "🟡",
  note: "🔵",
  none: "⚪",
};

function severityEmoji(level) {
  return SEVERITY_EMOJI[level] || "⚪";
}

// ─── Parse Semgrep results ───────────────────────────────────────────────────

function parseSemgrep() {
  if (!fs.existsSync(SEMGREP_PATH)) {
    console.warn("⚠️  semgrep-results.json not found, skipping Semgrep section.");
    return [];
  }

  const raw = JSON.parse(fs.readFileSync(SEMGREP_PATH, "utf8"));
  const results = raw.results || [];

  return results.map((r) => ({
    tool: "Semgrep",
    ruleId: r.check_id || "unknown",
    severity: r.extra?.severity || "WARNING",
    file: r.path || "unknown",
    line: r.start?.line || 0,
    message: r.extra?.message || "No message",
  }));
}

// ─── Parse CodeQL SARIF results ──────────────────────────────────────────────

function parseCodeQL() {
  if (!fs.existsSync(CODEQL_DIR)) {
    console.warn("⚠️  codeql-sarif directory not found, skipping CodeQL section.");
    return [];
  }

  const sarifFiles = fs
    .readdirSync(CODEQL_DIR)
    .filter((f) => f.endsWith(".sarif"));

  if (sarifFiles.length === 0) {
    console.warn("⚠️  No SARIF files found in codeql-sarif/, skipping CodeQL section.");
    return [];
  }

  const findings = [];

  for (const file of sarifFiles) {
    const raw = JSON.parse(
      fs.readFileSync(path.join(CODEQL_DIR, file), "utf8")
    );

    for (const run of raw.runs || []) {
      // Build a ruleId → severity map from the rules array
      const ruleMap = {};
      for (const rule of run.tool?.driver?.rules || []) {
        ruleMap[rule.id] = {
          name: rule.name || rule.id,
          severity:
            rule.defaultConfiguration?.level ||
            rule.properties?.["problem.severity"] ||
            "warning",
        };
      }

      for (const result of run.results || []) {
        const loc =
          result.locations?.[0]?.physicalLocation;
        const ruleInfo = ruleMap[result.ruleId] || {};

        findings.push({
          tool: "CodeQL",
          ruleId: result.ruleId || "unknown",
          severity: result.level || ruleInfo.severity || "warning",
          file:
            loc?.artifactLocation?.uri || "unknown",
          line: loc?.region?.startLine || 0,
          message: result.message?.text || "No message",
        });
      }
    }
  }

  return findings;
}

// ─── Group findings by severity ──────────────────────────────────────────────

function groupBySeverity(findings) {
  const groups = { ERROR: [], error: [], WARNING: [], warning: [], INFO: [], note: [], none: [] };
  for (const f of findings) {
    const key = f.severity;
    if (!groups[key]) groups[key] = [];
    groups[key].push(f);
  }

  // Normalize to uppercase buckets
  return {
    HIGH: [...(groups.ERROR || []), ...(groups.error || [])],
    MEDIUM: [...(groups.WARNING || []), ...(groups.warning || [])],
    LOW: [
      ...(groups.INFO || []),
      ...(groups.note || []),
      ...(groups.none || []),
    ],
  };
}

// ─── Build Markdown report ───────────────────────────────────────────────────

function buildMarkdown(semgrepFindings, codeqlFindings) {
  const allFindings = [...semgrepFindings, ...codeqlFindings];
  const grouped = groupBySeverity(allFindings);

  const semgrepCount = semgrepFindings.length;
  const codeqlCount = codeqlFindings.length;
  const totalCount = allFindings.length;

  const highCount = grouped.HIGH.length;
  const mediumCount = grouped.MEDIUM.length;
  const lowCount = grouped.LOW.length;

  const now = new Date().toUTCString();

  let md = `# 🔐 Joplin Plugin Security Report\n\n`;
  md += `> Generated: ${now}\n\n`;
  md += `---\n\n`;

  // Summary table
  md += `## Summary\n\n`;
  md += `| | Count |\n`;
  md += `|---|---|\n`;
  md += `| 🔴 High Severity | ${highCount} |\n`;
  md += `| 🟡 Medium Severity | ${mediumCount} |\n`;
  md += `| 🔵 Low Severity | ${lowCount} |\n`;
  md += `| **Total Findings** | **${totalCount}** |\n\n`;

  md += `| Tool | Findings |\n`;
  md += `|---|---|\n`;
  md += `| Semgrep (Custom Joplin Rules) | ${semgrepCount} |\n`;
  md += `| CodeQL | ${codeqlCount} |\n\n`;

  // Overall verdict
  if (totalCount === 0) {
    md += `## ✅ Result: CLEAN\n\nNo issues detected by either scanner.\n\n`;
  } else if (highCount > 0) {
    md += `## 🔴 Result: REVIEW REQUIRED\n\n${highCount} high severity finding(s) require maintainer attention before approval.\n\n`;
  } else if (mediumCount > 0) {
    md += `## 🟡 Result: REVIEW RECOMMENDED\n\nNo high severity findings, but ${mediumCount} medium severity finding(s) should be reviewed.\n\n`;
  } else {
    md += `## 🔵 Result: LOW RISK\n\nOnly low severity or informational findings. Likely safe to approve.\n\n`;
  }

  md += `---\n\n`;

  // Findings sections
  function renderFindings(label, findings) {
    if (findings.length === 0) return "";
    let s = `## ${label} (${findings.length})\n\n`;
    for (const f of findings) {
      s += `### ${severityEmoji(f.severity)} \`${f.ruleId}\`\n\n`;
      s += `- **Tool:** ${f.tool}\n`;
      s += `- **File:** \`${f.file}\` — Line ${f.line}\n`;
      s += `- **Message:** ${f.message}\n\n`;
    }
    return s;
  }

  md += renderFindings("🔴 High Severity Findings", grouped.HIGH);
  md += renderFindings("🟡 Medium Severity Findings", grouped.MEDIUM);
  md += renderFindings("🔵 Low Severity / Informational", grouped.LOW);

  md += `---\n\n`;
  md += `*This report is generated automatically. A human maintainer must make the final approval decision.*\n`;

  return md;
}

// ─── Main ────────────────────────────────────────────────────────────────────

function main() {
  console.log("📥 Parsing Semgrep results...");
  const semgrepFindings = parseSemgrep();
  console.log(`   Found ${semgrepFindings.length} Semgrep findings.`);

  console.log("📥 Parsing CodeQL SARIF results...");
  const codeqlFindings = parseCodeQL();
  console.log(`   Found ${codeqlFindings.length} CodeQL findings.`);

  console.log("📝 Generating combined report...");
  const report = buildMarkdown(semgrepFindings, codeqlFindings);

  fs.writeFileSync(OUTPUT_PATH, report, "utf8");
  console.log(`✅ Report written to: ${OUTPUT_PATH}`);

  // Also write to GitHub Actions Step Summary if available
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    fs.appendFileSync(summaryPath, report, "utf8");
    console.log("✅ Report also written to GitHub Actions Step Summary.");
  }

  // Exit with error code if high severity findings exist
  const allFindings = [...semgrepFindings, ...codeqlFindings];
  const grouped = groupBySeverity(allFindings);
  if (grouped.HIGH.length > 0) {
    console.error(`\n🔴 ${grouped.HIGH.length} high severity finding(s) detected.`);
    process.exit(1); // Fail the CI job on high severity
  }
}

main();
