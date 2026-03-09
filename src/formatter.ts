import { ScanReport, ToolScanResult, ThreatSeverity } from './types.js';

const SEVERITY_COLORS: Record<ThreatSeverity, string> = {
  critical: '\x1b[91m',  // bright red
  high: '\x1b[31m',      // red
  medium: '\x1b[33m',    // yellow
  low: '\x1b[36m',       // cyan
  info: '\x1b[37m',      // white
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

function severityIcon(severity: ThreatSeverity): string {
  const icons: Record<ThreatSeverity, string> = {
    critical: '[!!!]',
    high: '[!!]',
    medium: '[!]',
    low: '[~]',
    info: '[i]',
  };
  return `${SEVERITY_COLORS[severity]}${icons[severity]}${RESET}`;
}

function riskBar(score: number): string {
  const filled = Math.round(score / 5);
  const empty = 20 - filled;
  const color = score > 75 ? '\x1b[91m' : score > 50 ? '\x1b[31m' : score > 25 ? '\x1b[33m' : '\x1b[32m';
  return `${color}${'#'.repeat(filled)}${DIM}${'-'.repeat(empty)}${RESET} ${score}/100`;
}

/**
 * Format scan report as colored terminal text
 */
export function formatText(report: ScanReport): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${BOLD}  mcp-shield  Security Scan Report${RESET}`);
  lines.push(`  ${'='.repeat(40)}`);
  lines.push('');

  if (report.serverUri) {
    lines.push(`  Server: ${report.serverUri}`);
  }
  lines.push(`  Tools scanned: ${report.toolsScanned}`);
  lines.push(`  Scan time: ${report.scanDuration}ms`);
  lines.push('');

  // Summary
  const s = report.summary;
  const riskColor = s.overallRisk === 'safe' ? '\x1b[32m' :
    s.overallRisk === 'low' ? '\x1b[36m' :
    s.overallRisk === 'medium' ? '\x1b[33m' : '\x1b[91m';
  lines.push(`  Overall Risk: ${riskColor}${BOLD}${s.overallRisk.toUpperCase()}${RESET}`);
  lines.push(`  Threats: ${s.totalThreats} (${SEVERITY_COLORS.critical}${s.critical} critical${RESET}, ${SEVERITY_COLORS.high}${s.high} high${RESET}, ${SEVERITY_COLORS.medium}${s.medium} medium${RESET}, ${SEVERITY_COLORS.low}${s.low} low${RESET})`);
  lines.push(`  Passed: ${s.passedTools}/${report.toolsScanned} tools`);
  lines.push('');

  // Per-tool results
  for (const result of report.results) {
    lines.push(`  ${BOLD}${result.toolName}${RESET}  ${riskBar(result.riskScore)}  [${result.riskLevel}]`);

    if (result.threats.length === 0) {
      lines.push(`    ${DIM}No threats detected${RESET}`);
    } else {
      for (const threat of result.threats) {
        lines.push(`    ${severityIcon(threat.severity)} ${SEVERITY_COLORS[threat.severity]}${threat.severity.toUpperCase().padEnd(8)}${RESET} [${threat.category}] ${threat.title}`);
        lines.push(`             ${DIM}${threat.evidence}${RESET}`);
      }
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Format scan report as JSON
 */
export function formatJson(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

/**
 * Format scan report as markdown
 */
export function formatMarkdown(report: ScanReport): string {
  const lines: string[] = [];

  lines.push('# MCP Shield Security Report');
  lines.push('');
  if (report.serverUri) {
    lines.push(`**Server:** ${report.serverUri}`);
  }
  lines.push(`**Tools Scanned:** ${report.toolsScanned}`);
  lines.push(`**Overall Risk:** ${report.summary.overallRisk.toUpperCase()}`);
  lines.push(`**Total Threats:** ${report.summary.totalThreats}`);
  lines.push('');

  // Summary table
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| Critical | ${report.summary.critical} |`);
  lines.push(`| High | ${report.summary.high} |`);
  lines.push(`| Medium | ${report.summary.medium} |`);
  lines.push(`| Low | ${report.summary.low} |`);
  lines.push(`| Info | ${report.summary.info} |`);
  lines.push('');

  // Per-tool results
  for (const result of report.results) {
    lines.push(`## ${result.toolName}`);
    lines.push('');
    lines.push(`Risk Score: **${result.riskScore}/100** (${result.riskLevel})`);
    lines.push('');

    if (result.threats.length === 0) {
      lines.push('No threats detected.');
    } else {
      lines.push('| Severity | Category | Finding | Evidence |');
      lines.push('|----------|----------|---------|----------|');
      for (const threat of result.threats) {
        lines.push(`| ${threat.severity.toUpperCase()} | ${threat.category} | ${threat.title} | ${threat.evidence.replace(/\|/g, '\\|')} |`);
      }
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Format report in the specified format
 */
export function formatReport(report: ScanReport, format: 'text' | 'json' | 'markdown' = 'text'): string {
  switch (format) {
    case 'json': return formatJson(report);
    case 'markdown': return formatMarkdown(report);
    default: return formatText(report);
  }
}
