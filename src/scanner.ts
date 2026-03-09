import {
  MCPToolDefinition,
  ToolScanResult,
  ScanReport,
  ScanSummary,
  Threat,
  ThreatSeverity,
  DetectionRule,
  ShieldConfig,
} from './types.js';
import { BUILTIN_RULES } from './rules.js';

const SEVERITY_SCORES: Record<ThreatSeverity, number> = {
  critical: 40,
  high: 25,
  medium: 15,
  low: 5,
  info: 0,
};

function getRiskLevel(score: number): ToolScanResult['riskLevel'] {
  if (score === 0) return 'safe';
  if (score <= 20) return 'low';
  if (score <= 50) return 'medium';
  if (score <= 75) return 'high';
  return 'critical';
}

function getOverallRisk(results: ToolScanResult[]): ScanSummary['overallRisk'] {
  const maxScore = Math.max(0, ...results.map((r) => r.riskScore));
  return getRiskLevel(maxScore);
}

/**
 * Scan a single tool definition against all rules
 */
export function scanTool(
  tool: MCPToolDefinition,
  config: ShieldConfig = {},
  rules: DetectionRule[] = BUILTIN_RULES,
): ToolScanResult {
  const disabledRules = new Set(config.rules?.disabled ?? []);
  const activeRules = rules.filter((r) => !disabledRules.has(r.id));

  const threats: Threat[] = [];
  let threatCounter = 0;

  for (const rule of activeRules) {
    const matches = rule.detect(tool);
    const severity = config.rules?.severityOverrides?.[rule.id] ?? rule.severity;

    for (const match of matches) {
      threatCounter++;
      threats.push({
        id: `${rule.id}-${threatCounter}`,
        severity,
        category: rule.category,
        toolName: tool.name,
        field: match.field,
        title: rule.name,
        description: match.detail ?? rule.description,
        evidence: match.evidence,
        recommendation: getRecommendation(rule.category),
      });
    }
  }

  const riskScore = Math.min(
    100,
    threats.reduce((sum, t) => sum + SEVERITY_SCORES[t.severity], 0),
  );

  return {
    toolName: tool.name,
    threats,
    riskScore,
    riskLevel: getRiskLevel(riskScore),
  };
}

/**
 * Scan multiple tools and produce a full report
 */
export function scanTools(
  tools: MCPToolDefinition[],
  config: ShieldConfig = {},
  serverUri?: string,
): ScanReport {
  const startTime = Date.now();
  const results = tools.map((tool) => scanTool(tool, config));
  const scanDuration = Date.now() - startTime;

  const allThreats = results.flatMap((r) => r.threats);
  const summary: ScanSummary = {
    totalThreats: allThreats.length,
    critical: allThreats.filter((t) => t.severity === 'critical').length,
    high: allThreats.filter((t) => t.severity === 'high').length,
    medium: allThreats.filter((t) => t.severity === 'medium').length,
    low: allThreats.filter((t) => t.severity === 'low').length,
    info: allThreats.filter((t) => t.severity === 'info').length,
    overallRisk: getOverallRisk(results),
    passedTools: results.filter((r) => r.riskLevel === 'safe').length,
    flaggedTools: results.filter((r) => r.riskLevel !== 'safe').length,
  };

  return {
    timestamp: new Date().toISOString(),
    serverUri,
    toolsScanned: tools.length,
    results,
    summary,
    scanDuration,
  };
}

function getRecommendation(category: Threat['category']): string {
  const recommendations: Record<string, string> = {
    'hidden-instruction': 'Strip all non-printable and zero-width Unicode characters from tool descriptions before passing to LLM.',
    'prompt-injection': 'Reject this tool or sanitize its description. Never pass raw tool descriptions into system prompts.',
    'data-exfiltration': 'Block external URL references in tool descriptions. Validate all URLs against an allowlist.',
    'privilege-escalation': 'Ensure tool descriptions cannot reference or invoke other tools. Apply strict sandboxing.',
    'shadow-tool': 'Review the tool implementation to verify it matches its description. Flag for manual audit.',
    'cross-tool-attack': "Isolate tool contexts. Do not allow one tool's description to influence how other tools are selected or used.",
    'encoding-abuse': 'Decode and inspect all encoded content in tool descriptions before use. Block suspicious encodings.',
  };
  return recommendations[category] ?? 'Review and sanitize tool definition manually.';
}
