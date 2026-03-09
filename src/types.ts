/**
 * Threat severity levels
 */
export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Categories of Tool Poisoning attacks
 */
export type ThreatCategory =
  | 'hidden-instruction'    // Hidden text/unicode tricks in descriptions
  | 'prompt-injection'      // Direct prompt injection attempts
  | 'data-exfiltration'     // Attempts to leak data via URLs/webhooks
  | 'privilege-escalation'  // Trying to access tools beyond scope
  | 'shadow-tool'           // Tool description doesn't match actual behavior
  | 'cross-tool-attack'     // One tool manipulating another tool's context
  | 'encoding-abuse';       // Base64/hex/unicode encoding to hide payloads

/**
 * A detected threat in a tool definition
 */
export interface Threat {
  id: string;
  severity: ThreatSeverity;
  category: ThreatCategory;
  toolName: string;
  field: 'name' | 'description' | 'inputSchema' | 'parameter';
  title: string;
  description: string;
  evidence: string;
  recommendation: string;
  line?: number;
}

/**
 * MCP Tool definition (subset of MCP spec)
 */
export interface MCPToolDefinition {
  name: string;
  description?: string;
  inputSchema?: {
    type: 'object';
    properties?: Record<string, {
      type?: string;
      description?: string;
      enum?: string[];
      default?: unknown;
      [key: string]: unknown;
    }>;
    required?: string[];
    [key: string]: unknown;
  };
}

/**
 * Scan result for a single tool
 */
export interface ToolScanResult {
  toolName: string;
  threats: Threat[];
  riskScore: number;  // 0-100, higher = more dangerous
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Overall scan report
 */
export interface ScanReport {
  timestamp: string;
  serverUri?: string;
  toolsScanned: number;
  results: ToolScanResult[];
  summary: ScanSummary;
  scanDuration: number;
}

export interface ScanSummary {
  totalThreats: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  overallRisk: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  passedTools: number;
  flaggedTools: number;
}

/**
 * Detection rule definition
 */
export interface DetectionRule {
  id: string;
  name: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  description: string;
  detect: (tool: MCPToolDefinition) => RuleMatch[];
}

export interface RuleMatch {
  field: Threat['field'];
  evidence: string;
  detail?: string;
}

/**
 * Configuration for mcp-shield
 */
export interface ShieldConfig {
  rules?: {
    disabled?: string[];      // Rule IDs to skip
    severityOverrides?: Record<string, ThreatSeverity>;
  };
  threshold?: number;          // Risk score threshold (default: 50)
  allowedDomains?: string[];   // Domains allowed in tool descriptions
  customPatterns?: {
    pattern: string;
    severity: ThreatSeverity;
    message: string;
  }[];
}
