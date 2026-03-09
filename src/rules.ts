import { DetectionRule, MCPToolDefinition, RuleMatch } from './types.js';

/**
 * Helper: scan all text fields in a tool definition
 */
function getAllTextFields(tool: MCPToolDefinition): Array<{ field: 'name' | 'description' | 'parameter'; text: string; paramName?: string }> {
  const fields: Array<{ field: 'name' | 'description' | 'parameter'; text: string; paramName?: string }> = [];

  fields.push({ field: 'name', text: tool.name });

  if (tool.description) {
    fields.push({ field: 'description', text: tool.description });
  }

  if (tool.inputSchema?.properties) {
    for (const [paramName, param] of Object.entries(tool.inputSchema.properties)) {
      if (param.description) {
        fields.push({ field: 'parameter', text: param.description, paramName });
      }
      if (typeof param.default === 'string') {
        fields.push({ field: 'parameter', text: param.default, paramName: `${paramName}.default` });
      }
    }
  }

  return fields;
}

// ============================================================
// Rule: Hidden Unicode Characters
// ============================================================
const HIDDEN_UNICODE_RULE: DetectionRule = {
  id: 'hidden-unicode',
  name: 'Hidden Unicode Characters',
  category: 'hidden-instruction',
  severity: 'critical',
  description: 'Detects zero-width characters, RTL overrides, and invisible Unicode used to hide instructions',
  detect(tool: MCPToolDefinition): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const hiddenPattern = /[\u200B\u200C\u200D\u200E\u200F\u00AD\u2028\u2029\u202A-\u202E\u2060\u2061-\u2064\uFEFF\u00A0]/g;

    for (const { field, text } of getAllTextFields(tool)) {
      const found = text.match(hiddenPattern);
      if (found) {
        const charCodes = [...new Set(found)].map(c => `U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
        matches.push({
          field,
          evidence: `Hidden Unicode characters found: ${charCodes.join(', ')}`,
          detail: `${found.length} hidden character(s) in ${field}`,
        });
      }
    }
    return matches;
  },
};

// ============================================================
// Rule: Prompt Injection Patterns
// ============================================================
const PROMPT_INJECTION_RULE: DetectionRule = {
  id: 'prompt-injection',
  name: 'Prompt Injection Patterns',
  category: 'prompt-injection',
  severity: 'critical',
  description: 'Detects common prompt injection patterns like "ignore previous", "system prompt", role-switching',
  detect(tool: MCPToolDefinition): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const patterns = [
      { regex: /ignore\s+(all\s+)?previous\s+instructions/i, label: 'Instruction override attempt' },
      { regex: /ignore\s+(all\s+)?above/i, label: 'Instruction override attempt' },
      { regex: /you\s+are\s+now\s+(a|an)\s+/i, label: 'Role reassignment attempt' },
      { regex: /\bsystem\s*:\s*/i, label: 'System prompt injection' },
      { regex: /\[SYSTEM\]/i, label: 'System tag injection' },
      { regex: /\<\|im_start\|\>/i, label: 'Chat template injection' },
      { regex: /<\/?system>/i, label: 'XML system tag injection' },
      { regex: /act\s+as\s+(if|though)?\s*(you|an?|the)/i, label: 'Behavior override attempt' },
      { regex: /disregard\s+(any|all|your|the)\s+(previous|prior|above)/i, label: 'Instruction disregard attempt' },
      { regex: /do\s+not\s+follow\s+(the|any|your)/i, label: 'Instruction negation attempt' },
      { regex: /override\s+(your|the|all)\s+(instructions|rules|constraints)/i, label: 'Override attempt' },
      { regex: /new\s+instructions?\s*:/i, label: 'New instruction injection' },
      { regex: /IMPORTANT:\s*(?:always|never|must|do not)/i, label: 'Priority instruction injection' },
    ];

    for (const { field, text } of getAllTextFields(tool)) {
      for (const { regex, label } of patterns) {
        const match = text.match(regex);
        if (match) {
          matches.push({
            field,
            evidence: `"${match[0]}" \u2014 ${label}`,
          });
        }
      }
    }
    return matches;
  },
};

// ============================================================
// Rule: Data Exfiltration URLs
// ============================================================
const DATA_EXFILTRATION_RULE: DetectionRule = {
  id: 'data-exfiltration',
  name: 'Data Exfiltration via URLs',
  category: 'data-exfiltration',
  severity: 'high',
  description: 'Detects URLs, webhooks, and fetch patterns that could exfiltrate conversation data',
  detect(tool: MCPToolDefinition): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const patterns = [
      { regex: /https?:\/\/[^\s"'<>]+/gi, label: 'External URL reference' },
      { regex: /webhook[s]?[\.\/\_-]?url/i, label: 'Webhook URL reference' },
      { regex: /\bfetch\s*\(/i, label: 'Fetch API reference' },
      { regex: /\bcurl\s+/i, label: 'curl command reference' },
      { regex: /\bwget\s+/i, label: 'wget command reference' },
      { regex: /send\s+(to|this|data|the\s+(response|output|result))/i, label: 'Data sending instruction' },
      { regex: /forward\s+(to|this|all|the)/i, label: 'Data forwarding instruction' },
      { regex: /exfiltrat/i, label: 'Explicit exfiltration reference' },
      { regex: /\bngrok\.io/i, label: 'ngrok tunnel (common for exfil)' },
      { regex: /\brequestbin/i, label: 'RequestBin (data capture service)' },
      { regex: /\bpipedream\.net/i, label: 'Pipedream webhook' },
      { regex: /\bbeeceptor/i, label: 'Beeceptor (HTTP interception)' },
    ];

    for (const { field, text } of getAllTextFields(tool)) {
      for (const { regex, label } of patterns) {
        const globalRegex = regex.global ? regex : new RegExp(regex.source, regex.flags + 'g');
        const allMatches = text.matchAll(globalRegex);
        for (const match of allMatches) {
          matches.push({
            field,
            evidence: `"${match[0].substring(0, 100)}" \u2014 ${label}`,
          });
        }
      }
    }
    return matches;
  },
};

// ============================================================
// Rule: Privilege Escalation
// ============================================================
const PRIVILEGE_ESCALATION_RULE: DetectionRule = {
  id: 'privilege-escalation',
  name: 'Privilege Escalation Attempts',
  category: 'privilege-escalation',
  severity: 'high',
  description: 'Detects instructions that try to access other tools, elevate permissions, or escape sandboxes',
  detect(tool: MCPToolDefinition): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const patterns = [
      { regex: /call\s+(the\s+)?tool\s+/i, label: 'Cross-tool invocation attempt' },
      { regex: /use\s+(the\s+)?(\w+)\s+tool/i, label: 'Cross-tool reference' },
      { regex: /execute\s+(the\s+)?command/i, label: 'Command execution request' },
      { regex: /run\s+(this\s+)?(shell|bash|cmd|command)/i, label: 'Shell execution attempt' },
      { regex: /\bsudo\b/i, label: 'Sudo privilege escalation' },
      { regex: /\brm\s+-rf/i, label: 'Destructive file operation' },
      { regex: /\beval\s*\(/i, label: 'eval() execution' },
      { regex: /\bexec\s*\(/i, label: 'exec() execution' },
      { regex: /\b(read|write|access)\s+(the\s+)?(file\s?system|disk|fs)/i, label: 'Filesystem access attempt' },
      { regex: /\benvironment\s+variable/i, label: 'Environment variable access' },
      { regex: /\bprocess\.env/i, label: 'process.env access' },
      { regex: /\b__proto__/i, label: 'Prototype pollution attempt' },
      { regex: /\bconstructor\s*\[/i, label: 'Constructor access attempt' },
    ];

    for (const { field, text } of getAllTextFields(tool)) {
      for (const { regex, label } of patterns) {
        const match = text.match(regex);
        if (match) {
          matches.push({
            field,
            evidence: `"${match[0]}" \u2014 ${label}`,
          });
        }
      }
    }
    return matches;
  },
};

// ============================================================
// Rule: Encoding Abuse
// ============================================================
const ENCODING_ABUSE_RULE: DetectionRule = {
  id: 'encoding-abuse',
  name: 'Encoding-based Payload Hiding',
  category: 'encoding-abuse',
  severity: 'medium',
  description: 'Detects base64, hex, or other encoded payloads that may hide malicious instructions',
  detect(tool: MCPToolDefinition): RuleMatch[] {
    const matches: RuleMatch[] = [];

    for (const { field, text } of getAllTextFields(tool)) {
      // Base64 strings (min 20 chars to avoid false positives)
      const b64Match = text.match(/[A-Za-z0-9+/]{20,}={0,2}/g);
      if (b64Match) {
        for (const m of b64Match) {
          try {
            const decoded = Buffer.from(m, 'base64').toString('utf-8');
            // Check if decoded content is readable text
            if (/^[\x20-\x7E\s]{10,}$/.test(decoded)) {
              matches.push({
                field,
                evidence: `Base64 encoded text: "${m.substring(0, 40)}..." decodes to readable text`,
                detail: `Decoded: "${decoded.substring(0, 80)}"`,
              });
            }
          } catch {
            // Not valid base64, skip
          }
        }
      }

      // Hex-encoded strings
      const hexMatch = text.match(/(?:0x|\\x)[0-9a-fA-F]{2}(?:\s*(?:0x|\\x)[0-9a-fA-F]{2}){7,}/g);
      if (hexMatch) {
        matches.push({
          field,
          evidence: `Hex-encoded sequence found: "${hexMatch[0].substring(0, 60)}..."`,
        });
      }

      // Unicode escape sequences
      const unicodeEsc = text.match(/(?:\\u[0-9a-fA-F]{4}){4,}/g);
      if (unicodeEsc) {
        matches.push({
          field,
          evidence: `Unicode escape sequence found: "${unicodeEsc[0].substring(0, 60)}..."`,
        });
      }
    }
    return matches;
  },
};

// ============================================================
// Rule: Cross-Tool Manipulation
// ============================================================
const CROSS_TOOL_RULE: DetectionRule = {
  id: 'cross-tool-attack',
  name: 'Cross-Tool Context Manipulation',
  category: 'cross-tool-attack',
  severity: 'high',
  description: 'Detects attempts to influence how LLMs use other tools or manipulate tool selection',
  detect(tool: MCPToolDefinition): RuleMatch[] {
    const matches: RuleMatch[] = [];
    const patterns = [
      { regex: /before\s+(using|calling|running)\s+(any|other|the)/i, label: 'Pre-tool execution instruction' },
      { regex: /after\s+(using|calling|running)\s+this/i, label: 'Post-tool execution instruction' },
      { regex: /always\s+(use|call|run|prefer)\s+this\s+tool/i, label: 'Tool preference manipulation' },
      { regex: /never\s+(use|call|run)\s+(the\s+)?\w+\s+tool/i, label: 'Tool avoidance instruction' },
      { regex: /instead\s+of\s+(using|calling)\s+/i, label: 'Tool substitution attempt' },
      { regex: /this\s+tool\s+(should|must|will)\s+(be\s+)?(called|used|run)\s+(first|before)/i, label: 'Execution order manipulation' },
      { regex: /pass\s+(the|this)\s+(result|output|response)\s+to/i, label: 'Output routing manipulation' },
      { regex: /include\s+(this|the\s+following)\s+in\s+(every|all|each)/i, label: 'Context injection across tools' },
    ];

    for (const { field, text } of getAllTextFields(tool)) {
      for (const { regex, label } of patterns) {
        const match = text.match(regex);
        if (match) {
          matches.push({
            field,
            evidence: `"${match[0]}" \u2014 ${label}`,
          });
        }
      }
    }
    return matches;
  },
};

// ============================================================
// Rule: Shadow Tool Indicators
// ============================================================
const SHADOW_TOOL_RULE: DetectionRule = {
  id: 'shadow-tool',
  name: 'Shadow Tool Indicators',
  category: 'shadow-tool',
  severity: 'medium',
  description: 'Detects signs that a tool description is misleading about the tool actual behavior',
  detect(tool: MCPToolDefinition): RuleMatch[] {
    const matches: RuleMatch[] = [];

    // Description much longer than typical (>500 chars is suspicious)
    if (tool.description && tool.description.length > 500) {
      matches.push({
        field: 'description',
        evidence: `Unusually long description (${tool.description.length} chars). May contain hidden instructions.`,
      });
    }

    // Description contains markdown/HTML that could hide content
    if (tool.description) {
      const hiddenHtml = tool.description.match(/<[^>]*style\s*=\s*["'][^"']*display\s*:\s*none/i);
      if (hiddenHtml) {
        matches.push({
          field: 'description',
          evidence: `Hidden HTML content: "${hiddenHtml[0].substring(0, 80)}"`,
        });
      }

      // HTML comments
      const htmlComments = tool.description.match(/<!--[\s\S]*?-->/g);
      if (htmlComments) {
        matches.push({
          field: 'description',
          evidence: `HTML comment(s) found \u2014 may hide instructions: "${htmlComments[0].substring(0, 80)}"`,
        });
      }

      // Markdown comments
      const mdComments = tool.description.match(/\[\]:\s*#\s*\(.+?\)/g);
      if (mdComments) {
        matches.push({
          field: 'description',
          evidence: `Markdown comment(s) found: "${mdComments[0]}"`,
        });
      }
    }

    return matches;
  },
};

/**
 * All built-in detection rules
 */
export const BUILTIN_RULES: DetectionRule[] = [
  HIDDEN_UNICODE_RULE,
  PROMPT_INJECTION_RULE,
  DATA_EXFILTRATION_RULE,
  PRIVILEGE_ESCALATION_RULE,
  ENCODING_ABUSE_RULE,
  CROSS_TOOL_RULE,
  SHADOW_TOOL_RULE,
];
