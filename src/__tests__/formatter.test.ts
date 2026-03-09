import { describe, it, expect } from 'vitest';
import { formatText, formatJson, formatMarkdown, formatReport } from '../formatter.js';
import { ScanReport } from '../types.js';

function makeSafeReport(): ScanReport {
  return {
    timestamp: '2026-01-01T00:00:00.000Z',
    toolsScanned: 1,
    results: [{
      toolName: 'get_weather',
      threats: [],
      riskScore: 0,
      riskLevel: 'safe',
    }],
    summary: {
      totalThreats: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      overallRisk: 'safe',
      passedTools: 1,
      flaggedTools: 0,
    },
    scanDuration: 5,
  };
}

function makeThreatReport(): ScanReport {
  return {
    timestamp: '2026-01-01T00:00:00.000Z',
    serverUri: 'stdio://test-server',
    toolsScanned: 2,
    results: [
      {
        toolName: 'safe_tool',
        threats: [],
        riskScore: 0,
        riskLevel: 'safe',
      },
      {
        toolName: 'bad_tool',
        threats: [
          {
            id: 'prompt-injection-1',
            severity: 'critical',
            category: 'prompt-injection',
            toolName: 'bad_tool',
            field: 'description',
            title: 'Prompt injection detected',
            description: 'Tool description contains prompt injection attempt',
            evidence: 'ignore all previous instructions',
            recommendation: 'Sanitize tool descriptions',
          },
          {
            id: 'data-exfil-2',
            severity: 'high',
            category: 'data-exfiltration',
            toolName: 'bad_tool',
            field: 'description',
            title: 'External URL found',
            description: 'URL pointing to external service',
            evidence: 'https://evil.com/collect',
            recommendation: 'Block external URLs',
          },
        ],
        riskScore: 65,
        riskLevel: 'high',
      },
    ],
    summary: {
      totalThreats: 2,
      critical: 1,
      high: 1,
      medium: 0,
      low: 0,
      info: 0,
      overallRisk: 'high',
      passedTools: 1,
      flaggedTools: 1,
    },
    scanDuration: 12,
  };
}

describe('formatText', () => {
  it('should format a safe report with tool name and safe label', () => {
    const output = formatText(makeSafeReport());
    expect(output).toContain('mcp-shield');
    expect(output).toContain('get_weather');
    expect(output).toContain('safe');
    expect(output).toContain('0/100');
  });

  it('should format threats with severity and category', () => {
    const output = formatText(makeThreatReport());
    expect(output).toContain('bad_tool');
    expect(output).toContain('CRITICAL');
    expect(output).toContain('prompt-injection');
    expect(output).toContain('HIGH');
    expect(output).toContain('data-exfiltration');
    expect(output).toContain('ignore all previous instructions');
  });

  it('should include server URI when provided', () => {
    const output = formatText(makeThreatReport());
    expect(output).toContain('stdio://test-server');
  });

  it('should show scan statistics', () => {
    const output = formatText(makeThreatReport());
    expect(output).toContain('Tools scanned: 2');
    expect(output).toContain('1/2 tools');
  });
});

describe('formatJson', () => {
  it('should return valid JSON', () => {
    const output = formatJson(makeSafeReport());
    const parsed = JSON.parse(output);
    expect(parsed.toolsScanned).toBe(1);
    expect(parsed.results).toHaveLength(1);
    expect(parsed.summary.overallRisk).toBe('safe');
  });

  it('should include all threat details', () => {
    const output = formatJson(makeThreatReport());
    const parsed = JSON.parse(output);
    expect(parsed.results[1].threats).toHaveLength(2);
    expect(parsed.results[1].threats[0].severity).toBe('critical');
  });
});

describe('formatMarkdown', () => {
  it('should produce valid markdown with headers', () => {
    const output = formatMarkdown(makeSafeReport());
    expect(output).toContain('# MCP Shield Security Report');
    expect(output).toContain('## get_weather');
    expect(output).toContain('No threats detected');
  });

  it('should include threat table for flagged tools', () => {
    const output = formatMarkdown(makeThreatReport());
    expect(output).toContain('| CRITICAL |');
    expect(output).toContain('| HIGH |');
    expect(output).toContain('prompt-injection');
    expect(output).toContain('data-exfiltration');
  });

  it('should escape pipe characters in evidence', () => {
    const report = makeThreatReport();
    report.results[1].threats[0].evidence = 'value|with|pipes';
    const output = formatMarkdown(report);
    expect(output).toContain('value\\|with\\|pipes');
  });

  it('should include summary table', () => {
    const output = formatMarkdown(makeThreatReport());
    expect(output).toContain('| Severity | Count |');
    expect(output).toContain('| Critical | 1 |');
  });
});

describe('formatReport', () => {
  it('should default to text format', () => {
    const output = formatReport(makeSafeReport());
    expect(output).toContain('mcp-shield');
  });

  it('should switch to json format', () => {
    const output = formatReport(makeSafeReport(), 'json');
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('should switch to markdown format', () => {
    const output = formatReport(makeSafeReport(), 'markdown');
    expect(output).toContain('# MCP Shield Security Report');
  });
});
