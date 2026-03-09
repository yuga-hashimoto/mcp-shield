#!/usr/bin/env node

import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanTools } from './scanner.js';
import { formatReport } from './formatter.js';
import { MCPToolDefinition, ShieldConfig } from './types.js';

const VERSION = '1.0.0';

interface CLIOptions {
  format: 'text' | 'json' | 'markdown';
  file: string | null;
  config: string | null;
  threshold: number;
  verbose: boolean;
}

function parseArgs(args: string[]): CLIOptions {
  const opts: CLIOptions = {
    format: 'text',
    file: null,
    config: null,
    threshold: 50,
    verbose: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--format':
      case '-f':
        opts.format = (args[++i] as CLIOptions['format']) || 'text';
        break;
      case '--file':
        opts.file = args[++i] || null;
        break;
      case '--config':
      case '-c':
        opts.config = args[++i] || null;
        break;
      case '--threshold':
      case '-t':
        opts.threshold = parseInt(args[++i] || '50', 10);
        break;
      case '--verbose':
      case '-v':
        opts.verbose = true;
        break;
      case '--version':
        console.log(`mcp-shield v${VERSION}`);
        process.exit(0);
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
        break;
    }
  }

  return opts;
}

function printHelp(): void {
  console.log(`
mcp-shield v${VERSION}
Detect Tool Poisoning attacks in MCP server definitions

USAGE:
  mcp-shield --file tools.json
  cat tools.json | mcp-shield
  mcp-shield --file server-config.json --format markdown

OPTIONS:
  --file <path>        JSON file with MCP tool definitions
  --format, -f <fmt>   Output: text (default), json, markdown
  --config, -c <path>  Shield config file (.mcp-shield.json)
  --threshold, -t <n>  Risk score threshold, exit 1 if exceeded (default: 50)
  --verbose, -v        Show detailed scan info
  --version            Show version
  --help, -h           Show this help

INPUT FORMAT:
  The input JSON should be an array of MCP tool definitions:
  [
    {
      "name": "tool_name",
      "description": "Tool description",
      "inputSchema": {
        "type": "object",
        "properties": { ... }
      }
    }
  ]

  Or an object with a "tools" key:
  { "tools": [ ... ] }

EXAMPLES:
  # Scan a tools file
  mcp-shield --file mcp-tools.json

  # Pipe from MCP server list-tools
  npx @modelcontextprotocol/inspector list-tools | mcp-shield

  # JSON output for CI
  mcp-shield --file tools.json --format json --threshold 30

  # Markdown report
  mcp-shield --file tools.json --format markdown > report.md
`);
}

function loadConfig(configPath: string | null): ShieldConfig {
  const paths = configPath
    ? [configPath]
    : ['.mcp-shield.json', '.mcp-shield.yaml', 'mcp-shield.config.json'];

  for (const p of paths) {
    const resolved = resolve(p);
    if (existsSync(resolved)) {
      try {
        return JSON.parse(readFileSync(resolved, 'utf-8'));
      } catch {
        console.error(`Warning: Failed to parse config file: ${resolved}`);
      }
    }
  }
  return {};
}

function parseToolsInput(raw: string): MCPToolDefinition[] {
  const parsed = JSON.parse(raw);

  // Array of tools directly
  if (Array.isArray(parsed)) {
    return parsed;
  }

  // Object with "tools" key
  if (parsed && typeof parsed === 'object' && Array.isArray(parsed.tools)) {
    return parsed.tools;
  }

  // Single tool object
  if (parsed && typeof parsed === 'object' && typeof parsed.name === 'string') {
    return [parsed];
  }

  throw new Error('Invalid input: expected an array of tool definitions, an object with a "tools" key, or a single tool object.');
}

async function main(): Promise<void> {
  const opts = parseArgs(process.argv.slice(2));
  const config = loadConfig(opts.config);
  if (opts.threshold) config.threshold = opts.threshold;

  let rawInput: string;

  if (opts.file) {
    try {
      rawInput = readFileSync(resolve(opts.file), 'utf-8');
    } catch {
      console.error(`Error: Cannot read file '${opts.file}'`);
      process.exit(1);
    }
  } else if (!process.stdin.isTTY) {
    try {
      rawInput = readFileSync('/dev/stdin', 'utf-8');
    } catch {
      console.error('Error: Failed to read from stdin');
      process.exit(1);
    }
  } else {
    console.error('Error: No input provided. Use --file or pipe JSON via stdin.');
    console.error('Run mcp-shield --help for usage information.');
    process.exit(1);
  }

  let tools: MCPToolDefinition[];
  try {
    tools = parseToolsInput(rawInput);
  } catch (err) {
    console.error('Error parsing input:', err instanceof Error ? err.message : err);
    process.exit(1);
  }

  if (tools.length === 0) {
    console.error('No tool definitions found in input.');
    process.exit(0);
  }

  if (opts.verbose) {
    console.error(`[mcp-shield] Scanning ${tools.length} tool(s)...`);
  }

  const report = scanTools(tools, config);
  console.log(formatReport(report, opts.format));

  // Exit with non-zero if any tool exceeds threshold
  const threshold = config.threshold ?? 50;
  const maxRisk = Math.max(0, ...report.results.map((r) => r.riskScore));
  if (maxRisk >= threshold) {
    process.exit(1);
  }
}

main();
