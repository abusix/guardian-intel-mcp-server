#!/usr/bin/env node

import { Command } from 'commander';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const program = new Command();

program
  .name('guardian-intel-mcp-server')
  .description('Abusix Guardian Intel MCP Server - Threat intelligence for AI assistants')
  .version('1.0.0');

program
  .option('--api-key <key>', 'Abusix Guardian Intel API key (can also use ABUSIX_API_KEY env var)')
  .option('--base-url <url>', 'Base URL for Guardian Intel API (default: https://threat-intel-api.abusix.com/beta)')
  .option('--debug', 'Enable debug logging')
  .option('--help-usage', 'Show detailed usage examples')
  .action(async (options) => {
    if (options.helpUsage) {
      showUsageExamples();
      return;
    }

    // Validate API key
    const apiKey = options.apiKey || process.env.ABUSIX_API_KEY;
    if (!apiKey) {
      console.error('❌ Error: Abusix Guardian Intel API key is required');
      console.error('');
      console.error('Set it using one of these methods:');
      console.error('  1. Environment variable: export ABUSIX_API_KEY="your-api-key"');
      console.error('  2. Command line option: --api-key "your-api-key"');
      console.error('');
      console.error('Get your API key from: https://portal.abusix.com/');
      process.exit(1);
    }

    // Set up environment variables
    const env = { ...process.env };
    env.ABUSIX_API_KEY = apiKey;
    
    if (options.baseUrl) {
      env.ABUSIX_BASE_URL = options.baseUrl;
    }

    if (options.debug) {
      env.DEBUG = '1';
    }

    // Start the MCP server
    const serverPath = join(__dirname, 'index.js');
    
    if (options.debug) {
      console.error('🚀 Starting Guardian Intel MCP Server...');
      console.error(`📍 Server path: ${serverPath}`);
      console.error(`🔑 API key: ${apiKey.substring(0, 8)}...`);
      console.error(`🌐 Base URL: ${env.ABUSIX_BASE_URL || 'https://threat-intel-api.abusix.com/beta'}`);
      console.error('');
    }

    const serverProcess = spawn('node', [serverPath], {
      env,
      stdio: 'inherit'
    });

    serverProcess.on('error', (error) => {
      console.error('❌ Failed to start Guardian Intel MCP Server:', error.message);
      process.exit(1);
    });

    serverProcess.on('exit', (code) => {
      if (code !== 0) {
        console.error(`❌ Guardian Intel MCP Server exited with code ${code}`);
        process.exit(code || 1);
      }
    });

    // Handle graceful shutdown
    process.on('SIGINT', () => {
      console.error('🛑 Shutting down Guardian Intel MCP Server...');
      serverProcess.kill('SIGINT');
    });

    process.on('SIGTERM', () => {
      console.error('🛑 Shutting down Guardian Intel MCP Server...');
      serverProcess.kill('SIGTERM');
    });
  });

function showUsageExamples() {
  console.log(`
🔍 Abusix Guardian Intel MCP Server Usage Examples

BASIC USAGE:
  npx @abusix/guardian-intel-mcp-server

CONFIGURATION:
  # Using environment variable (recommended)
  export ABUSIX_API_KEY="your-api-key-here"
  npx @abusix/guardian-intel-mcp-server

  # Using command line option
  npx @abusix/guardian-intel-mcp-server --api-key "your-api-key-here"

  # Custom API endpoint
  npx @abusix/guardian-intel-mcp-server --base-url "https://custom-api.example.com"

  # Debug mode
  npx @abusix/guardian-intel-mcp-server --debug

AVAILABLE MCP TOOLS:
  🔍 guardian_intel_lookup          - Look up threat intelligence for an IP address
  📋 guardian_intel_tags_list       - List all available threat intelligence tags  
  🏷️  guardian_intel_tag_details    - Get detailed information about a specific tag
  📊 guardian_intel_tag_ips         - Get IP addresses associated with a tag

INTEGRATION EXAMPLES:
  # Claude Desktop (add to config)
  {
    "mcpServers": {
      "guardian-intel": {
        "command": "npx",
        "args": ["@abusix/guardian-intel-mcp-server"],
        "env": {
          "ABUSIX_API_KEY": "your-api-key-here"
        }
      }
    }
  }

  # With MCP client
  mcp-client connect stdio -- npx @abusix/guardian-intel-mcp-server

GET API KEY:
  Visit: https://portal.abusix.com/

DOCUMENTATION:
  • Guardian Intel API: https://docs.abusix.com/docs/guardian-intel/
  • MCP Protocol: https://modelcontextprotocol.io/
  • GitHub: https://github.com/abusix/guardian-intel-mcp-server
`);
}

program.parse();