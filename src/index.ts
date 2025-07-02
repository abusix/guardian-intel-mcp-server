#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import { GuardianIntelClient } from './guardian-intel-client.js';
import { GuardianIntelTools } from './tools.js';

class GuardianIntelMcpServer {
  private server: Server;
  private guardianIntelClient: GuardianIntelClient;
  private guardianIntelTools: GuardianIntelTools;

  constructor() {
    this.server = new Server(
      {
        name: '@abusix/guardian-intel-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    const apiKey = process.env.ABUSIX_API_KEY;
    if (!apiKey) {
      throw new Error('ABUSIX_API_KEY environment variable is required');
    }

    this.guardianIntelClient = new GuardianIntelClient({
      apiKey,
      baseUrl: process.env.ABUSIX_BASE_URL
    });

    this.guardianIntelTools = new GuardianIntelTools(this.guardianIntelClient);

    this.setupToolHandlers();
  }

  private setupToolHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: this.guardianIntelTools.getToolDefinitions(),
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const result = await this.guardianIntelTools.executeTool(name, args || {});
        
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        
        // Handle specific error types
        if (errorMessage.includes('Invalid IP address')) {
          throw new McpError(ErrorCode.InvalidParams, errorMessage);
        }
        
        if (errorMessage.includes('Tag name is required')) {
          throw new McpError(ErrorCode.InvalidParams, errorMessage);
        }
        
        if (errorMessage.includes('Guardian Intel API Error (404)')) {
          throw new McpError(ErrorCode.InvalidParams, 'Tag not found');
        }
        
        if (errorMessage.includes('Guardian Intel API Error (503)')) {
          throw new McpError(ErrorCode.InternalError, 'Guardian Intel service temporarily unavailable');
        }
        
        if (errorMessage.includes('timeout')) {
          throw new McpError(ErrorCode.InternalError, 'Request timeout - Guardian Intel API is not responding');
        }
        
        if (errorMessage.includes('Unable to connect')) {
          throw new McpError(ErrorCode.InternalError, 'Unable to connect to Guardian Intel API');
        }

        // Generic error handling
        throw new McpError(ErrorCode.InternalError, `Tool execution failed: ${errorMessage}`);
      }
    });
  }

  async run(): Promise<void> {
    // Test the API connection on startup
    try {
      const isHealthy = await this.guardianIntelClient.healthCheck();
      if (!isHealthy) {
        console.error('Warning: Unable to connect to Guardian Intel API. Please check your API key and network connection.');
      } else {
        console.error('✓ Connected to Guardian Intel API successfully');
      }
    } catch (error) {
      console.error('Warning: Guardian Intel API health check failed:', error instanceof Error ? error.message : 'Unknown error');
    }

    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    
    console.error('Guardian Intel MCP Server running on stdio');
  }
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  console.error('Received SIGINT, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.error('Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

// Error handling
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start the server
if (import.meta.url === `file://${process.argv[1]}`) {
  const server = new GuardianIntelMcpServer();
  server.run().catch((error) => {
    console.error('Failed to start Guardian Intel MCP Server:', error);
    process.exit(1);
  });
}