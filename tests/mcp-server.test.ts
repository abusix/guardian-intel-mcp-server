import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { GuardianIntelClient } from '../src/guardian-intel-client.js';
import { GuardianIntelTools } from '../src/tools.js';
import { suppressConsole, restoreConsole } from './setup.js';

// Mock dependencies
jest.mock('@modelcontextprotocol/sdk/server/index.js');
jest.mock('../src/guardian-intel-client.js');
jest.mock('../src/tools.js');

const MockedServer = Server as jest.MockedClass<typeof Server>;
const MockedGuardianIntelClient = GuardianIntelClient as jest.MockedClass<typeof GuardianIntelClient>;
const MockedGuardianIntelTools = GuardianIntelTools as jest.MockedClass<typeof GuardianIntelTools>;

// We need to import the server class after mocking
let GuardianIntelMcpServer: any;

describe('GuardianIntelMcpServer', () => {
  let mockServer: jest.Mocked<Server>;
  let mockClient: jest.Mocked<GuardianIntelClient>;
  let mockTools: jest.Mocked<GuardianIntelTools>;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(async () => {
    // Save original environment
    originalEnv = process.env;
    
    // Reset mocks
    jest.clearAllMocks();
    suppressConsole();

    // Create mock instances
    mockServer = {
      setRequestHandler: jest.fn(),
      connect: jest.fn()
    } as any;

    mockClient = {
      healthCheck: jest.fn()
    } as any;

    mockTools = {
      getToolDefinitions: jest.fn(),
      executeTool: jest.fn()
    } as any;

    // Setup mock constructors
    MockedServer.mockImplementation(() => mockServer);
    MockedGuardianIntelClient.mockImplementation(() => mockClient);
    MockedGuardianIntelTools.mockImplementation(() => mockTools);

    // Set up environment
    process.env = {
      ...originalEnv,
      ABUSIX_API_KEY: 'test-api-key'
    };

    // Dynamic import to get the fresh module after mocking
    const module = await import('../src/index.js');
    GuardianIntelMcpServer = (module as any).GuardianIntelMcpServer;
  });

  afterEach(() => {
    // Restore environment
    process.env = originalEnv;
    restoreConsole();
    jest.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should initialize server with correct configuration', () => {
      new GuardianIntelMcpServer();

      expect(MockedServer).toHaveBeenCalledWith(
        {
          name: '@abusix/guardian-intel-mcp-server',
          version: '1.0.0'
        },
        {
          capabilities: {
            tools: {}
          }
        }
      );
    });

    it('should initialize Guardian Intel client with API key', () => {
      new GuardianIntelMcpServer();

      expect(MockedGuardianIntelClient).toHaveBeenCalledWith({
        apiKey: 'test-api-key',
        baseUrl: undefined
      });
    });

    it('should initialize Guardian Intel client with custom base URL', () => {
      process.env.ABUSIX_BASE_URL = 'https://custom-api.example.com';
      
      new GuardianIntelMcpServer();

      expect(MockedGuardianIntelClient).toHaveBeenCalledWith({
        apiKey: 'test-api-key',
        baseUrl: 'https://custom-api.example.com'
      });
    });

    it('should throw error when API key is missing', () => {
      delete process.env.ABUSIX_API_KEY;

      expect(() => new GuardianIntelMcpServer())
        .toThrow('ABUSIX_API_KEY environment variable is required');
    });

    it('should set up request handlers', () => {
      new GuardianIntelMcpServer();

      expect(mockServer.setRequestHandler).toHaveBeenCalledTimes(2);
    });
  });

  describe('request handlers', () => {
    let server: any;
    let listToolsHandler: any;
    let callToolHandler: any;

    beforeEach(() => {
      server = new GuardianIntelMcpServer();
      
      // Get the handlers that were registered
      const setRequestHandlerCalls = mockServer.setRequestHandler.mock.calls;
      listToolsHandler = setRequestHandlerCalls.find(call => 
        call[0].type === 'tools/list'
      )?.[1];
      callToolHandler = setRequestHandlerCalls.find(call => 
        call[0].type === 'tools/call'
      )?.[1];
    });

    describe('list tools handler', () => {
      it('should return tool definitions', async () => {
        const mockToolDefinitions = [
          { name: 'guardian_intel_lookup', description: 'Test tool' }
        ];
        mockTools.getToolDefinitions.mockReturnValue(mockToolDefinitions as any);

        const result = await listToolsHandler();

        expect(result).toEqual({
          tools: mockToolDefinitions
        });
      });
    });

    describe('call tool handler', () => {
      it('should execute tool successfully', async () => {
        const mockResult = { ip: '1.2.3.4', classification: 'malicious' };
        mockTools.executeTool.mockResolvedValue(mockResult);

        const request = {
          params: {
            name: 'guardian_intel_lookup',
            arguments: { ip: '1.2.3.4' }
          }
        };

        const result = await callToolHandler(request);

        expect(mockTools.executeTool).toHaveBeenCalledWith('guardian_intel_lookup', { ip: '1.2.3.4' });
        expect(result).toEqual({
          content: [
            {
              type: 'text',
              text: JSON.stringify(mockResult, null, 2)
            }
          ]
        });
      });

      it('should handle missing arguments', async () => {
        const mockResult = { tags: [] };
        mockTools.executeTool.mockResolvedValue(mockResult);

        const request = {
          params: {
            name: 'guardian_intel_tags_list'
            // No arguments
          }
        };

        const result = await callToolHandler(request);

        expect(mockTools.executeTool).toHaveBeenCalledWith('guardian_intel_tags_list', {});
      });

      it('should handle invalid IP address error', async () => {
        mockTools.executeTool.mockRejectedValue(new Error('Invalid IP address format'));

        const request = {
          params: {
            name: 'guardian_intel_lookup',
            arguments: { ip: 'invalid-ip' }
          }
        };

        await expect(callToolHandler(request))
          .rejects.toThrow(expect.objectContaining({
            code: -32602, // InvalidParams
            message: 'Invalid IP address format'
          }));
      });

      it('should handle tag name required error', async () => {
        mockTools.executeTool.mockRejectedValue(new Error('Tag name is required'));

        const request = {
          params: {
            name: 'guardian_intel_tag_details',
            arguments: { tagName: '' }
          }
        };

        await expect(callToolHandler(request))
          .rejects.toThrow(expect.objectContaining({
            code: -32602, // InvalidParams
            message: 'Tag name is required'
          }));
      });

      it('should handle 404 tag not found error', async () => {
        mockTools.executeTool.mockRejectedValue(new Error('Guardian Intel API Error (404): Tag not found'));

        const request = {
          params: {
            name: 'guardian_intel_tag_details',
            arguments: { tagName: 'nonexistent-tag' }
          }
        };

        await expect(callToolHandler(request))
          .rejects.toThrow(expect.objectContaining({
            code: -32602, // InvalidParams
            message: 'Tag not found'
          }));
      });

      it('should handle 503 service unavailable error', async () => {
        mockTools.executeTool.mockRejectedValue(new Error('Guardian Intel API Error (503): Service unavailable'));

        const request = {
          params: {
            name: 'guardian_intel_lookup',
            arguments: { ip: '1.2.3.4' }
          }
        };

        await expect(callToolHandler(request))
          .rejects.toThrow(expect.objectContaining({
            code: -32603, // InternalError
            message: 'Guardian Intel service temporarily unavailable'
          }));
      });

      it('should handle timeout error', async () => {
        mockTools.executeTool.mockRejectedValue(new Error('Request timeout'));

        const request = {
          params: {
            name: 'guardian_intel_lookup',
            arguments: { ip: '1.2.3.4' }
          }
        };

        await expect(callToolHandler(request))
          .rejects.toThrow(expect.objectContaining({
            code: -32603, // InternalError
            message: 'Request timeout - Guardian Intel API is not responding'
          }));
      });

      it('should handle connection error', async () => {
        mockTools.executeTool.mockRejectedValue(new Error('Unable to connect to Guardian Intel API'));

        const request = {
          params: {
            name: 'guardian_intel_lookup',
            arguments: { ip: '1.2.3.4' }
          }
        };

        await expect(callToolHandler(request))
          .rejects.toThrow(expect.objectContaining({
            code: -32603, // InternalError
            message: 'Unable to connect to Guardian Intel API'
          }));
      });

      it('should handle generic errors', async () => {
        mockTools.executeTool.mockRejectedValue(new Error('Some other error'));

        const request = {
          params: {
            name: 'guardian_intel_lookup',
            arguments: { ip: '1.2.3.4' }
          }
        };

        await expect(callToolHandler(request))
          .rejects.toThrow(expect.objectContaining({
            code: -32603, // InternalError
            message: 'Tool execution failed: Some other error'
          }));
      });

      it('should handle non-Error exceptions', async () => {
        mockTools.executeTool.mockRejectedValue('String error');

        const request = {
          params: {
            name: 'guardian_intel_lookup',
            arguments: { ip: '1.2.3.4' }
          }
        };

        await expect(callToolHandler(request))
          .rejects.toThrow(expect.objectContaining({
            code: -32603, // InternalError
            message: 'Tool execution failed: String error'
          }));
      });
    });
  });

  describe('run method', () => {
    let server: any;

    beforeEach(() => {
      server = new GuardianIntelMcpServer();
    });

    it('should perform health check and connect to transport', async () => {
      mockClient.healthCheck.mockResolvedValue(true);
      
      // Mock StdioServerTransport
      const mockTransport = {};
      jest.doMock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
        StdioServerTransport: jest.fn().mockImplementation(() => mockTransport)
      }));

      await server.run();

      expect(mockClient.healthCheck).toHaveBeenCalled();
      expect(mockServer.connect).toHaveBeenCalledWith(mockTransport);
    });

    it('should handle health check failure gracefully', async () => {
      mockClient.healthCheck.mockResolvedValue(false);
      
      const mockTransport = {};
      jest.doMock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
        StdioServerTransport: jest.fn().mockImplementation(() => mockTransport)
      }));

      await server.run();

      expect(mockClient.healthCheck).toHaveBeenCalled();
      expect(mockServer.connect).toHaveBeenCalled();
    });

    it('should handle health check error gracefully', async () => {
      mockClient.healthCheck.mockRejectedValue(new Error('Health check failed'));
      
      const mockTransport = {};
      jest.doMock('@modelcontextprotocol/sdk/server/stdio.js', () => ({
        StdioServerTransport: jest.fn().mockImplementation(() => mockTransport)
      }));

      await server.run();

      expect(mockClient.healthCheck).toHaveBeenCalled();
      expect(mockServer.connect).toHaveBeenCalled();
    });
  });
});