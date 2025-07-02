import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { spawn } from 'child_process';
import { Command } from 'commander';
import { suppressConsole, restoreConsole } from './setup.js';

// Mock dependencies
jest.mock('child_process');
jest.mock('commander');

const mockSpawn = spawn as jest.MockedFunction<typeof spawn>;
const MockedCommand = Command as jest.MockedClass<typeof Command>;

describe('CLI', () => {
  let mockProgram: any;
  let mockProcess: any;
  let originalEnv: NodeJS.ProcessEnv;
  let originalArgv: string[];
  let originalExit: typeof process.exit;

  beforeEach(() => {
    // Save original state
    originalEnv = process.env;
    originalArgv = process.argv;
    originalExit = process.exit;
    
    // Reset mocks
    jest.clearAllMocks();
    suppressConsole();

    // Mock process.exit
    process.exit = jest.fn() as any;

    // Create mock program
    mockProgram = {
      name: jest.fn().mockReturnThis(),
      description: jest.fn().mockReturnThis(),
      version: jest.fn().mockReturnThis(),
      option: jest.fn().mockReturnThis(),
      action: jest.fn().mockReturnThis(),
      parse: jest.fn()
    };

    MockedCommand.mockImplementation(() => mockProgram);

    // Mock child process
    mockProcess = {
      on: jest.fn(),
      kill: jest.fn()
    };

    mockSpawn.mockReturnValue(mockProcess as any);

    // Reset environment
    process.env = { ...originalEnv };
    process.argv = ['node', 'cli.js'];
  });

  afterEach(() => {
    // Restore original state
    process.env = originalEnv;
    process.argv = originalArgv;
    process.exit = originalExit;
    restoreConsole();
    jest.restoreAllMocks();
  });

  describe('CLI configuration', () => {
    beforeEach(async () => {
      // Import the CLI module to trigger setup
      await import('../src/cli.js');
    });

    it('should configure program with correct metadata', () => {
      expect(mockProgram.name).toHaveBeenCalledWith('guardian-intel-mcp-server');
      expect(mockProgram.description).toHaveBeenCalledWith('Abusix Guardian Intel MCP Server - Threat intelligence for AI assistants');
      expect(mockProgram.version).toHaveBeenCalledWith('1.0.0');
    });

    it('should configure all CLI options', () => {
      expect(mockProgram.option).toHaveBeenCalledWith('--api-key <key>', 'Abusix Guardian Intel API key (can also use ABUSIX_API_KEY env var)');
      expect(mockProgram.option).toHaveBeenCalledWith('--base-url <url>', 'Base URL for Guardian Intel API (default: https://threat-intel-api.abusix.com/beta)');
      expect(mockProgram.option).toHaveBeenCalledWith('--debug', 'Enable debug logging');
      expect(mockProgram.option).toHaveBeenCalledWith('--help-usage', 'Show detailed usage examples');
    });

    it('should set up action handler', () => {
      expect(mockProgram.action).toHaveBeenCalledWith(expect.any(Function));
    });

    it('should call parse method', () => {
      expect(mockProgram.parse).toHaveBeenCalled();
    });
  });

  describe('action handler', () => {
    let actionHandler: any;

    beforeEach(async () => {
      await import('../src/cli.js');
      
      // Get the action handler
      const actionCall = mockProgram.action.mock.calls[0];
      actionHandler = actionCall[0];
    });

    it('should show usage examples when --help-usage is provided', async () => {
      const options = { helpUsage: true };
      
      await actionHandler(options);
      
      // Should not spawn a process
      expect(mockSpawn).not.toHaveBeenCalled();
    });

    it('should exit with error when no API key is provided', async () => {
      const options = {};
      delete process.env.ABUSIX_API_KEY;
      
      await actionHandler(options);
      
      expect(process.exit).toHaveBeenCalledWith(1);
      expect(mockSpawn).not.toHaveBeenCalled();
    });

    it('should use API key from command line option', async () => {
      const options = { apiKey: 'cli-api-key' };
      
      await actionHandler(options);
      
      expect(mockSpawn).toHaveBeenCalledWith('node', expect.any(Array), {
        env: expect.objectContaining({
          ABUSIX_API_KEY: 'cli-api-key'
        }),
        stdio: 'inherit'
      });
    });

    it('should use API key from environment variable', async () => {
      const options = {};
      process.env.ABUSIX_API_KEY = 'env-api-key';
      
      await actionHandler(options);
      
      expect(mockSpawn).toHaveBeenCalledWith('node', expect.any(Array), {
        env: expect.objectContaining({
          ABUSIX_API_KEY: 'env-api-key'
        }),
        stdio: 'inherit'
      });
    });

    it('should prioritize command line API key over environment', async () => {
      const options = { apiKey: 'cli-api-key' };
      process.env.ABUSIX_API_KEY = 'env-api-key';
      
      await actionHandler(options);
      
      expect(mockSpawn).toHaveBeenCalledWith('node', expect.any(Array), {
        env: expect.objectContaining({
          ABUSIX_API_KEY: 'cli-api-key'
        }),
        stdio: 'inherit'
      });
    });

    it('should set custom base URL when provided', async () => {
      const options = { 
        apiKey: 'test-key',
        baseUrl: 'https://custom-api.example.com'
      };
      
      await actionHandler(options);
      
      expect(mockSpawn).toHaveBeenCalledWith('node', expect.any(Array), {
        env: expect.objectContaining({
          ABUSIX_API_KEY: 'test-key',
          ABUSIX_BASE_URL: 'https://custom-api.example.com'
        }),
        stdio: 'inherit'
      });
    });

    it('should enable debug mode when requested', async () => {
      const options = { 
        apiKey: 'test-key',
        debug: true
      };
      
      await actionHandler(options);
      
      expect(mockSpawn).toHaveBeenCalledWith('node', expect.any(Array), {
        env: expect.objectContaining({
          ABUSIX_API_KEY: 'test-key',
          DEBUG: '1'
        }),
        stdio: 'inherit'
      });
    });

    it('should spawn server process with correct parameters', async () => {
      const options = { apiKey: 'test-key' };
      
      await actionHandler(options);
      
      expect(mockSpawn).toHaveBeenCalledWith('node', expect.arrayContaining([
        expect.stringMatching(/index\.js$/)
      ]), {
        env: expect.objectContaining({
          ABUSIX_API_KEY: 'test-key'
        }),
        stdio: 'inherit'
      });
    });

    it('should set up process event handlers', async () => {
      const options = { apiKey: 'test-key' };
      
      await actionHandler(options);
      
      expect(mockProcess.on).toHaveBeenCalledWith('error', expect.any(Function));
      expect(mockProcess.on).toHaveBeenCalledWith('exit', expect.any(Function));
    });

    it('should handle spawn error', async () => {
      const options = { apiKey: 'test-key' };
      
      await actionHandler(options);
      
      // Get the error handler
      const errorCall = mockProcess.on.mock.calls.find(call => call[0] === 'error');
      const errorHandler = errorCall[1];
      
      // Simulate error
      errorHandler(new Error('Spawn failed'));
      
      expect(process.exit).toHaveBeenCalledWith(1);
    });

    it('should handle non-zero exit code', async () => {
      const options = { apiKey: 'test-key' };
      
      await actionHandler(options);
      
      // Get the exit handler
      const exitCall = mockProcess.on.mock.calls.find(call => call[0] === 'exit');
      const exitHandler = exitCall[1];
      
      // Simulate non-zero exit
      exitHandler(1);
      
      expect(process.exit).toHaveBeenCalledWith(1);
    });

    it('should handle zero exit code gracefully', async () => {
      const options = { apiKey: 'test-key' };
      
      await actionHandler(options);
      
      // Get the exit handler
      const exitCall = mockProcess.on.mock.calls.find(call => call[0] === 'exit');
      const exitHandler = exitCall[1];
      
      // Simulate zero exit
      exitHandler(0);
      
      // Should not call process.exit for successful termination
      expect(process.exit).not.toHaveBeenCalled();
    });
  });

  describe('signal handling', () => {
    let actionHandler: any;

    beforeEach(async () => {
      await import('../src/cli.js');
      
      const actionCall = mockProgram.action.mock.calls[0];
      actionHandler = actionCall[0];
    });

    it('should set up SIGINT handler', async () => {
      const options = { apiKey: 'test-key' };
      
      // Mock process.on for the main process
      const originalProcessOn = process.on;
      const mockProcessOn = jest.fn();
      process.on = mockProcessOn as any;
      
      await actionHandler(options);
      
      expect(mockProcessOn).toHaveBeenCalledWith('SIGINT', expect.any(Function));
      
      // Restore
      process.on = originalProcessOn;
    });

    it('should set up SIGTERM handler', async () => {
      const options = { apiKey: 'test-key' };
      
      // Mock process.on for the main process
      const originalProcessOn = process.on;
      const mockProcessOn = jest.fn();
      process.on = mockProcessOn as any;
      
      await actionHandler(options);
      
      expect(mockProcessOn).toHaveBeenCalledWith('SIGTERM', expect.any(Function));
      
      // Restore
      process.on = originalProcessOn;
    });

    it('should kill child process on SIGINT', async () => {
      const options = { apiKey: 'test-key' };
      
      const originalProcessOn = process.on;
      const mockProcessOn = jest.fn();
      process.on = mockProcessOn as any;
      
      await actionHandler(options);
      
      // Get the SIGINT handler
      const sigintCall = mockProcessOn.mock.calls.find(call => call[0] === 'SIGINT');
      const sigintHandler = sigintCall[1];
      
      // Simulate SIGINT
      sigintHandler();
      
      expect(mockProcess.kill).toHaveBeenCalledWith('SIGINT');
      
      // Restore
      process.on = originalProcessOn;
    });

    it('should kill child process on SIGTERM', async () => {
      const options = { apiKey: 'test-key' };
      
      const originalProcessOn = process.on;
      const mockProcessOn = jest.fn();
      process.on = mockProcessOn as any;
      
      await actionHandler(options);
      
      // Get the SIGTERM handler
      const sigtermCall = mockProcessOn.mock.calls.find(call => call[0] === 'SIGTERM');
      const sigtermHandler = sigtermCall[1];
      
      // Simulate SIGTERM
      sigtermHandler();
      
      expect(mockProcess.kill).toHaveBeenCalledWith('SIGTERM');
      
      // Restore
      process.on = originalProcessOn;
    });
  });
});