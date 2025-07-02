// Global test setup
import { jest } from '@jest/globals';

// Mock environment variables for testing
process.env.NODE_ENV = 'test';

// Global timeout for all tests
jest.setTimeout(10000);

// Mock console methods to reduce noise in tests
const originalConsoleError = console.error;
const originalConsoleLog = console.log;

beforeEach(() => {
  // Restore original console methods before each test
  console.error = originalConsoleError;
  console.log = originalConsoleLog;
});

// Helper to suppress console output in tests
export const suppressConsole = () => {
  console.error = jest.fn();
  console.log = jest.fn();
};

// Helper to restore console output
export const restoreConsole = () => {
  console.error = originalConsoleError;
  console.log = originalConsoleLog;
};