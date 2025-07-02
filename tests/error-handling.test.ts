import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import axios, { AxiosError } from 'axios';
import { GuardianIntelClient } from '../src/guardian-intel-client';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe.skip('Error Handling and Edge Cases', () => {
  let client: GuardianIntelClient;
  let mockAxiosInstance: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockAxiosInstance = {
      get: jest.fn(),
      interceptors: {
        response: {
          use: jest.fn()
        }
      }
    };
    
    mockedAxios.create.mockReturnValue(mockAxiosInstance);
    
    client = new GuardianIntelClient({
      apiKey: 'test-api-key'
    });
  });

  describe('Network and Connection Errors', () => {
    it('should handle connection timeout', async () => {
      const timeoutError = {
        message: 'timeout of 30000ms exceeded',
        name: 'Error',
        code: 'ECONNABORTED'
      } as any;
      
      mockAxiosInstance.get.mockRejectedValue(timeoutError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Guardian Intel API request timeout');
    });

    it('should handle connection refused', async () => {
      const connectionError = {
        message: 'connect ECONNREFUSED',
        name: 'Error',
        code: 'ECONNREFUSED'
      } as any;
      
      mockAxiosInstance.get.mockRejectedValue(connectionError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Unable to connect to Guardian Intel API');
    });

    it('should handle DNS resolution failure', async () => {
      const dnsError = {
        message: 'getaddrinfo ENOTFOUND',
        name: 'Error',
        code: 'ENOTFOUND'
      } as any;
      
      mockAxiosInstance.get.mockRejectedValue(dnsError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Unable to connect to Guardian Intel API');
    });

    it('should handle generic network errors', async () => {
      const networkError = {
        message: 'Network error',
        name: 'Error'
      } as any;
      
      mockAxiosInstance.get.mockRejectedValue(networkError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Guardian Intel API Error: Network error');
    });
  });

  describe('HTTP Status Code Errors', () => {
    it('should handle 400 Bad Request', async () => {
      const axiosError = {
        message: 'Request failed with status code 400',
        name: 'AxiosError',
        response: {
          status: 400,
          statusText: 'Bad Request',
          data: {
            status: 'error',
            statusCode: 400,
            message: 'Invalid IP address format'
          }
        }
      } as AxiosError;
      
      mockAxiosInstance.get.mockRejectedValue(axiosError);

      await expect(client.lookupIp('192.168.1.1'))
        .rejects.toThrow('Guardian Intel API Error (400): Invalid IP address format');
    });

    it('should handle 401 Unauthorized', async () => {
      const axiosError = {
        response: {
          status: 401,
          data: {
            status: 'error',
            statusCode: 401,
            message: 'Invalid API key'
          }
        }
      } as AxiosError;
      
      mockAxiosInstance.get.mockRejectedValue(axiosError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Guardian Intel API Error (401): Invalid API key');
    });

    it('should handle 403 Forbidden', async () => {
      const axiosError = {
        response: {
          status: 403,
          data: {
            status: 'error',
            statusCode: 403,
            message: 'API key does not have required permissions'
          }
        }
      } as AxiosError;
      
      mockAxiosInstance.get.mockRejectedValue(axiosError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Guardian Intel API Error (403): API key does not have required permissions');
    });

    it('should handle 404 Not Found', async () => {
      const axiosError = {
        response: {
          status: 404,
          data: {
            status: 'error',
            statusCode: 404,
            message: 'Tag not found'
          }
        }
      } as AxiosError;
      
      mockAxiosInstance.get.mockRejectedValue(axiosError);

      await expect(client.getTagDetails('nonexistent-tag'))
        .rejects.toThrow('Guardian Intel API Error (404): Tag not found');
    });

    it('should handle 429 Rate Limit Exceeded', async () => {
      const axiosError = {
        response: {
          status: 429,
          data: {
            status: 'error',
            statusCode: 429,
            message: 'Rate limit exceeded'
          }
        }
      } as AxiosError;
      
      mockAxiosInstance.get.mockRejectedValue(axiosError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Guardian Intel API Error (429): Rate limit exceeded');
    });

    it('should handle 500 Internal Server Error', async () => {
      const axiosError = {
        response: {
          status: 500,
          data: {
            status: 'error',
            statusCode: 500,
            message: 'Internal server error'
          }
        }
      } as AxiosError;
      
      mockAxiosInstance.get.mockRejectedValue(axiosError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Guardian Intel API Error (500): Internal server error');
    });

    it('should handle 503 Service Unavailable', async () => {
      const axiosError = {
        response: {
          status: 503,
          data: {
            status: 'error',
            statusCode: 503,
            message: 'Service temporarily unavailable'
          }
        }
      } as AxiosError;
      
      mockAxiosInstance.get.mockRejectedValue(axiosError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Guardian Intel API Error (503): Service temporarily unavailable');
    });
  });

  describe('Malformed Response Handling', () => {
    it('should handle response without error details', async () => {
      const axiosError = {
        response: {
          status: 500,
          data: 'Internal Server Error'
        }
      } as AxiosError;
      
      mockAxiosInstance.get.mockRejectedValue(axiosError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Guardian Intel API Error: Request failed with status code 500');
    });

    it('should handle empty response', async () => {
      const axiosError = {
        response: {
          status: 500,
          data: null
        }
      } as AxiosError;
      
      mockAxiosInstance.get.mockRejectedValue(axiosError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Guardian Intel API Error: Request failed with status code 500');
    });

    it('should handle response with unexpected format', async () => {
      const axiosError = {
        response: {
          status: 400,
          data: {
            unexpected: 'format'
          }
        }
      } as AxiosError;
      
      mockAxiosInstance.get.mockRejectedValue(axiosError);

      await expect(client.lookupIp('1.2.3.4'))
        .rejects.toThrow('Guardian Intel API Error: Request failed with status code 400');
    });
  });

  describe('Input Validation Edge Cases', () => {
    describe('IP Address Validation', () => {
      it('should reject empty string', async () => {
        await expect(client.lookupIp(''))
          .rejects.toThrow('Invalid IP address format');
      });

      it('should reject whitespace only', async () => {
        await expect(client.lookupIp('   '))
          .rejects.toThrow('Invalid IP address format');
      });

      it('should reject null as string', async () => {
        await expect(client.lookupIp('null'))
          .rejects.toThrow('Invalid IP address format');
      });

      it('should reject undefined as string', async () => {
        await expect(client.lookupIp('undefined'))
          .rejects.toThrow('Invalid IP address format');
      });

      it('should reject IP with leading zeros', async () => {
        await expect(client.lookupIp('192.168.001.001'))
          .rejects.toThrow('Invalid IP address format');
      });

      it('should reject IP with values > 255', async () => {
        await expect(client.lookupIp('192.168.1.256'))
          .rejects.toThrow('Invalid IP address format');
      });

      it('should reject IPv6 with invalid format', async () => {
        await expect(client.lookupIp('2001:0db8:85a3::8a2e::7334'))
          .rejects.toThrow('Invalid IP address format');
      });

      it('should reject hostname instead of IP', async () => {
        await expect(client.lookupIp('example.com'))
          .rejects.toThrow('Invalid IP address format');
      });

      it('should reject CIDR notation', async () => {
        await expect(client.lookupIp('192.168.1.0/24'))
          .rejects.toThrow('Invalid IP address format');
      });
    });

    describe('Tag Name Validation', () => {
      it('should reject empty tag name in getTagDetails', async () => {
        await expect(client.getTagDetails(''))
          .rejects.toThrow('Tag name is required');
      });

      it('should reject whitespace-only tag name in getTagDetails', async () => {
        await expect(client.getTagDetails('   '))
          .rejects.toThrow('Tag name is required');
      });

      it('should reject empty tag name in getTagIps', async () => {
        await expect(client.getTagIps(''))
          .rejects.toThrow('Tag name is required');
      });

      it('should reject whitespace-only tag name in getTagIps', async () => {
        await expect(client.getTagIps('   '))
          .rejects.toThrow('Tag name is required');
      });
    });

    describe('Pagination Parameter Validation', () => {
      it('should reject negative offset', async () => {
        await expect(client.getTagIps('test-tag', { offset: -1 }))
          .rejects.toThrow('Offset must be non-negative and limit must be positive');
      });

      it('should reject zero limit', async () => {
        await expect(client.getTagIps('test-tag', { limit: 0 }))
          .rejects.toThrow('Offset must be non-negative and limit must be positive');
      });

      it('should reject negative limit', async () => {
        await expect(client.getTagIps('test-tag', { limit: -1 }))
          .rejects.toThrow('Offset must be non-negative and limit must be positive');
      });

      it('should reject limit exceeding maximum', async () => {
        await expect(client.getTagIps('test-tag', { limit: 10001 }))
          .rejects.toThrow('Limit cannot exceed 10,000');
      });

      it('should accept maximum limit', async () => {
        mockAxiosInstance.get.mockResolvedValue({
          data: {
            result: {
              tag: 'test-tag',
              entries: [],
              total: 0,
              offset: 0,
              limit: 10000
            }
          }
        });

        await expect(client.getTagIps('test-tag', { limit: 10000 }))
          .resolves.toBeDefined();
      });

      it('should accept fractional numbers as integers', async () => {
        mockAxiosInstance.get.mockResolvedValue({
          data: {
            result: {
              tag: 'test-tag',
              entries: [],
              total: 0,
              offset: 5,
              limit: 100
            }
          }
        });

        // JavaScript will truncate these to integers
        await expect(client.getTagIps('test-tag', { offset: 5.7, limit: 100.9 }))
          .resolves.toBeDefined();
      });
    });
  });

  describe('Edge Case Data Handling', () => {
    it('should handle API response with missing optional fields', async () => {
      const minimalResponse = {
        data: {
          result: {
            item: '1.2.3.4',
            intent: 'unknown'
            // Missing all optional fields
          }
        }
      };

      mockAxiosInstance.get.mockResolvedValue(minimalResponse);

      const result = await client.lookupIp('1.2.3.4');
      
      expect(result.ip).toBe('1.2.3.4');
      expect(result.confidence).toBe('low');
      expect(result.first_seen).toBeUndefined();
      expect(result.last_seen).toBeUndefined();
      expect(result.abuse_contact).toBeUndefined();
      expect(result.asn).toBeUndefined();
      expect(result.tags).toBeUndefined();
      expect(result.observed_activity).toBeUndefined();
    });

    it('should handle empty arrays in response', async () => {
      const emptyArrayResponse = {
        data: {
          result: {
            item: '1.2.3.4',
            intent: 'unknown',
            tags: [],
            observedActivity: {}
          }
        }
      };

      mockAxiosInstance.get.mockResolvedValue(emptyArrayResponse);

      const result = await client.lookupIp('1.2.3.4');
      
      expect(result.tags).toEqual([]);
      expect(result.observed_activity).toEqual({});
    });

    it('should handle tags response with empty result array', async () => {
      const emptyTagsResponse = {
        data: {
          result: []
        }
      };

      mockAxiosInstance.get.mockResolvedValue(emptyTagsResponse);

      const result = await client.getTags();
      
      expect(result.tags).toEqual([]);
    });

    it('should handle tag IPs response with empty entries', async () => {
      const emptyIpsResponse = {
        data: {
          result: {
            tag: 'test-tag',
            entries: [],
            total: 0,
            offset: 0,
            limit: 1000
          }
        }
      };

      mockAxiosInstance.get.mockResolvedValue(emptyIpsResponse);

      const result = await client.getTagIps('test-tag');
      
      expect(result.ips).toEqual([]);
      expect(result.total).toBe(0);
    });

    it('should handle Unicode characters in tag names', async () => {
      const unicodeResponse = {
        data: {
          result: {
            name: 'test-tag-🔒',
            intent: 'malicious',
            category: 'activity',
            description: 'Unicode test tag'
          }
        }
      };

      mockAxiosInstance.get.mockResolvedValue(unicodeResponse);

      const result = await client.getTagDetails('test-tag-🔒');
      
      expect(result.tag).toBe('test-tag-🔒');
    });

    it('should handle very long tag names', async () => {
      const longTagName = 'a'.repeat(1000);
      const longTagResponse = {
        data: {
          result: {
            name: longTagName,
            intent: 'malicious',
            category: 'activity',
            description: 'Very long tag name'
          }
        }
      };

      mockAxiosInstance.get.mockResolvedValue(longTagResponse);

      const result = await client.getTagDetails(longTagName);
      
      expect(result.tag).toBe(longTagName);
    });
  });

  describe('Concurrent Request Handling', () => {
    it('should handle multiple concurrent requests', async () => {
      mockAxiosInstance.get.mockResolvedValue({
        data: {
          result: {
            item: '1.2.3.4',
            intent: 'unknown'
          }
        }
      });

      const promises = Array.from({ length: 10 }, (_, i) => 
        client.lookupIp(`1.2.3.${i + 1}`)
      );

      const results = await Promise.all(promises);
      
      expect(results).toHaveLength(10);
      expect(mockAxiosInstance.get).toHaveBeenCalledTimes(10);
    });

    it('should handle mixed success and failure in concurrent requests', async () => {
      mockAxiosInstance.get
        .mockResolvedValueOnce({
          data: { result: { item: '1.2.3.1', intent: 'unknown' } }
        })
        .mockRejectedValueOnce(new Error('API Error'))
        .mockResolvedValueOnce({
          data: { result: { item: '1.2.3.3', intent: 'unknown' } }
        });

      const promises = [
        client.lookupIp('1.2.3.1'),
        client.lookupIp('1.2.3.2'),
        client.lookupIp('1.2.3.3')
      ];

      const results = await Promise.allSettled(promises);
      
      expect(results[0].status).toBe('fulfilled');
      expect(results[1].status).toBe('rejected');
      expect(results[2].status).toBe('fulfilled');
    });
  });
});