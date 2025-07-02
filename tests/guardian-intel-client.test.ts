import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import axios from 'axios';
import { GuardianIntelClient } from '../src/guardian-intel-client';

// Mock axios
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('GuardianIntelClient', () => {
  let client: GuardianIntelClient;
  let mockAxiosInstance: any;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();
    
    // Create mock axios instance
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
      apiKey: 'test-api-key',
      baseUrl: 'https://test-api.example.com'
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('constructor', () => {
    it('should create axios instance with proper configuration', () => {
      expect(mockedAxios.create).toHaveBeenCalledWith({
        baseURL: 'https://test-api.example.com',
        headers: {
          'Authorization': 'Bearer test-api-key',
          'Content-Type': 'application/json',
          'User-Agent': '@abusix/guardian-intel-mcp-server/1.0.0'
        },
        timeout: 30000
      });
    });

    it('should use default base URL when not provided', () => {
      new GuardianIntelClient({ apiKey: 'test-key' });
      
      expect(mockedAxios.create).toHaveBeenCalledWith(
        expect.objectContaining({
          baseURL: 'https://threat-intel-api.abusix.com/beta'
        })
      );
    });
  });

  describe('lookupIp', () => {
    const mockLookupResponse = {
      data: {
        status: 'success',
        statusCode: 200,
        result: {
          ip: '1.2.3.4',
          classification: 'malicious',
          firstSeen: '2023-01-01T00:00:00Z',
          lastSeen: '2023-12-31T23:59:59Z',
          abuseContact: 'abuse@example.com',
          asn: {
            number: 12345,
            name: 'Test ASN',
            country: 'US'
          },
          blocklists: ['blocklist1', 'blocklist2'],
          activities: [
            {
              type: 'malware',
              description: 'Malware distribution',
              timestamp: '2023-06-15T12:00:00Z',
              severity: 'high'
            }
          ]
        }
      }
    };

    it('should successfully lookup valid IPv4 address', async () => {
      mockAxiosInstance.get.mockResolvedValue(mockLookupResponse);

      const result = await client.lookupIp('1.2.3.4');

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/query/1.2.3.4');
      expect(result).toEqual(mockLookupResponse.data);
    });

    it('should successfully lookup valid IPv6 address', async () => {
      const ipv6Response = {
        ...mockLookupResponse,
        data: {
          ...mockLookupResponse.data,
          result: {
            ...mockLookupResponse.data.result,
            ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
          }
        }
      };
      
      mockAxiosInstance.get.mockResolvedValue(ipv6Response);

      const result = await client.lookupIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334');

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/query/2001%3A0db8%3A85a3%3A0000%3A0000%3A8a2e%3A0370%3A7334');
      expect(result).toEqual(ipv6Response.data);
    });

    it('should reject invalid IP address format', async () => {
      await expect(client.lookupIp('invalid-ip')).rejects.toThrow('Invalid IP address format');
      expect(mockAxiosInstance.get).not.toHaveBeenCalled();
    });

    it('should reject empty IP address', async () => {
      await expect(client.lookupIp('')).rejects.toThrow('Invalid IP address format');
      expect(mockAxiosInstance.get).not.toHaveBeenCalled();
    });

    it('should handle API errors properly', async () => {
      const apiError = new Error('API Error');
      mockAxiosInstance.get.mockRejectedValue(apiError);

      await expect(client.lookupIp('1.2.3.4')).rejects.toThrow('API Error');
    });
  });

  describe('getTags', () => {
    const mockTagsResponse = {
      data: {
        status: 'success',
        statusCode: 200,
        result: [
          {
            name: 'credentials:brute-force',
            intent: 'malicious',
            category: 'activity',
            description: 'Brute force credential attacks'
          },
          {
            name: 'tool:scanner',
            intent: 'suspicious',
            category: 'tool'
          }
        ]
      }
    };

    it('should get tags without descriptions', async () => {
      mockAxiosInstance.get.mockResolvedValue(mockTagsResponse);

      const result = await client.getTags(false);

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/tags', { params: {} });
      expect(result).toEqual(mockTagsResponse.data);
    });

    it('should get tags with descriptions', async () => {
      mockAxiosInstance.get.mockResolvedValue(mockTagsResponse);

      const result = await client.getTags(true);

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/tags', { 
        params: { includeDescriptions: 'true' } 
      });
      expect(result).toEqual(mockTagsResponse.data);
    });

    it('should handle API errors', async () => {
      const apiError = new Error('Tags API Error');
      mockAxiosInstance.get.mockRejectedValue(apiError);

      await expect(client.getTags()).rejects.toThrow('Tags API Error');
    });
  });

  describe('getTagDetails', () => {
    const mockTagDetailsResponse = {
      data: {
        status: 'success',
        statusCode: 200,
        result: {
          name: 'credentials:brute-force',
          intent: 'malicious',
          category: 'activity',
          description: 'Brute force credential attacks',
          references: ['https://example.com/ref1', 'https://example.com/ref2'],
          timeline: [
            {
              action: 'created',
              timestamp: '2023-01-01T00:00:00Z',
              description: 'Tag created'
            }
          ]
        }
      }
    };

    it('should get tag details successfully', async () => {
      mockAxiosInstance.get.mockResolvedValue(mockTagDetailsResponse);

      const result = await client.getTagDetails('credentials:brute-force');

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/tags/credentials%3Abrute-force');
      expect(result).toEqual(mockTagDetailsResponse.data);
    });

    it('should reject empty tag name', async () => {
      await expect(client.getTagDetails('')).rejects.toThrow('Tag name is required');
      expect(mockAxiosInstance.get).not.toHaveBeenCalled();
    });

    it('should reject whitespace-only tag name', async () => {
      await expect(client.getTagDetails('   ')).rejects.toThrow('Tag name is required');
      expect(mockAxiosInstance.get).not.toHaveBeenCalled();
    });

    it('should handle API errors', async () => {
      const apiError = new Error('Tag Details API Error');
      mockAxiosInstance.get.mockRejectedValue(apiError);

      await expect(client.getTagDetails('test-tag')).rejects.toThrow('Tag Details API Error');
    });
  });

  describe('getTagIps', () => {
    const mockTagIpsResponse = {
      data: {
        status: 'success',
        statusCode: 200,
        result: {
          tag: 'credentials:brute-force',
          entries: ['1.2.3.4', '5.6.7.8', '9.10.11.12'],
          lastUpdate: '2023-12-31T23:59:59Z',
          total: 1000,
          snapshot: 'snapshot-123'
        }
      }
    };

    it('should get tag IPs with default parameters', async () => {
      mockAxiosInstance.get.mockResolvedValue(mockTagIpsResponse);

      const result = await client.getTagIps('credentials:brute-force');

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/tags/credentials%3Abrute-force/ips', {
        params: {
          offset: '0',
          limit: '1000'
        }
      });
      expect(result).toEqual(mockTagIpsResponse.data);
    });

    it('should get tag IPs with custom parameters', async () => {
      mockAxiosInstance.get.mockResolvedValue(mockTagIpsResponse);

      const result = await client.getTagIps('test-tag', {
        offset: 100,
        limit: 500,
        snapshot: 'test-snapshot'
      });

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/tags/test-tag/ips', {
        params: {
          offset: '100',
          limit: '500',
          snapshot: 'test-snapshot'
        }
      });
      expect(result).toEqual(mockTagIpsResponse.data);
    });

    it('should reject empty tag name', async () => {
      await expect(client.getTagIps('')).rejects.toThrow('Tag name is required');
      expect(mockAxiosInstance.get).not.toHaveBeenCalled();
    });

    it('should reject limit exceeding maximum', async () => {
      await expect(client.getTagIps('test-tag', { limit: 20000 }))
        .rejects.toThrow('Limit cannot exceed 10,000');
      expect(mockAxiosInstance.get).not.toHaveBeenCalled();
    });

    it('should reject negative offset', async () => {
      await expect(client.getTagIps('test-tag', { offset: -1 }))
        .rejects.toThrow('Offset must be non-negative and limit must be positive');
      expect(mockAxiosInstance.get).not.toHaveBeenCalled();
    });

    it('should reject zero limit', async () => {
      await expect(client.getTagIps('test-tag', { limit: 0 }))
        .rejects.toThrow('Offset must be non-negative and limit must be positive');
      expect(mockAxiosInstance.get).not.toHaveBeenCalled();
    });

    it('should handle API errors', async () => {
      const apiError = new Error('Tag IPs API Error');
      mockAxiosInstance.get.mockRejectedValue(apiError);

      await expect(client.getTagIps('test-tag')).rejects.toThrow('Tag IPs API Error');
    });
  });

  describe('healthCheck', () => {
    it('should return true when API is healthy', async () => {
      mockAxiosInstance.get.mockResolvedValue({ data: { status: 'success' } });

      const result = await client.healthCheck();

      expect(result).toBe(true);
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/tags', {
        params: { limit: '1' },
        timeout: 5000
      });
    });

    it('should return false when API is unhealthy', async () => {
      mockAxiosInstance.get.mockRejectedValue(new Error('Health check failed'));

      const result = await client.healthCheck();

      expect(result).toBe(false);
    });
  });
});