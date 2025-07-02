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
          'x-api-key': 'test-api-key',
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
        result: {
          item: '1.2.3.4',
          tags: ['malware', 'botnet'],
          intent: 'malicious',
          firstSeen: '2023-01-01T00:00:00Z',
          lastSeen: '2023-12-31T23:59:59Z',
          asn: {
            asn: '12345',
            name: 'Test ASN',
            countryCode: 'US'
          },
          abuseContact: {
            email: 'abuse@example.com',
            status: 'verified',
            lastVerification: '2023-12-01T00:00:00Z'
          },
          observedActivity: {
            malware: {
              type: 'malware',
              description: 'Malware distribution',
              timestamp: '2023-06-15T12:00:00Z',
              severity: 'high'
            }
          }
        }
      }
    };

    it('should successfully lookup valid IPv4 address', async () => {
      mockAxiosInstance.get.mockResolvedValue(mockLookupResponse);

      const result = await client.lookupIp('1.2.3.4');

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/query/1.2.3.4');
      expect(result).toEqual({
        ip: '1.2.3.4',
        tags: ['malware', 'botnet'],
        confidence: 'high',
        threat_level: 'malicious',
        first_seen: '2023-01-01T00:00:00Z',
        last_seen: '2023-12-31T23:59:59Z',
        asn: {
          asn: '12345',
          name: 'Test ASN',
          countryCode: 'US'
        },
        abuse_contact: {
          email: 'abuse@example.com',
          status: 'verified',
          lastVerification: '2023-12-01T00:00:00Z'
        },
        observed_activity: {
          malware: {
            type: 'malware',
            description: 'Malware distribution',
            timestamp: '2023-06-15T12:00:00Z',
            severity: 'high'
          }
        }
      });
    });

    it('should successfully lookup valid IPv6 address', async () => {
      const ipv6Response = {
        ...mockLookupResponse,
        data: {
          ...mockLookupResponse.data,
          result: {
            ...mockLookupResponse.data.result,
            item: '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
          }
        }
      };
      
      mockAxiosInstance.get.mockResolvedValue(ipv6Response);

      const result = await client.lookupIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334');

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/query/2001%3A0db8%3A85a3%3A0000%3A0000%3A8a2e%3A0370%3A7334');
      expect(result).toEqual({
        ip: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        tags: ['malware', 'botnet'],
        confidence: 'high',
        threat_level: 'malicious',
        first_seen: '2023-01-01T00:00:00Z',
        last_seen: '2023-12-31T23:59:59Z',
        asn: {
          asn: '12345',
          name: 'Test ASN',
          countryCode: 'US'
        },
        abuse_contact: {
          email: 'abuse@example.com',
          status: 'verified',
          lastVerification: '2023-12-01T00:00:00Z'
        },
        observed_activity: {
          malware: {
            type: 'malware',
            description: 'Malware distribution',
            timestamp: '2023-06-15T12:00:00Z',
            severity: 'high'
          }
        }
      });
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
      expect(result).toEqual({
        tags: ['credentials:brute-force', 'tool:scanner'],
        tag_details: undefined
      });
    });

    it('should get tags with descriptions', async () => {
      mockAxiosInstance.get.mockResolvedValue(mockTagsResponse);

      const result = await client.getTags(true);

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/tags', { 
        params: { includeDescriptions: 'true' } 
      });
      expect(result).toEqual({
        tags: ['credentials:brute-force', 'tool:scanner'],
        tag_details: [
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
      });
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
        result: {
          name: 'credentials:brute-force',
          description: 'Brute force credential attacks',
          category: 'activity',
          intent: 'malicious'
        }
      }
    };

    it('should get tag details successfully', async () => {
      mockAxiosInstance.get.mockResolvedValue(mockTagDetailsResponse);

      const result = await client.getTagDetails('credentials:brute-force');

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/tags/credentials%3Abrute-force');
      expect(result).toEqual({
        tag: 'credentials:brute-force',
        description: 'Brute force credential attacks',
        category: 'activity',
        confidence: 'high',
        intent: 'malicious'
      });
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
        result: {
          tag: 'credentials:brute-force',
          entries: ['1.2.3.4', '5.6.7.8', '9.10.11.12'],
          total: 1000,
          offset: 0,
          limit: 1000
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
      expect(result).toEqual({
        tag: 'credentials:brute-force',
        total: 1000,
        offset: 0,
        limit: 1000,
        ips: ['1.2.3.4', '5.6.7.8', '9.10.11.12']
      });
    });

    it('should get tag IPs with custom parameters', async () => {
      const customMockResponse = {
        data: {
          result: {
            tag: 'test-tag',
            entries: ['1.2.3.4', '5.6.7.8', '9.10.11.12'],
            total: 1000,
            offset: 100,
            limit: 500
          }
        }
      };
      mockAxiosInstance.get.mockResolvedValue(customMockResponse);

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
      expect(result).toEqual({
        tag: 'test-tag',
        total: 1000,
        offset: 100,
        limit: 500,
        ips: ['1.2.3.4', '5.6.7.8', '9.10.11.12']
      });
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