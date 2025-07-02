import { jest, describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { GuardianIntelTools } from '../src/tools';
import { GuardianIntelClient } from '../src/guardian-intel-client';

// Mock the GuardianIntelClient
jest.mock('../src/guardian-intel-client');
const MockedGuardianIntelClient = GuardianIntelClient as jest.MockedClass<typeof GuardianIntelClient>;

describe('GuardianIntelTools', () => {
  let tools: GuardianIntelTools;
  let mockClient: jest.Mocked<GuardianIntelClient>;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockClient = new MockedGuardianIntelClient({
      apiKey: 'test-key'
    }) as jest.Mocked<GuardianIntelClient>;
    
    tools = new GuardianIntelTools(mockClient);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('getToolDefinitions', () => {
    it('should return all 4 tool definitions', () => {
      const definitions = tools.getToolDefinitions();
      
      expect(definitions).toHaveLength(4);
      expect(definitions.map(t => t.name)).toEqual([
        'guardian_intel_lookup',
        'guardian_intel_tags_list',
        'guardian_intel_tag_details',
        'guardian_intel_tag_ips'
      ]);
    });

    it('should have proper schema for lookup tool', () => {
      const definitions = tools.getToolDefinitions();
      const lookupTool = definitions.find(t => t.name === 'guardian_intel_lookup');
      
      expect(lookupTool).toBeDefined();
      expect(lookupTool!.inputSchema.properties?.ip).toBeDefined();
      expect(lookupTool!.inputSchema.required).toContain('ip');
    });

    it('should have proper schema for tags list tool', () => {
      const definitions = tools.getToolDefinitions();
      const tagsListTool = definitions.find(t => t.name === 'guardian_intel_tags_list');
      
      expect(tagsListTool).toBeDefined();
      expect(tagsListTool!.inputSchema.properties?.includeDescriptions).toBeDefined();
    });

    it('should have proper schema for tag details tool', () => {
      const definitions = tools.getToolDefinitions();
      const tagDetailsTool = definitions.find(t => t.name === 'guardian_intel_tag_details');
      
      expect(tagDetailsTool).toBeDefined();
      expect(tagDetailsTool!.inputSchema.properties?.tagName).toBeDefined();
      expect(tagDetailsTool!.inputSchema.required).toContain('tagName');
    });

    it('should have proper schema for tag IPs tool', () => {
      const definitions = tools.getToolDefinitions();
      const tagIpsTool = definitions.find(t => t.name === 'guardian_intel_tag_ips');
      
      expect(tagIpsTool).toBeDefined();
      expect(tagIpsTool!.inputSchema.properties?.tagName).toBeDefined();
      expect(tagIpsTool!.inputSchema.properties?.offset).toBeDefined();
      expect(tagIpsTool!.inputSchema.properties?.limit).toBeDefined();
      expect(tagIpsTool!.inputSchema.required).toContain('tagName');
    });
  });

  describe('executeTool', () => {
    describe('guardian_intel_lookup', () => {
      const mockLookupResponse = {
        ip: '1.2.3.4',
        tags: ['malware', 'botnet'],
        threat_level: 'HIGH',
        confidence: 'high',
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
      };

      it('should execute IP lookup successfully', async () => {
        mockClient.lookupIp.mockResolvedValue(mockLookupResponse as any);

        const result = await tools.executeTool('guardian_intel_lookup', { ip: '1.2.3.4' });

        expect(mockClient.lookupIp).toHaveBeenCalledWith('1.2.3.4');
        expect(result).toEqual({
          ip: '1.2.3.4',
          tags: ['malware', 'botnet'],
          threat_level: 'HIGH',
          confidence: 'high',
          first_seen: '2023-01-01T00:00:00Z',
          last_seen: '2023-12-31T23:59:59Z',
          abuse_contact: 'abuse@example.com',
          asn: {
            number: '12345',
            name: 'Test ASN',
            country: 'US'
          },
          observed_activity: {
            malware: {
              type: 'malware',
              description: 'Malware distribution',
              timestamp: '2023-06-15T12:00:00Z',
              severity: 'high'
            }
          },
          summary: expect.stringContaining('IP threat level: HIGH')
        });
      });

      it('should handle suspicious classification', async () => {
        const suspiciousResponse = {
          ...mockLookupResponse,
          threat_level: 'MEDIUM'
        };
        mockClient.lookupIp.mockResolvedValue(suspiciousResponse as any);

        const result = await tools.executeTool('guardian_intel_lookup', { ip: '1.2.3.4' });

        expect(result.threat_level).toBe('MEDIUM');
      });

      it('should handle unknown classification', async () => {
        const unknownResponse = {
          ...mockLookupResponse,
          threat_level: 'unknown'
        };
        mockClient.lookupIp.mockResolvedValue(unknownResponse as any);

        const result = await tools.executeTool('guardian_intel_lookup', { ip: '1.2.3.4' });

        expect(result.threat_level).toBe('unknown');
      });

      it('should handle response with null ASN', async () => {
        const responseWithoutAsn = {
          ...mockLookupResponse,
          asn: null
        };
        mockClient.lookupIp.mockResolvedValue(responseWithoutAsn as any);

        const result = await tools.executeTool('guardian_intel_lookup', { ip: '1.2.3.4' });

        expect(result.asn).toBeNull();
      });
    });

    describe('guardian_intel_tags_list', () => {
      const mockTagsResponse = {
        tags: ['credentials:brute-force', 'tool:scanner', 'actor:apt29'],
        tag_details: [
          {
            name: 'credentials:brute-force',
            intent: 'malicious',
            category: 'activity',
            description: 'Brute force attacks'
          },
          {
            name: 'tool:scanner',
            intent: 'suspicious',
            category: 'tool'
          },
          {
            name: 'actor:apt29',
            intent: 'malicious',
            category: 'actor'
          }
        ]
      };

      it('should execute tags list successfully', async () => {
        mockClient.getTags.mockResolvedValue(mockTagsResponse as any);

        const result = await tools.executeTool('guardian_intel_tags_list', { includeDescriptions: true });

        expect(mockClient.getTags).toHaveBeenCalledWith(true);
        expect(result).toEqual({
          total_tags: 3,
          tags: ['credentials:brute-force', 'tool:scanner', 'actor:apt29'],
          tag_details: [
            {
              name: 'credentials:brute-force',
              intent: 'malicious',
              category: 'activity',
              description: 'Brute force attacks'
            },
            {
              name: 'tool:scanner',
              intent: 'suspicious',
              category: 'tool',
              description: null
            },
            {
              name: 'actor:apt29',
              intent: 'malicious',
              category: 'actor',
              description: null
            }
          ],
          categories: {
            activity: 1,
            tool: 1,
            actor: 1
          },
          intents: {
            malicious: 2,
            suspicious: 1
          }
        });
      });

      it('should handle tags list without descriptions', async () => {
        mockClient.getTags.mockResolvedValue(mockTagsResponse as any);

        await tools.executeTool('guardian_intel_tags_list', { includeDescriptions: false });

        expect(mockClient.getTags).toHaveBeenCalledWith(false);
      });

      it('should handle default parameters', async () => {
        mockClient.getTags.mockResolvedValue(mockTagsResponse as any);

        await tools.executeTool('guardian_intel_tags_list', {});

        expect(mockClient.getTags).toHaveBeenCalledWith(undefined);
      });
    });

    describe('guardian_intel_tag_details', () => {
      const mockTagDetailsResponse = {
        tag: 'credentials:brute-force',
        description: 'Brute force credential attacks',
        category: 'activity',
        confidence: 'high',
        intent: 'malicious'
      };

      it('should execute tag details successfully', async () => {
        mockClient.getTagDetails.mockResolvedValue(mockTagDetailsResponse as any);

        const result = await tools.executeTool('guardian_intel_tag_details', { 
          tagName: 'credentials:brute-force' 
        });

        expect(mockClient.getTagDetails).toHaveBeenCalledWith('credentials:brute-force');
        expect(result).toEqual({
          tag: {
            name: 'credentials:brute-force',
            intent: 'malicious',
            category: 'activity',
            description: 'Brute force credential attacks'
          },
          confidence: 'high',
          threat_context: 'This tag represents malicious activity in the activity category. Brute force credential attacks'
        });
      });
    });

    describe('guardian_intel_tag_ips', () => {
      const mockTagIpsResponse = {
        tag: 'credentials:brute-force',
        ips: ['1.2.3.4', '5.6.7.8'],
        total: 1000,
        offset: 0,
        limit: 1000
      };

      it('should execute tag IPs successfully with default parameters', async () => {
        mockClient.getTagIps.mockResolvedValue(mockTagIpsResponse as any);

        const result = await tools.executeTool('guardian_intel_tag_ips', { 
          tagName: 'credentials:brute-force' 
        });

        expect(mockClient.getTagIps).toHaveBeenCalledWith('credentials:brute-force', {
          offset: undefined,
          limit: undefined,
          snapshot: undefined
        });
        expect(result).toEqual({
          tag: 'credentials:brute-force',
          ip_addresses: ['1.2.3.4', '5.6.7.8'],
          pagination: {
            total: 1000,
            returned: 2,
            offset: 0,
            limit: 1000,
            has_more: true
          },
          summary: "Found 2 IP addresses associated with tag 'credentials:brute-force'"
        });
      });

      it('should execute tag IPs with custom parameters', async () => {
        const customResponse = {
          ...mockTagIpsResponse,
          offset: 100,
          limit: 500
        };
        mockClient.getTagIps.mockResolvedValue(customResponse as any);

        const result = await tools.executeTool('guardian_intel_tag_ips', { 
          tagName: 'test-tag',
          offset: 100,
          limit: 500,
          snapshot: 'test-snapshot'
        });

        expect(mockClient.getTagIps).toHaveBeenCalledWith('test-tag', {
          offset: 100,
          limit: 500,
          snapshot: 'test-snapshot'
        });
        expect((result.pagination as any).offset).toBe(100);
        expect((result.pagination as any).limit).toBe(500);
      });

      it('should calculate has_more correctly when no more results', async () => {
        const responseWithNoMore = {
          ...mockTagIpsResponse,
          total: 2
        };
        mockClient.getTagIps.mockResolvedValue(responseWithNoMore as any);

        const result = await tools.executeTool('guardian_intel_tag_ips', { 
          tagName: 'test-tag',
          offset: 0
        });

        expect((result.pagination as any).has_more).toBe(false);
      });
    });

    describe('error handling', () => {
      it('should throw error for unknown tool', async () => {
        await expect(tools.executeTool('unknown_tool', {}))
          .rejects.toThrow('Tool execution failed: Unknown tool: unknown_tool');
      });

      it('should wrap client errors', async () => {
        mockClient.lookupIp.mockRejectedValue(new Error('Client error'));

        await expect(tools.executeTool('guardian_intel_lookup', { ip: '1.2.3.4' }))
          .rejects.toThrow('Tool execution failed: Client error');
      });

      it('should handle non-Error exceptions', async () => {
        mockClient.lookupIp.mockRejectedValue('String error');

        await expect(tools.executeTool('guardian_intel_lookup', { ip: '1.2.3.4' }))
          .rejects.toThrow('Tool execution failed: String error');
      });
    });
  });
});