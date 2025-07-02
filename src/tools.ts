import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { GuardianIntelClient } from './guardian-intel-client.js';
import {
  LookupToolParams,
  TagsListToolParams,
  TagDetailsToolParams,
  TagIpsToolParams
} from './types.js';

export class GuardianIntelTools {
  constructor(private client: GuardianIntelClient) {}

  getToolDefinitions(): Tool[] {
    return [
      {
        name: 'guardian_intel_lookup',
        description: 'Look up threat intelligence for an IP address using Abusix Guardian Intel. Returns classification (malicious/suspicious/unknown), blocklist status, abuse contacts, ASN information, and observed malicious activities.',
        inputSchema: {
          type: 'object',
          properties: {
            ip: {
              type: 'string',
              description: 'The IP address to look up (IPv4 or IPv6)',
              pattern: '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
            }
          },
          required: ['ip']
        }
      },
      {
        name: 'guardian_intel_tags_list',
        description: 'Retrieve all available threat intelligence tags from Guardian Intel. Tags categorize different types of threats, tools, activities, and actors.',
        inputSchema: {
          type: 'object',
          properties: {
            includeDescriptions: {
              type: 'boolean',
              description: 'Whether to include detailed descriptions for each tag',
              default: false
            }
          }
        }
      },
      {
        name: 'guardian_intel_tag_details',
        description: 'Get detailed information about a specific threat intelligence tag, including its description, references, and timeline of activities.',
        inputSchema: {
          type: 'object',
          properties: {
            tagName: {
              type: 'string',
              description: 'The name of the tag to look up (e.g., "credentials:brute-force")',
              minLength: 1
            }
          },
          required: ['tagName']
        }
      },
      {
        name: 'guardian_intel_tag_ips',
        description: 'Retrieve IP addresses associated with a specific threat intelligence tag. Supports pagination for large datasets.',
        inputSchema: {
          type: 'object',
          properties: {
            tagName: {
              type: 'string',
              description: 'The name of the tag to get IPs for (e.g., "credentials:brute-force")',
              minLength: 1
            },
            offset: {
              type: 'number',
              description: 'Starting offset for pagination',
              default: 0,
              minimum: 0
            },
            limit: {
              type: 'number',
              description: 'Maximum number of IPs to return (max 10,000)',
              default: 1000,
              minimum: 1,
              maximum: 10000
            },
            snapshot: {
              type: 'string',
              description: 'Snapshot identifier for consistent pagination across requests'
            }
          },
          required: ['tagName']
        }
      }
    ];
  }

  async executeTool(name: string, args: any): Promise<any> {
    try {
      switch (name) {
        case 'guardian_intel_lookup':
          return await this.lookupIp(args as LookupToolParams);
        
        case 'guardian_intel_tags_list':
          return await this.getTagsList(args as TagsListToolParams);
        
        case 'guardian_intel_tag_details':
          return await this.getTagDetails(args as TagDetailsToolParams);
        
        case 'guardian_intel_tag_ips':
          return await this.getTagIps(args as TagIpsToolParams);
        
        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } catch (error) {
      throw new Error(`Tool execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async lookupIp(params: LookupToolParams) {
    const response = await this.client.lookupIp(params.ip);
    
    return {
      ip: response.ip,
      tags: response.tags || [],
      threat_level: response.threat_level || 'unknown',
      confidence: response.confidence || 'low',
      first_seen: response.first_seen,
      last_seen: response.last_seen,
      abuse_contact: response.abuse_contact?.email,
      asn: response.asn ? {
        number: response.asn.asn,
        name: response.asn.name,
        country: response.asn.countryCode
      } : null,
      observed_activity: response.observed_activity,
      summary: this.generateThreatSummary(response)
    };
  }

  private async getTagsList(params: TagsListToolParams) {
    const response = await this.client.getTags(params.includeDescriptions);
    
    return {
      total_tags: response.tags.length,
      tags: response.tags,
      tag_details: response.tag_details ? response.tag_details.map(tag => ({
        name: tag.name,
        intent: tag.intent,
        category: tag.category,
        description: tag.description || null
      })) : [],
      categories: response.tag_details ? this.getCategoryStats(response.tag_details) : {},
      intents: response.tag_details ? this.getIntentStats(response.tag_details) : {}
    };
  }

  private async getTagDetails(params: TagDetailsToolParams) {
    const response = await this.client.getTagDetails(params.tagName);
    
    return {
      tag: {
        name: response.tag,
        intent: response.intent,
        category: response.category,
        description: response.description
      },
      confidence: response.confidence,
      threat_context: this.generateTagContext(response)
    };
  }

  private async getTagIps(params: TagIpsToolParams) {
    const response = await this.client.getTagIps(params.tagName, {
      offset: params.offset,
      limit: params.limit,
      snapshot: params.snapshot
    });
    
    return {
      tag: response.tag,
      ip_addresses: response.ips,
      pagination: {
        total: response.total || 0,
        returned: response.ips.length,
        offset: response.offset || 0,
        limit: response.limit || 1000,
        has_more: (response.offset || 0) + response.ips.length < (response.total || 0)
      },
      summary: `Found ${response.ips.length} IP addresses associated with tag '${response.tag}'`
    };
  }

  private getAggregatedThreatLevel(classification: string): string {
    switch (classification.toLowerCase()) {
      case 'malicious':
        return 'HIGH';
      case 'suspicious':
        return 'MEDIUM';
      case 'unknown':
        return 'LOW';
      default:
        return 'UNKNOWN';
    }
  }

  private generateThreatSummary(result: any): string {
    const threatLevel = result.threat_level || 'unknown';
    const tags = result.tags || [];
    
    let summary = `IP threat level: ${threatLevel.toUpperCase()}`;
    
    if (tags.length > 0) {
      summary += ` with ${tags.length} associated tag(s): ${tags.slice(0, 3).join(', ')}`;
      if (tags.length > 3) {
        summary += ` and ${tags.length - 3} more`;
      }
    }
    
    if (result.first_seen) {
      summary += `. First seen: ${result.first_seen}`;
    }
    
    return summary;
  }

  private getCategoryStats(tags: any[]): Record<string, number> {
    const stats: Record<string, number> = {};
    tags.forEach(tag => {
      stats[tag.category] = (stats[tag.category] || 0) + 1;
    });
    return stats;
  }

  private getIntentStats(tags: any[]): Record<string, number> {
    const stats: Record<string, number> = {};
    tags.forEach(tag => {
      stats[tag.intent] = (stats[tag.intent] || 0) + 1;
    });
    return stats;
  }

  private generateTagContext(tagDetails: any): string {
    const { intent, category, description } = tagDetails;
    
    let context = `This tag represents ${intent} activity in the ${category} category`;
    
    if (description) {
      context += `. ${description}`;
    }
    
    return context;
  }
}