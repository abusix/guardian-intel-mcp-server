import axios, { AxiosInstance, AxiosError } from 'axios';
import {
  GuardianIntelConfig,
  LookupResponse,
  TagsListResponse,
  TagDetailsResponse,
  TagIpsResponse,
  ApiError
} from './types.js';

export class GuardianIntelClient {
  private client: AxiosInstance;
  private readonly baseUrl: string;

  constructor(config: GuardianIntelConfig) {
    this.baseUrl = config.baseUrl || 'https://threat-intel-api.abusix.com/beta';
    
    this.client = axios.create({
      baseURL: this.baseUrl,
      headers: {
        'Authorization': `Bearer ${config.apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': '@abusix/guardian-intel-mcp-server/1.0.0'
      },
      timeout: 30000
    });

    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        throw this.handleApiError(error);
      }
    );
  }

  private handleApiError(error: AxiosError): Error {
    if (error.response?.data) {
      const apiError = error.response.data as ApiError;
      return new Error(`Guardian Intel API Error (${apiError.statusCode}): ${apiError.message}`);
    }
    
    if (error.code === 'ECONNABORTED') {
      return new Error('Guardian Intel API request timeout');
    }
    
    if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
      return new Error('Unable to connect to Guardian Intel API');
    }
    
    return new Error(`Guardian Intel API Error: ${error.message}`);
  }

  private isValidIpAddress(ip: string): boolean {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
  }

  async lookupIp(ip: string): Promise<LookupResponse> {
    if (!this.isValidIpAddress(ip)) {
      throw new Error('Invalid IP address format');
    }

    try {
      const response = await this.client.get<LookupResponse>(`/query/${encodeURIComponent(ip)}`);
      return response.data;
    } catch (error) {
      throw error;
    }
  }

  async getTags(includeDescriptions = false): Promise<TagsListResponse> {
    try {
      const params = includeDescriptions ? { includeDescriptions: 'true' } : {};
      const response = await this.client.get<TagsListResponse>('/tags', { params });
      return response.data;
    } catch (error) {
      throw error;
    }
  }

  async getTagDetails(tagName: string): Promise<TagDetailsResponse> {
    if (!tagName || tagName.trim().length === 0) {
      throw new Error('Tag name is required');
    }

    try {
      const response = await this.client.get<TagDetailsResponse>(`/tags/${encodeURIComponent(tagName)}`);
      return response.data;
    } catch (error) {
      throw error;
    }
  }

  async getTagIps(
    tagName: string, 
    options: {
      offset?: number;
      limit?: number;
      snapshot?: string;
    } = {}
  ): Promise<TagIpsResponse> {
    if (!tagName || tagName.trim().length === 0) {
      throw new Error('Tag name is required');
    }

    const { offset = 0, limit = 1000, snapshot } = options;

    if (limit > 10000) {
      throw new Error('Limit cannot exceed 10,000');
    }

    if (offset < 0 || limit < 1) {
      throw new Error('Offset must be non-negative and limit must be positive');
    }

    try {
      const params: Record<string, string> = {
        offset: offset.toString(),
        limit: limit.toString()
      };

      if (snapshot) {
        params.snapshot = snapshot;
      }

      const response = await this.client.get<TagIpsResponse>(
        `/tags/${encodeURIComponent(tagName)}/ips`,
        { params }
      );
      return response.data;
    } catch (error) {
      throw error;
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.client.get('/tags', { 
        params: { limit: '1' },
        timeout: 5000 
      });
      return true;
    } catch (error) {
      return false;
    }
  }
}