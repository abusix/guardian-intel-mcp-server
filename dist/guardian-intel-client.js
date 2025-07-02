import axios from 'axios';
export class GuardianIntelClient {
    client;
    baseUrl;
    constructor(config) {
        if (!config.apiKey || config.apiKey.trim().length === 0) {
            throw new Error('Guardian Intel API key is required and cannot be empty');
        }
        this.baseUrl = config.baseUrl || 'https://threat-intel-api.abusix.com/beta';
        this.client = axios.create({
            baseURL: this.baseUrl,
            headers: {
                'x-api-key': `${config.apiKey}`,
                'Content-Type': 'application/json',
                'User-Agent': '@abusix/guardian-intel-mcp-server/1.0.0'
            },
            timeout: 30000
        });
        this.client.interceptors.response.use((response) => response, (error) => {
            throw this.handleApiError(error);
        });
    }
    handleApiError(error) {
        const status = error.response?.status;
        const statusText = error.response?.statusText;
        if (error.response?.data) {
            const apiError = error.response.data;
            // Try to extract error message from various possible response formats
            const errorMessage = apiError.message ||
                apiError.error ||
                apiError.detail ||
                apiError.description ||
                statusText ||
                'Unknown API error';
            const errorCode = apiError.statusCode || apiError.code || status || 'Unknown';
            return new Error(`Guardian Intel API Error (${errorCode}): ${errorMessage}`);
        }
        // Handle specific HTTP status codes
        if (status) {
            switch (status) {
                case 401:
                    return new Error(`Guardian Intel API Error (401): Invalid or missing API key`);
                case 403:
                    return new Error(`Guardian Intel API Error (403): Access forbidden - check API key permissions`);
                case 404:
                    return new Error(`Guardian Intel API Error (404): Resource not found`);
                case 429:
                    return new Error(`Guardian Intel API Error (429): Rate limit exceeded`);
                case 500:
                    return new Error(`Guardian Intel API Error (500): Internal server error`);
                case 503:
                    return new Error(`Guardian Intel API Error (503): Service temporarily unavailable`);
                default:
                    return new Error(`Guardian Intel API Error (${status}): ${statusText || 'HTTP error'}`);
            }
        }
        if (error.code === 'ECONNABORTED') {
            return new Error('Guardian Intel API request timeout');
        }
        if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
            return new Error('Unable to connect to Guardian Intel API');
        }
        return new Error(`Guardian Intel API Error: ${error.message}`);
    }
    isValidIpAddress(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }
    async lookupIp(ip) {
        if (!this.isValidIpAddress(ip)) {
            throw new Error('Invalid IP address format');
        }
        try {
            const response = await this.client.get(`/query/${encodeURIComponent(ip)}`);
            // Extract the result from the API wrapper
            if (response.data?.result) {
                return {
                    ip: response.data.result.item,
                    tags: response.data.result.tags,
                    confidence: response.data.result.intent === 'malicious' ? 'high' : response.data.result.intent === 'suspicious' ? 'medium' : 'low',
                    threat_level: response.data.result.intent,
                    first_seen: response.data.result.firstSeen,
                    last_seen: response.data.result.lastSeen,
                    asn: response.data.result.asn,
                    abuse_contact: response.data.result.abuseContact,
                    observed_activity: response.data.result.observedActivity
                };
            }
            throw new Error('Invalid response format from Guardian Intel API');
        }
        catch (error) {
            throw error;
        }
    }
    async getTags(includeDescriptions = false) {
        try {
            const params = includeDescriptions ? { includeDescriptions: 'true' } : {};
            const response = await this.client.get('/tags', { params });
            // Extract the result from the API wrapper
            if (response.data?.result && Array.isArray(response.data.result)) {
                return {
                    tags: response.data.result.map((tag) => tag.name),
                    tag_details: includeDescriptions ? response.data.result : undefined
                };
            }
            throw new Error('Invalid response format from Guardian Intel API');
        }
        catch (error) {
            throw error;
        }
    }
    async getTagDetails(tagName) {
        if (!tagName || tagName.trim().length === 0) {
            throw new Error('Tag name is required');
        }
        try {
            const response = await this.client.get(`/tags/${encodeURIComponent(tagName)}`);
            // Extract the result from the API wrapper
            if (response.data?.result) {
                return {
                    tag: response.data.result.name,
                    description: response.data.result.description,
                    category: response.data.result.category,
                    confidence: response.data.result.intent === 'malicious' ? 'high' : response.data.result.intent === 'suspicious' ? 'medium' : 'low',
                    intent: response.data.result.intent
                };
            }
            throw new Error('Invalid response format from Guardian Intel API');
        }
        catch (error) {
            throw error;
        }
    }
    async getTagIps(tagName, options = {}) {
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
            const params = {
                offset: offset.toString(),
                limit: limit.toString()
            };
            if (snapshot) {
                params.snapshot = snapshot;
            }
            const response = await this.client.get(`/tags/${encodeURIComponent(tagName)}/ips`, { params });
            // Extract the result from the API wrapper
            if (response.data?.result) {
                return {
                    tag: response.data.result.tag || tagName,
                    total: response.data.result.total,
                    offset: response.data.result.offset || offset,
                    limit: response.data.result.limit || limit,
                    ips: response.data.result.entries || []
                };
            }
            throw new Error('Invalid response format from Guardian Intel API');
        }
        catch (error) {
            throw error;
        }
    }
    async healthCheck() {
        try {
            await this.client.get('/tags', {
                params: { limit: '1' },
                timeout: 5000
            });
            return true;
        }
        catch (error) {
            return false;
        }
    }
}
//# sourceMappingURL=guardian-intel-client.js.map