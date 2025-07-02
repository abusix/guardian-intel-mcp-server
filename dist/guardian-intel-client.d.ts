import { GuardianIntelConfig, LookupResponse, TagsListResponse, TagDetailsResponse, TagIpsResponse } from './types.js';
export declare class GuardianIntelClient {
    private client;
    private readonly baseUrl;
    constructor(config: GuardianIntelConfig);
    private handleApiError;
    private isValidIpAddress;
    lookupIp(ip: string): Promise<LookupResponse>;
    getTags(includeDescriptions?: boolean): Promise<TagsListResponse>;
    getTagDetails(tagName: string): Promise<TagDetailsResponse>;
    getTagIps(tagName: string, options?: {
        offset?: number;
        limit?: number;
        snapshot?: string;
    }): Promise<TagIpsResponse>;
    healthCheck(): Promise<boolean>;
}
//# sourceMappingURL=guardian-intel-client.d.ts.map