export interface GuardianIntelConfig {
    apiKey: string;
    baseUrl?: string;
}
export interface LookupResponse {
    ip: string;
    tags?: string[];
    confidence?: string;
    threat_level?: string;
    first_seen?: string;
    last_seen?: string;
    asn?: {
        asn: string;
        name: string;
        countryCode: string;
    };
    abuse_contact?: {
        email: string;
        status: string;
        lastVerification: string;
    };
    observed_activity?: any;
}
export interface MaliciousActivity {
    type: string;
    description: string;
    timestamp: string;
    severity: 'high' | 'medium' | 'low';
}
export interface TagsListResponse {
    tags: string[];
    tag_details?: TagSummary[];
}
export interface TagSummary {
    name: string;
    intent: 'malicious' | 'suspicious' | 'unknown' | 'none';
    category: 'activity' | 'tool' | 'actor' | 'none';
    description?: string;
}
export interface TagDetailsResponse {
    tag: string;
    description?: string;
    category?: string;
    confidence?: string;
    intent?: string;
}
export interface TimelineEntry {
    action: string;
    timestamp: string;
    description: string;
}
export interface TagIpsResponse {
    tag: string;
    total?: number;
    offset?: number;
    limit?: number;
    ips: string[];
}
export interface ApiError {
    status: string;
    statusCode: number;
    message: string;
    error?: string;
}
export interface LookupToolParams {
    ip: string;
}
export interface TagsListToolParams {
    includeDescriptions?: boolean;
}
export interface TagDetailsToolParams {
    tagName: string;
}
export interface TagIpsToolParams {
    tagName: string;
    offset?: number;
    limit?: number;
    snapshot?: string;
}
//# sourceMappingURL=types.d.ts.map