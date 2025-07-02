export interface GuardianIntelConfig {
  apiKey: string;
  baseUrl?: string;
}

export interface LookupResponse {
  status: string;
  statusCode: number;
  result: {
    ip: string;
    classification: 'malicious' | 'suspicious' | 'unknown';
    firstSeen?: string;
    lastSeen?: string;
    abuseContact?: string;
    asn?: {
      number: number;
      name: string;
      country: string;
    };
    blocklists?: string[];
    activities?: MaliciousActivity[];
  };
}

export interface MaliciousActivity {
  type: string;
  description: string;
  timestamp: string;
  severity: 'high' | 'medium' | 'low';
}

export interface TagsListResponse {
  status: string;
  statusCode: number;
  result: TagSummary[];
}

export interface TagSummary {
  name: string;
  intent: 'malicious' | 'suspicious' | 'unknown' | 'none';
  category: 'activity' | 'tool' | 'actor' | 'none';
  description?: string;
}

export interface TagDetailsResponse {
  status: string;
  statusCode: number;
  result: {
    name: string;
    intent: 'malicious' | 'suspicious' | 'unknown' | 'none';
    category: 'activity' | 'tool' | 'actor' | 'none';
    description: string;
    references: string[];
    timeline: TimelineEntry[];
  };
}

export interface TimelineEntry {
  action: string;
  timestamp: string;
  description: string;
}

export interface TagIpsResponse {
  status: string;
  statusCode: number;
  result: {
    tag: string;
    entries: string[];
    lastUpdate: string;
    total: number;
    snapshot: string;
  };
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