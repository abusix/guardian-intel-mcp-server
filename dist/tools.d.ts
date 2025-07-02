import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { GuardianIntelClient } from './guardian-intel-client.js';
export declare class GuardianIntelTools {
    private client;
    constructor(client: GuardianIntelClient);
    getToolDefinitions(): Tool[];
    executeTool(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>>;
    private lookupIp;
    private getTagsList;
    private getTagDetails;
    private getTagIps;
    private getAggregatedThreatLevel;
    private generateThreatSummary;
    private getCategoryStats;
    private getIntentStats;
    private generateTagContext;
}
//# sourceMappingURL=tools.d.ts.map