/**
 * MCP Server 工厂 — 创建并配置 Security Guardian Pro 服务器实例。
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
export interface ServerContext {
    server: McpServer;
    shutdown: () => Promise<void>;
}
export declare function createServer(): ServerContext;
//# sourceMappingURL=server.d.ts.map