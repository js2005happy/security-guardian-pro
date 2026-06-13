/**
 * 结构化日志 — stderr 通道，零污染 stdout (MCP 协议)。
 */
const RANK = { debug: 0, info: 1, warn: 2, error: 3 };
function emit(lv, msg, ctx) {
    const th = (process.env.LOG_LEVEL || "info").toLowerCase();
    if (RANK[lv] < (RANK[th] ?? 1))
        return;
    process.stderr.write(JSON.stringify({
        ts: new Date().toISOString(), level: lv, msg,
        ...(ctx !== undefined ? { ctx } : {}),
    }) + "\n");
}
export const logger = {
    debug: (m, c) => emit("debug", m, c),
    info: (m, c) => emit("info", m, c),
    warn: (m, c) => emit("warn", m, c),
    error: (m, c) => emit("error", m, c),
};
//# sourceMappingURL=logger.js.map