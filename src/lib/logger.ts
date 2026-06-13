/**
 * 结构化日志 — stderr 通道，零污染 stdout (MCP 协议)。
 */

type Level = "debug"|"info"|"warn"|"error";
const RANK: Record<Level,number> = { debug:0, info:1, warn:2, error:3 };

function emit(lv: Level, msg: string, ctx?: unknown): void {
  const th = (process.env.LOG_LEVEL||"info").toLowerCase() as Level;
  if (RANK[lv] < (RANK[th]??1)) return;
  process.stderr.write(JSON.stringify({
    ts: new Date().toISOString(), level: lv, msg,
    ...(ctx!==undefined?{ctx}:{}),
  })+"\n");
}

export const logger = {
  debug: (m:string,c?:unknown)=>emit("debug",m,c),
  info:  (m:string,c?:unknown)=>emit("info",m,c),
  warn:  (m:string,c?:unknown)=>emit("warn",m,c),
  error: (m:string,c?:unknown)=>emit("error",m,c),
};
