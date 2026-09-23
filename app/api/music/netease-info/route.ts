import { NextResponse } from "next/server";
import { Agent, fetch as undiciFetch } from "undici";

/**
 * 网易云代理状态查询：让设置界面能展示服务端实际使用的上游地址，并做一次连通性探测。
 * 上游地址来自服务端环境变量，不暴露给客户端去改写（真正的转发发生在 [...path] 路由里）。
 */

export const runtime = "nodejs";
export const maxDuration = 30;

const DEFAULT_UPSTREAM = "http://127.0.0.1:4001";

const ALLOW_INSECURE_UPSTREAM = (process.env.NETEASE_API_INSECURE || "true").trim().toLowerCase() !== "false";

let insecureDispatcher: Agent | null = null;
function upstreamDispatcher(): Agent | null {
    if (!ALLOW_INSECURE_UPSTREAM) return null;
    if (!insecureDispatcher) {
        insecureDispatcher = new Agent({ connect: { rejectUnauthorized: false } });
    }
    return insecureDispatcher;
}

function resolveUpstreamBase(): string {
    const raw = process.env.NETEASE_API_BASE
        || process.env.NEXT_PUBLIC_DEFAULT_NETEASE_API_BASE
        || DEFAULT_UPSTREAM;
    return raw.trim().replace(/\/+$/, "");
}

export async function GET() {
    const baseUrl = resolveUpstreamBase();
    if (!baseUrl) {
        return NextResponse.json({
            configured: false,
            reachable: false,
            baseUrl: "",
            message: "未配置上游地址：请在服务端设置 NETEASE_API_BASE。",
        });
    }

    const init: Record<string, unknown> = { signal: AbortSignal.timeout(15_000) };
    const dispatcher = upstreamDispatcher();
    if (dispatcher) init.dispatcher = dispatcher;

    try {
        const probe = await undiciFetch(`${baseUrl}/search?keywords=test&limit=1`, init as never);
        if (!probe.ok) {
            return NextResponse.json({
                configured: true,
                reachable: false,
                baseUrl,
                message: `上游返回 HTTP ${probe.status}（地址可达但接口异常）`,
            });
        }
        const data = await probe.json().catch(() => null) as { result?: unknown; code?: number } | null;
        const hasResult = Boolean(data && (data.result || data.code === 200));
        return NextResponse.json({
            configured: true,
            reachable: hasResult,
            baseUrl,
            message: hasResult ? "连接成功" : "上游返回格式异常",
        });
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return NextResponse.json({
            configured: true,
            reachable: false,
            baseUrl,
            message: `无法连接上游（${baseUrl}）：${detail}`,
        });
    }
}
