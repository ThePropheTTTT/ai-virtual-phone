import { NextRequest, NextResponse } from "next/server";
import { fetch as undiciFetch } from "undici";

import {
    CLIENT_BASE_HEADER,
    resolveUpstreamBase,
    upstreamDispatcher,
} from "@/lib/server/netease-upstream";

/**
 * 网易云代理状态查询：让设置界面能展示当前实际使用的上游地址，并做一次连通性探测。
 *
 * 上游地址的解析与代理路由共用同一份逻辑（含客户端传入地址的安全校验），
 * 保证「测试连接」的结论与真实转发一致。
 */

export const runtime = "nodejs";
export const maxDuration = 30;

export async function GET(request: NextRequest) {
    const baseUrl = resolveUpstreamBase(request.headers.get(CLIENT_BASE_HEADER));
    if (!baseUrl) {
        return NextResponse.json({
            configured: false,
            reachable: false,
            baseUrl: "",
            message: "未拿到上游地址：请在音乐设置里填写 API 地址，或设置服务端 NETEASE_API_BASE。",
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
