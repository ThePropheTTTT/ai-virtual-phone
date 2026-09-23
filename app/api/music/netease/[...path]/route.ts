import { NextRequest, NextResponse } from "next/server";
import { fetch as undiciFetch } from "undici";

import {
    CLIENT_BASE_HEADER,
    requestOriginInfo,
    resolveUpstreamBase,
    upstreamDispatcher,
} from "@/lib/server/netease-upstream";

/**
 * 网易云音乐 API 服务端代理。
 *
 * 为什么需要它：自部署的 NeteaseCloudMusicApi 通常用自签名证书跑 HTTPS（或只在内网
 * 可达），而浏览器对 fetch 发起的跨域请求**不提供「忽略证书警告」的选项**——证书
 * 不受信或 SAN 与访问地址不一致时请求直接被拒，CORS 配好了也一样失败（实测结论）。
 * 改由服务端转发后浏览器只请求本站：同源、不触发 CORS，也不受浏览器证书策略约束。
 *
 * 上游地址的解析与安全校验见 lib/server/netease-upstream.ts。
 */

export const runtime = "nodejs";
// 音频/图片流式转发可能较慢，给足时间
export const maxDuration = 60;

function corsHeaders(): Record<string, string> {
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": `Content-Type, ${CLIENT_BASE_HEADER}`,
        "Cache-Control": "no-store",
    };
}

export async function OPTIONS() {
    return new NextResponse(null, { status: 204, headers: corsHeaders() });
}

async function forward(request: NextRequest, path: string[]): Promise<Response> {
    const { host, protocol } = requestOriginInfo(request);
    const upstreamBase = resolveUpstreamBase(request.headers.get(CLIENT_BASE_HEADER), host, protocol);
    if (!upstreamBase) {
        return NextResponse.json(
            {
                code: 503,
                error: "netease_proxy_unconfigured",
                message: "网易云 API 代理未拿到上游地址：请在音乐设置里填写 API 地址，或设置服务端 NETEASE_API_BASE。",
            },
            { status: 503, headers: corsHeaders() },
        );
    }

    const upstreamUrl = `${upstreamBase}/${path.map(encodeURIComponent).join("/")}${request.nextUrl.search}`;

    const method = request.method === "POST" ? "POST" : "GET";
    const init: Record<string, unknown> = {
        method,
        headers: { "Content-Type": request.headers.get("content-type") || "application/json" },
        signal: AbortSignal.timeout(45_000),
    };
    const dispatcher = upstreamDispatcher();
    if (dispatcher) init.dispatcher = dispatcher;
    if (method === "POST") init.body = await request.text();

    try {
        const upstream = await undiciFetch(upstreamUrl, init as never);

        // 原样透传响应体（含音频/图片的流式内容）与关键响应头
        const headers: Record<string, string> = { ...corsHeaders() };
        for (const name of ["content-type", "content-length", "content-range", "accept-ranges"]) {
            const value = upstream.headers.get(name);
            if (value) headers[name] = value;
        }
        return new NextResponse(upstream.body as unknown as ReadableStream, {
            status: upstream.status,
            headers,
        });
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        const isTimeout = error instanceof Error && (error.name === "TimeoutError" || error.name === "AbortError");
        return NextResponse.json(
            {
                code: isTimeout ? 504 : 502,
                error: isTimeout ? "netease_upstream_timeout" : "netease_upstream_unreachable",
                message: isTimeout
                    ? `连接网易云 API 超时（${upstreamBase}）。`
                    : `无法连接网易云 API（${upstreamBase}）：${detail}`,
            },
            { status: isTimeout ? 504 : 502, headers: corsHeaders() },
        );
    }
}

export async function GET(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
    const { path } = await context.params;
    return forward(request, path || []);
}

export async function POST(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
    const { path } = await context.params;
    return forward(request, path || []);
}
