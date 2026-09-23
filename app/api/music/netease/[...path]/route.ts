import { NextRequest, NextResponse } from "next/server";
import { Agent, fetch as undiciFetch } from "undici";

/**
 * 网易云音乐 API 服务端代理。
 *
 * 为什么需要它：自部署的 NeteaseCloudMusicApi 通常用自签名证书跑 HTTPS（或在内网地址上），
 * 而浏览器对 fetch 发起的跨域请求**不会给出「忽略证书警告」的选项**——证书不受信或 SAN
 * 与访问地址不一致时请求直接被拒。CORS 配好了也一样失败（这是实测结论，不是推测）。
 * 改由服务端转发后：
 *   - 浏览器只请求本站（同源，不触发 CORS）
 *   - 服务端到服务端不受浏览器证书策略约束（见 NETEASE_API_INSECURE）
 *
 * 上游地址**只从服务端环境变量读取**，不接受客户端传入，避免把这里变成任意 URL 转发器。
 * 优先级：NETEASE_API_BASE → NEXT_PUBLIC_DEFAULT_NETEASE_API_BASE → 本机回环默认值。
 */

export const runtime = "nodejs";
// 音频/图片流式转发可能较慢，给足时间
export const maxDuration = 60;

const DEFAULT_UPSTREAM = "http://127.0.0.1:4001";

/** 自签名证书的实例需要置 false 才能连上；仅影响本代理到上游这一跳。 */
const ALLOW_INSECURE_UPSTREAM = (process.env.NETEASE_API_INSECURE || "true").trim().toLowerCase() !== "false";

let insecureDispatcher: Agent | null = null;
function upstreamDispatcher(): Agent | null {
    if (!ALLOW_INSECURE_UPSTREAM) return null;
    if (!insecureDispatcher) {
        insecureDispatcher = new Agent({ connect: { rejectUnauthorized: false } });
    }
    return insecureDispatcher;
}

function corsHeaders(): Record<string, string> {
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Cache-Control": "no-store",
    };
}

function resolveUpstreamBase(): string {
    const raw = process.env.NETEASE_API_BASE
        || process.env.NEXT_PUBLIC_DEFAULT_NETEASE_API_BASE
        || DEFAULT_UPSTREAM;
    return raw.trim().replace(/\/+$/, "");
}

function disabledResponse() {
    return NextResponse.json(
        {
            code: 503,
            error: "netease_proxy_unconfigured",
            message: "网易云 API 代理未配置：请在服务端设置 NETEASE_API_BASE 指向你的实例地址。",
        },
        { status: 503, headers: corsHeaders() },
    );
}

export async function OPTIONS() {
    return new NextResponse(null, { status: 204, headers: corsHeaders() });
}

async function forward(request: NextRequest, path: string[]): Promise<Response> {
    const upstreamBase = resolveUpstreamBase();
    if (!upstreamBase) return disabledResponse();

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
        // 用 undici 的 fetch：只有它能带 dispatcher 关闭证书校验，
        // 全局 fetch 在应用启动后再改 NODE_TLS_REJECT_UNAUTHORIZED 已不生效。
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
