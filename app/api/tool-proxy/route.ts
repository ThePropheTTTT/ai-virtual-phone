import { NextRequest, NextResponse } from "next/server";
import { lookup } from "node:dns/promises";
import { ProxyAgent, fetch as undiciFetch, type Dispatcher } from "undici";

export const maxDuration = 120;

function getProxyDispatcher(): Dispatcher | undefined {
    const proxyUrl = process.env.https_proxy || process.env.HTTPS_PROXY
        || process.env.http_proxy || process.env.HTTP_PROXY;
    if (!proxyUrl) return undefined;
    return new ProxyAgent(proxyUrl);
}

type ProxyErrorPayload = {
    error: string;
    errorName?: string;
    cause?: string;
    url?: string;
};

// 服务端 SSRF 防线：客户端 network.fetch 有同款校验，但绕过客户端直接 POST
// 本路由时必须在这里再拦一次，禁止代理探测本机/内网/云元数据地址。
function isPrivateIpv4(host: string): boolean {
    const parts = host.split(".").map(part => Number(part));
    if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return false;
    const [a, b] = parts;
    return a === 0
        || a === 10
        || a === 127
        || (a === 169 && b === 254)
        || (a === 172 && b >= 16 && b <= 31)
        || (a === 192 && b === 168)
        || (a === 100 && b >= 64 && b <= 127);
}

/**
 * 字符串层的快速拦截。注意这会先剥掉主机名末尾的点：`localhost.` 是 `localhost` 的
 * 等价 FQDN 写法（DNS 解析结果相同），但字符串比较既不等于 "localhost" 也不以
 * ".localhost" 结尾——此前正是靠这一点绕过了整条防线（`metadata.google.internal.` 同理）。
 */
function blockedProxyUrlReason(rawUrl: string): string | null {
    let url: URL;
    try {
        url = new URL(rawUrl);
    } catch {
        return "URL 格式不合法";
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
        return "只允许 http/https URL";
    }
    const host = normalizeHostname(url.hostname);
    const isIpv6Literal = host.includes(":");
    const blocked = host === "localhost"
        || host.endsWith(".localhost")
        || host.endsWith(".local")
        || host.endsWith(".internal")
        || host === "::1"
        || host === "0:0:0:0:0:0:0:1"
        || (isIpv6Literal && (host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80") || host.startsWith("::ffff:")))
        || isPrivateIpv4(host);
    return blocked ? "不允许代理访问本机或内网地址" : null;
}

/** 去掉 IPv6 字面量的方括号与主机名末尾的点（FQDN 根点）。 */
function normalizeHostname(rawHostname: string): string {
    return rawHostname
        .toLowerCase()
        .replace(/^\[|\]$/g, "")
        .replace(/\.+$/, "");
}

function isBlockedResolvedAddress(address: string): boolean {
    const normalized = normalizeHostname(address);
    if (normalized.includes(":")) {
        // IPv4-mapped IPv6（::ffff:127.0.0.1）按 v4 再判一次
        if (normalized.startsWith("::ffff:")) {
            return isBlockedResolvedAddress(normalized.slice("::ffff:".length));
        }
        return normalized === "::1"
            || normalized === "::"
            || normalized.startsWith("fc")
            || normalized.startsWith("fd")
            || normalized.startsWith("fe80");
    }
    return isPrivateIpv4(normalized);
}

/**
 * 完整防线：先做字符串判断，再把主机名**解析成地址**逐个校验。
 * 只比较字符串时，攻击者自己的域名可以解析到 127.0.0.1 / 169.254.169.254 而不被拦；
 * 解析后校验把这条路径一并堵上（尾点绕过也在这里失效，因为解析结果就是本机地址）。
 * 解析失败不拦截——那种情况下后续 fetch 同样连不上，交给它报错即可。
 */
async function blockedProxyUrlReasonWithDns(rawUrl: string): Promise<string | null> {
    const stringReason = blockedProxyUrlReason(rawUrl);
    if (stringReason) return stringReason;

    let host: string;
    try {
        host = normalizeHostname(new URL(rawUrl).hostname);
    } catch {
        return "URL 格式不合法";
    }
    // 已经是 IP 字面量时上面的判断已覆盖，无需解析
    if (/^[0-9.]+$/.test(host) || host.includes(":")) return null;

    try {
        const addresses = await lookup(host, { all: true });
        if (addresses.some(entry => isBlockedResolvedAddress(entry.address))) {
            return "不允许代理访问本机或内网地址（域名解析到内网）";
        }
    } catch {
        return null;
    }
    return null;
}

/**
 * Server-side proxy for external tool/MCP requests.
 * Bypasses browser CORS restrictions.
 *
 * POST /api/tool-proxy
 * Body: { url, method, headers, body }
 */
export async function POST(req: NextRequest) {
    let requestUrlForDebug = "";
    let fetchUrlForDebug = "";
    try {
        const { url, method, headers, body, timeoutMs } = await req.json();
        requestUrlForDebug = typeof url === "string" ? url : "";

        if (!url || typeof url !== "string") {
            return NextResponse.json({ error: "Missing url" }, { status: 400 });
        }
        const blockedReason = await blockedProxyUrlReasonWithDns(url);
        if (blockedReason) {
            return NextResponse.json({ error: blockedReason }, { status: 400 });
        }

        const fetchHeaders: Record<string, string> = {
            ...(headers || {}),
        };

        // SSE discovery needs Accept header for event-stream
        if (method === "SSE_DISCOVER") {
            fetchHeaders["Accept"] = "text/event-stream";
        }

        const fetchOptions: RequestInit = {
            method: (method === "SSE_DISCOVER" || method === "SSE_REQUEST") ? "GET" : (method || "POST"),
            headers: fetchHeaders,
        };

        if (body !== undefined && body !== null && method !== "GET" && method !== "SSE_DISCOVER" && method !== "SSE_REQUEST") {
            fetchOptions.body = typeof body === "string" ? body : JSON.stringify(body);
            if (!fetchHeaders["Content-Type"]) {
                fetchHeaders["Content-Type"] = "application/json";
            }
        }

        // For GET requests with body as query params
        let fetchUrl = url;
        if (method === "GET" && body && typeof body === "object") {
            const params = new URLSearchParams();
            for (const [k, v] of Object.entries(body)) {
                if (v !== undefined && v !== "") params.set(k, String(v));
            }
            const sep = fetchUrl.includes("?") ? "&" : "?";
            fetchUrl = `${fetchUrl}${sep}${params.toString()}`;
        }
        fetchUrlForDebug = fetchUrl;

        const requestedTimeoutMs = Number(timeoutMs);
        const proxyTimeoutMs = Number.isFinite(requestedTimeoutMs) && requestedTimeoutMs > 0
            ? Math.max(1000, Math.min(requestedTimeoutMs, 120_000))
            : 120_000;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), proxyTimeoutMs);
        const dispatcher = getProxyDispatcher();

        const res = await (dispatcher
            ? undiciFetch(fetchUrl, {
                method: fetchOptions.method || "POST",
                headers: fetchHeaders,
                body: fetchOptions.body as string | undefined,
                signal: controller.signal,
                dispatcher,
            }) as unknown as Response
            : fetch(fetchUrl, { ...fetchOptions, signal: controller.signal })
        );
        clearTimeout(timeout);

        // Forward response headers we care about
        const responseHeaders: Record<string, string> = {};
        const sessionId = res.headers.get("mcp-session-id");
        if (sessionId) responseHeaders["mcp-session-id"] = sessionId;
        const wwwAuth = res.headers.get("www-authenticate");
        if (wwwAuth) responseHeaders["www-authenticate"] = wwwAuth;

        // SSE_DISCOVER: just get the endpoint path
        if (method === "SSE_DISCOVER") {
            if (!res.ok) {
                const errText = await res.text().catch(() => "");
                return NextResponse.json({ endpointPath: "", debug: `HTTP ${res.status}: ${errText.slice(0, 300)}` }, { status: 200 });
            }
            const { endpointPath, buffer } = await readSseEndpoint(res);
            return NextResponse.json({ endpointPath, debug: buffer.slice(0, 500) }, { status: 200 });
        }

        // SSE_REQUEST: full SSE flow — connect, get endpoint, POST message, read response from SSE stream
        if (method === "SSE_REQUEST") {
            try {
                if (!res.ok) {
                    const errText = await res.text().catch(() => "");
                    return NextResponse.json({ error: `SSE connect: HTTP ${res.status} ${errText.slice(0, 200)}` }, { status: 502 });
                }

                const { endpointPath, reader, decoder, buffer: initialBuffer } = await readSseEndpointKeepOpen(res);
                if (!endpointPath || !reader) {
                    return NextResponse.json({ error: `SSE 未返回 endpoint。收到: ${initialBuffer?.slice(0, 200) || "(空)"}` }, { status: 502 });
                }

                // Resolve message URL
                const baseUrl = new URL(url);
                const msgUrl = new URL(endpointPath, baseUrl.origin);
                for (const [k, v] of baseUrl.searchParams.entries()) {
                    if (!msgUrl.searchParams.has(k)) msgUrl.searchParams.set(k, v);
                }
                // endpointPath 来自远端响应,可能是指向内网的绝对 URL,再拦一次
                const msgBlockedReason = await blockedProxyUrlReasonWithDns(msgUrl.toString());
                if (msgBlockedReason) {
                    reader.cancel().catch(() => {});
                    return NextResponse.json({ error: `SSE endpoint ${msgBlockedReason}` }, { status: 400 });
                }

                // POST the JSON-RPC body to the message endpoint
                const postHeaders: Record<string, string> = { "Content-Type": "application/json", ...(headers || {}) };
                const postRes = await fetch(msgUrl.toString(), {
                    method: "POST",
                    headers: postHeaders,
                    body: typeof body === "string" ? body : JSON.stringify(body),
                });

                if (!postRes.ok && postRes.status !== 202) {
                    reader.cancel().catch(() => {});
                    const errText = await postRes.text().catch(() => "");
                    return NextResponse.json({ error: `POST ${msgUrl.pathname}: HTTP ${postRes.status} ${errText.slice(0, 200)}` }, { status: 502 });
                }

                // Read SSE stream for the "message" event containing the JSON-RPC response
                let sseBuffer = initialBuffer;
                const sseTimeout = setTimeout(() => reader.cancel().catch(() => {}), 15_000);
                try {
                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        sseBuffer += decoder.decode(value, { stream: true });

                        // Look for "event: message\ndata: {...}" or just "data: {...}" after the endpoint event
                        const msgMatch = sseBuffer.match(/event:\s*message\ndata:\s*(.+)/);
                        if (msgMatch) {
                            clearTimeout(sseTimeout);
                            reader.cancel().catch(() => {});
                            return new NextResponse(msgMatch[1].trim(), {
                                status: 200,
                                headers: { "Content-Type": "application/json" },
                            });
                        }
                    }
                } finally {
                    clearTimeout(sseTimeout);
                    reader.cancel().catch(() => {});
                }

                return NextResponse.json({ error: `SSE 流未返回响应。缓冲: ${sseBuffer.slice(0, 300)}` }, { status: 504 });
            } catch (sseErr) {
                const msg = sseErr instanceof Error ? sseErr.message : String(sseErr);
                return NextResponse.json({ error: `SSE 请求异常: ${msg}` }, { status: 502 });
            }
        }

        const ct = (res.headers.get("Content-Type") || "").toLowerCase();
        const isBinary = ct.includes("zip") || ct.includes("octet-stream") || ct.includes("pdf")
            || ct.startsWith("image/") || ct.startsWith("audio/") || ct.startsWith("video/");

        if (isBinary && res.ok) {
            const buf = await res.arrayBuffer();
            const base64 = Buffer.from(buf).toString("base64");
            return NextResponse.json({
                _binary: true,
                contentType: ct,
                data: base64,
            }, { status: res.status, headers: responseHeaders });
        }

        const responseText = await res.text();

        return new NextResponse(responseText, {
            status: res.status,
            headers: {
                "Content-Type": res.headers.get("Content-Type") || "application/json",
                ...responseHeaders,
            },
        });
    } catch (err) {
        const payload = buildProxyErrorPayload(err, fetchUrlForDebug || requestUrlForDebug);
        const status = payload.error.includes("超时") ? 504 : 502;
        return NextResponse.json(payload, { status });
    }
}

function buildProxyErrorPayload(err: unknown, rawUrl: string): ProxyErrorPayload {
    const errorName = err instanceof Error ? err.name : undefined;
    const message = err instanceof Error ? err.message : String(err);
    const cause = extractCauseText(err);
    const safeUrl = safeDebugUrl(rawUrl);
    const hostname = safeHostname(rawUrl);
    const combined = `${errorName || ""} ${message} ${cause}`.toLowerCase();

    let error = `工具代理请求失败：${cause || message}`;
    if (combined.includes("abort")) {
        error = "工具代理请求超时（120秒）";
    } else if (combined.includes("eai_again") || combined.includes("enotfound") || combined.includes("getaddrinfo")) {
        error = `DNS 解析失败${hostname ? `（${hostname}）` : ""}：${cause || message}`;
    } else if (combined.includes("etimedout")) {
        error = `连接超时${hostname ? `（${hostname}）` : ""}：${cause || message}`;
    } else if (combined.includes("econnrefused")) {
        error = `连接被拒绝${hostname ? `（${hostname}）` : ""}：${cause || message}`;
    } else if (combined.includes("econnreset")) {
        error = `连接被重置${hostname ? `（${hostname}）` : ""}：${cause || message}`;
    }

    return {
        error,
        ...(errorName ? { errorName } : {}),
        ...(cause ? { cause } : {}),
        ...(safeUrl ? { url: safeUrl } : {}),
    };
}

function extractCauseText(err: unknown): string {
    if (!err || typeof err !== "object" || !("cause" in err)) return "";
    const cause = (err as { cause?: unknown }).cause;
    if (!cause) return "";
    if (cause instanceof Error) return cause.message;
    if (typeof cause === "string") return cause;
    if (typeof cause === "object") {
        const detail = cause as Record<string, unknown>;
        const parts = [detail.code, detail.syscall, detail.hostname].filter(Boolean).map(String);
        if (parts.length > 0) return parts.join(" ");
    }
    return String(cause);
}

function safeDebugUrl(rawUrl: string): string | undefined {
    try {
        const url = new URL(rawUrl);
        return `${url.origin}${url.pathname}`;
    } catch {
        return undefined;
    }
}

function safeHostname(rawUrl: string): string | undefined {
    try {
        return new URL(rawUrl).hostname;
    } catch {
        return undefined;
    }
}

// ── SSE helpers ──

function parseSseEndpoint(buffer: string): string {
    const lines = buffer.split("\n");
    let isEndpoint = false;
    for (const line of lines) {
        if (line.startsWith("event:endpoint") || line.startsWith("event: endpoint")) {
            isEndpoint = true;
        } else if (isEndpoint && line.startsWith("data:")) {
            return line.slice(5).trim();
        }
    }
    return "";
}

async function readSseEndpoint(res: Response): Promise<{ endpointPath: string; buffer: string }> {
    const reader = res.body?.getReader();
    if (!reader) return { endpointPath: "", buffer: "" };
    const decoder = new TextDecoder();
    let buffer = "";
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const ep = parseSseEndpoint(buffer);
            if (ep) return { endpointPath: ep, buffer };
        }
    } finally {
        reader.cancel().catch(() => {});
    }
    return { endpointPath: "", buffer };
}

async function readSseEndpointKeepOpen(res: Response): Promise<{ endpointPath: string; reader: ReadableStreamDefaultReader<Uint8Array> | null; decoder: TextDecoder; buffer: string }> {
    const reader = res.body?.getReader() ?? null;
    const decoder = new TextDecoder();
    if (!reader) return { endpointPath: "", reader: null, decoder, buffer: "" };
    let buffer = "";
    while (true) {
        const { done, value } = await reader.read();
        if (done) return { endpointPath: "", reader: null, decoder, buffer };
        buffer += decoder.decode(value, { stream: true });
        const ep = parseSseEndpoint(buffer);
        if (ep) return { endpointPath: ep, reader, decoder, buffer };
    }
}
