import { Agent } from "undici";

/**
 * 网易云 API 上游地址的解析与安全校验，供代理路由与状态查询路由共用。
 *
 * 为什么需要一个「上游地址」的概念：自部署的 NeteaseCloudMusicApi 通常用自签名证书
 * 跑 HTTPS（或只在内网可达），而浏览器对 fetch 发起的跨域请求**不提供「忽略证书
 * 警告」的选项**——证书不受信或 SAN 与访问地址不一致时请求直接被拒，CORS 配好了
 * 也一样失败。因此音乐请求统一经本站服务端转发。
 *
 * 这里**不写死任何上游地址**（见 resolveUpstreamWithSource 的三层解析）。
 * 唯一与「4001」有关的是 NETEASE_API_DERIVE_PORT，且它是可配的环境变量。
 */

/**
 * 取请求自身的 Host 与协议，供「从请求推导上游地址」使用。
 * 经 nginx 等反代后原始 Host 在转发头里，所以优先读 x-forwarded-*。
 */
export function requestOriginInfo(request: {
    headers: { get(name: string): string | null };
    nextUrl: { protocol: string };
}): { host: string | null; protocol: string } {
    const host = request.headers.get("x-forwarded-host") || request.headers.get("host");
    const forwardedProto = request.headers.get("x-forwarded-proto");
    const protocol = forwardedProto
        ? `${forwardedProto.split(",")[0].trim()}:`
        : request.nextUrl.protocol;
    return { host, protocol };
}

/**
 * 客户端用这个头把「设置里填的 API 地址」带上来。
 *
 * 这是首选来源：`.env.local` 是 gitignore 的，本地配好不会同步到部署的服务器，
 * 所以让浏览器把用户在设置里填的值带上，就不依赖任何部署时配置。
 */
export const CLIENT_BASE_HEADER = "x-netease-base";

/** 自签名证书的实例需要关掉校验才能连上；仅影响本代理到上游这一跳。 */
export const ALLOW_INSECURE_UPSTREAM =
    (process.env.NETEASE_API_INSECURE || "true").trim().toLowerCase() !== "false";

let insecureDispatcher: Agent | null = null;

/**
 * 关闭证书校验的 dispatcher。
 *
 * 必须用 undici 的 Agent：全局 fetch 在应用启动后再改
 * NODE_TLS_REJECT_UNAUTHORIZED 已经不生效了，只有 dispatcher 方式可靠。
 */
export function upstreamDispatcher(): Agent | null {
    if (!ALLOW_INSECURE_UPSTREAM) return null;
    if (!insecureDispatcher) {
        insecureDispatcher = new Agent({ connect: { rejectUnauthorized: false } });
    }
    return insecureDispatcher;
}

/**
 * 校验收客户端送来的上游地址。
 *
 * 允许客户端指定上游是刻意的取舍：这个代理只服务一个自部署实例，而部署时的环境
 * 变量不可靠。但它把这里变成了「用户可指定目标」的转发器，所以必须挡住最危险的
 * 用法——尤其是云元数据地址（169.254.169.254）与回环/内网，避免代理被用来探测
 * 服务器所在网络。返回 null 表示不采用，回退到服务端配置。
 */
export function sanitizeClientBase(raw: string | null): string | null {
    if (!raw) return null;
    let url: URL;
    try {
        url = new URL(raw.trim());
    } catch {
        return null;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;

    // 去掉 FQDN 根点，避免 localhost. 这类写法绕过字符串比较
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
    const isIpv6 = host.includes(":");

    const parts = host.split(".").map(Number);
    const isIpv4 = parts.length === 4 && parts.every(n => Number.isInteger(n) && n >= 0 && n <= 255);
    const privateIpv4 = isIpv4 && (
        parts[0] === 0 || parts[0] === 10 || parts[0] === 127
        || (parts[0] === 169 && parts[1] === 254)
        || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
        || (parts[0] === 192 && parts[1] === 168)
        || (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
    );
    const blockedHost = host === "localhost"
        || host.endsWith(".localhost")
        || host.endsWith(".local")
        || host.endsWith(".internal")
        || host === "::1"
        || host === "0:0:0:0:0:0:0:1"
        || (isIpv6 && (host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80") || host.startsWith("::ffff:")))
        || privateIpv4;

    if (blockedHost) return null;
    return `${url.protocol}//${url.host}`;
}

/**
 * 校验「由请求 Host 推导出来的」地址。
 *
 * 与 sanitizeClientBase 的区别：推导用的 Host 来自**请求本身**，没有攻击者能控制它
 * （能改 Host 的人本来就能直接访问服务器），所以不必按客户端输入那样严苛。
 *
 * 但有一类必须放行、sanitizeClientBase 却会挡掉的：**回环地址**。
 * 上游与站点同机部署时它就是 http://127.0.0.1:4001 / http://localhost:4001，
 * 这是最常见的情形，挡掉等于这个回退层永远不生效。
 *
 * 仍然挡住私网段与云元数据／组播地址——保留它们是无谓地把内部拓扑暴露给上游跳转。
 */
function isAcceptableDerivedBase(candidate: string): boolean {
    let url: URL;
    try {
        url = new URL(candidate);
    } catch {
        return false;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;

    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");

    // 回环：允许（同机部署的常态）
    if (host === "localhost" || host === "::1" || host === "0:0:0:0:0:0:0:1") return true;

    const parts = host.split(".").map(Number);
    const isIpv4 = parts.length === 4 && parts.every(n => Number.isInteger(n) && n >= 0 && n <= 255);
    if (isIpv4) {
        // 127.0.0.0/8 之外，其余非公网段一律拒绝
        if (parts[0] === 127) return true;
        return !(
            parts[0] === 0
            || parts[0] === 10
            || (parts[0] === 169 && parts[1] === 254)
            || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
            || (parts[0] === 192 && parts[1] === 168)
            || (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127)
            || parts[0] >= 224
        );
    }

    if (host.includes(":")) {
        // IPv6：回环已在上面放行，其余本地/组播段拒绝
        return !(host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80") || host.startsWith("ff"));
    }

    // 普通域名
    return !(host.endsWith(".local") || host.endsWith(".internal"));
}

/**
 * 上游地址解析。**没有任何写死的地址**，三层依次回退：
 *
 *   1. `settings`  客户端设置里填的地址（x-netease-base 头）——用户显式指定，优先级最高
 *   2. `env`       服务端 NETEASE_API_BASE / NEXT_PUBLIC_DEFAULT_NETEASE_API_BASE
 *   3. `derived`   从本次请求的 Host 推导：同协议 + 可配端口（默认 4001）
 *
 * 第 3 层是为了「零配置也能用」：小手机与 NeteaseCloudMusicApi 常同机部署，
 * 用浏览器正在访问的主机名换掉端口通常正好命中，且不依赖任何环境变量。
 *
 * 同时返回 source，供 netease-info 暴露——排查「地址到底从哪来」时，
 * 光看地址本身分不清是用户填的、环境变量给的、还是推导出来的。
 */
export type UpstreamSource = "settings" | "settings-rejected" | "env" | "derived";

export type UpstreamResolution = {
    baseUrl: string;
    source: UpstreamSource;
};

/**
 * 推导时替换成的端口。
 *
 * 与客户端共用同一个变量（NEXT_PUBLIC_NETEASE_API_PORT）：客户端推导出的地址会经
 * 请求头优先采用，这里只是「没带头时」的兜底。两边用同一个名字，才不会出现
 * 「客户端按 4001 推导、服务端按别的端口推导」这种配歪的情况。
 * 仍保留读取 NETEASE_API_DERIVE_PORT 作为兼容。
 */
function derivedPort(): string {
    const raw = process.env.NEXT_PUBLIC_NETEASE_API_PORT
        || process.env.NETEASE_API_DERIVE_PORT
        || "4001";
    return raw.trim() || "4001";
}

/**
 * 用请求自身的 Host 推导上游地址：保留协议，把端口换成上游端口。
 *
 * 例：请求来自 http://localhost:3001、上游端口 4001
 *     → http://localhost:4001
 *     请求来自 https://phone.example.com
 *     → https://phone.example.com:4001
 * 请求本身就跑在上游端口上时不推导（那是站点端口，不是上游）。
 */
function deriveFromRequestHost(requestHost: string | null, protocol: string): string {
    const raw = (requestHost || "").trim();
    if (!raw) return "";
    const port = derivedPort();
    try {
        const parsed = new URL(`${protocol}//${raw}`);
        const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
        if (!hostname) return "";
        if (parsed.port === port) return "";
        // IPv6 字面量要重新加回方括号
        const hostPart = hostname.includes(":") ? `[${hostname}]` : hostname;
        const candidate = `${parsed.protocol}//${hostPart}:${port}`;
        // 推导来源用宽松校验（见 isAcceptableDerivedBase）：
        // 回环是允许的，这里正是最常见的同机部署形态。
        return isAcceptableDerivedBase(candidate) ? candidate : "";
    } catch {
        return "";
    }
}

export function resolveUpstreamWithSource(
    clientBase: string | null,
    requestHost?: string | null,
    protocol?: string,
): UpstreamResolution {
    // 1. 用户设置
    const sanitized = sanitizeClientBase(clientBase);
    if (sanitized) return { baseUrl: sanitized, source: "settings" };
    // 带了值但没通过校验，单独标出来——通常是内网地址被安全策略挡了
    const rejected = Boolean(clientBase && clientBase.trim());

    // 2. 服务端环境变量
    const fromEnv = (process.env.NETEASE_API_BASE || process.env.NEXT_PUBLIC_DEFAULT_NETEASE_API_BASE || "").trim();
    if (fromEnv) {
        return {
            baseUrl: fromEnv.replace(/\/+$/, ""),
            source: rejected ? "settings-rejected" : "env",
        };
    }

    // 3. 从请求 Host 推导
    const derived = deriveFromRequestHost(requestHost || null, protocol || "http:");
    return { baseUrl: derived, source: rejected ? "settings-rejected" : "derived" };
}

export function resolveUpstreamBase(
    clientBase: string | null,
    requestHost?: string | null,
    protocol?: string,
): string {
    return resolveUpstreamWithSource(clientBase, requestHost, protocol).baseUrl;
}
