import { Agent } from "undici";

/**
 * 网易云 API 上游地址的解析与安全校验，供代理路由与状态查询路由共用。
 *
 * 为什么需要一个「上游地址」的概念：自部署的 NeteaseCloudMusicApi 通常用自签名证书
 * 跑 HTTPS（或只在内网可达），而浏览器对 fetch 发起的跨域请求**不提供「忽略证书
 * 警告」的选项**——证书不受信或 SAN 与访问地址不一致时请求直接被拒，CORS 配好了
 * 也一样失败。因此音乐请求统一经本站服务端转发。
 */

/**
 * 同机部署时的回退地址。
 *
 * 必须是 **https**：NeteaseCloudMusicApi 常挂在只收 HTTPS 的端口后面——实测
 * http://…:4001 会被 nginx 以 400 "plain HTTP request was sent to HTTPS port"
 * 拒绝，在界面上表现为代理「地址可达但接口异常」。证书多为自签名，由
 * upstreamDispatcher() 关掉校验，所以走回环也能连上。
 */
export const DEFAULT_UPSTREAM = "https://127.0.0.1:4001";

/**
 * 客户端用这个头把「我自己填的 API 地址」带上来。
 *
 * 为什么需要：服务端环境变量（.env.local）是 gitignore 的，本地配好不会同步到
 * 部署的服务器，服务器上代理就会回退到回环地址而连不上——表现为「本地好的、
 * 线上跟没改一样」。让客户端把地址带上来，就不依赖任何部署时配置。
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
 * 上游地址优先级：
 *   1. 客户端带来的地址（前提：通过了上面的安全校验）
 *   2. 服务端 NETEASE_API_BASE
 *   3. NEXT_PUBLIC_DEFAULT_NETEASE_API_BASE
 *   4. 本机回环默认值
 *
 * 同时返回来源，供 netease-info 暴露出来——排查「地址到底从哪来的」时，
 * 光看地址本身分不清是客户端送来的还是服务端回退的。
 */
export type UpstreamResolution = {
    baseUrl: string;
    source: "client-header" | "client-header-rejected" | "env" | "default";
};

export function resolveUpstreamWithSource(clientBase: string | null): UpstreamResolution {
    const sanitized = sanitizeClientBase(clientBase);
    if (sanitized) return { baseUrl: sanitized, source: "client-header" };
    // 带了头但没通过校验，单独标出来——这通常意味着内网地址被挡了
    const rejected = Boolean(clientBase && clientBase.trim());

    const fromEnv = (process.env.NETEASE_API_BASE || process.env.NEXT_PUBLIC_DEFAULT_NETEASE_API_BASE || "").trim();
    if (fromEnv) {
        return { baseUrl: fromEnv.replace(/\/+$/, ""), source: rejected ? "client-header-rejected" : "env" };
    }
    return { baseUrl: DEFAULT_UPSTREAM, source: rejected ? "client-header-rejected" : "default" };
}

export function resolveUpstreamBase(clientBase: string | null): string {
    return resolveUpstreamWithSource(clientBase).baseUrl;
}
