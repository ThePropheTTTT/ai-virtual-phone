import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import { ACCOUNT_GATE_COOKIE, ACCOUNT_SESSION_COOKIE } from "./lib/account-cookie-constants";
import { verifyAccountGateCookieValue } from "./lib/account-gate-cookie";
import {
  SELF_HOSTED_KEY_COOKIE,
  SELF_HOSTED_KEY_MAX_AGE_SECONDS,
  SELF_HOSTED_KEY_QUERY_PARAM,
  createSelfHostedKeyCookieValue,
  isSelfHostedAccessGateEnabled,
  matchesSelfHostedAccessKey,
  verifySelfHostedKeyCookieValue,
} from "./lib/self-hosted-access";
import { isSelfHostedModeEnabled } from "./lib/self-hosting";

const PUBLIC_ROUTE_PREFIXES = [
  "/verify",
  "/api/auth/",
  "/api/verify/",
  // iPhone Shortcuts does not share the PWA's login cookies. These handlers
  // validate either the bridge token or a short-lived per-command ticket.
  "/shortcut-run/",
  "/api/push/bridge-wake/",
  "/api/push/shortcut-commands/result/",
  "/api/push/shortcut-commands/media/",
  // 个人云的离线生成把「代发触发邮件」外包给站点，同样没有登录 cookie，
  // 凭 bridge_token 认账号（见该路由内的说明）。
  "/api/push/shortcut-commands/deliver-email/",
];

const STATIC_ROUTE_PREFIXES = [
  "/_next/",
  "/birds/",
  "/diary/",
  "/fonts/",
  "/game-builtins/",
  "/game-covers/",
  "/hdri/",
  "/images/",
  "/models/",
  "/widgets/",
  "/xiaohongshu/",
];

const STATIC_FILE_RE = /\.(?:avif|bin|css|gif|glb|gltf|hdr|ico|jpeg|jpg|js|json|map|mjs|mp3|ogg|otf|png|svg|ttf|txt|wasm|wav|webmanifest|webp|woff|woff2)$/i;

function isPublicRoute(pathname: string): boolean {
  return PUBLIC_ROUTE_PREFIXES.some((prefix) => pathname === prefix.slice(0, -1) || pathname.startsWith(prefix));
}

function isStaticRoute(pathname: string): boolean {
  return STATIC_ROUTE_PREFIXES.some((prefix) => pathname.startsWith(prefix)) || STATIC_FILE_RE.test(pathname);
}

function isApiRoute(pathname: string): boolean {
  return pathname.startsWith("/api/");
}

function rewriteToHome(request: NextRequest): NextResponse {
  const url = request.nextUrl.clone();
  url.pathname = "/";
  url.search = "";
  return NextResponse.rewrite(url);
}

/**
 * 自托管模式下的请求处理。
 *
 * 没设 SELF_HOSTED_ACCESS_KEY 时与过去完全一致（一律放行）。设了密钥之后，
 * /api/** 必须带一枚由密钥派生的 cookie —— 自托管单机版没有账号系统，这是唯一
 * 挡得住「谁扫到 IP 就能拿本站当开放代理、白嫖第三方 key」的东西。
 *
 * 页面本身仍然放行（拿得到外壳，但所有 /api/** 都是 401），这样首次访问可以用
 * ?k=<密钥> 换 cookie；静态资源与 PUBLIC_ROUTE_PREFIXES 也照旧放行。
 */
async function handleSelfHostedRequest(request: NextRequest, pathname: string): Promise<NextResponse> {
  if (!isSelfHostedAccessGateEnabled()) return NextResponse.next();
  if (isStaticRoute(pathname) || isPublicRoute(pathname)) return NextResponse.next();

  const keyCookie = request.cookies.get(SELF_HOSTED_KEY_COOKIE)?.value ?? "";
  if (await verifySelfHostedKeyCookieValue(keyCookie)) return NextResponse.next();

  const providedKey = request.nextUrl.searchParams.get(SELF_HOSTED_KEY_QUERY_PARAM) ?? "";
  if (matchesSelfHostedAccessKey(providedKey)) {
    const response = isApiRoute(pathname) ? NextResponse.next() : stripSelfHostedKeyParam(request);
    const forwardedProto = (request.headers.get("x-forwarded-proto") ?? "").split(",")[0].trim().toLowerCase();
    response.cookies.set({
      name: SELF_HOSTED_KEY_COOKIE,
      value: await createSelfHostedKeyCookieValue(),
      httpOnly: true,
      sameSite: "lax",
      secure: request.nextUrl.protocol === "https:" || forwardedProto === "https",
      path: "/",
      maxAge: SELF_HOSTED_KEY_MAX_AGE_SECONDS,
    });
    return response;
  }

  if (isApiRoute(pathname)) {
    return NextResponse.json(
      { ok: false, error: "缺少本站访问密钥，请用 ?k=<密钥> 打开一次本站。" },
      { status: 401, headers: { "Cache-Control": "no-store" } },
    );
  }

  return NextResponse.next();
}

function firstHeaderValue(value: string | null): string {
  return (value ?? "").split(",")[0].trim();
}

/**
 * 还原用户真正访问的地址来源。
 *
 * 自定义服务器（scripts/local-next-server.mjs）接在 nginx 后面时，`request.nextUrl`
 * 指向的是内网监听地址（实测直接拿它做重定向会给出 https://localhost:3001/），而
 * nginx 的 `proxy_set_header Host $host` 又会把公网端口 8443 剥掉。所以只能自己拼：
 * 协议取 X-Forwarded-Proto，主机取 X-Forwarded-Host（带端口）→ Host，端口缺失时再补
 * X-Forwarded-Port。这几个头都由 nginx 覆写，客户端自带的会被顶掉。
 */
function resolvePublicOrigin(request: NextRequest): string | null {
  const host = firstHeaderValue(request.headers.get("x-forwarded-host")) || firstHeaderValue(request.headers.get("host"));
  if (!host) return null;

  const proto = firstHeaderValue(request.headers.get("x-forwarded-proto")) || request.nextUrl.protocol.replace(":", "") || "http";
  const port = firstHeaderValue(request.headers.get("x-forwarded-port"));
  const isDefaultPort = (proto === "https" && port === "443") || (proto === "http" && port === "80");
  const authority = port && !isDefaultPort && !/:\d+$/.test(host) ? `${host}:${port}` : host;

  return `${proto}://${authority}`;
}

/**
 * 换到 cookie 之后把地址栏里的 ?k= 去掉，免得密钥留在浏览历史与 Referer 里。
 *
 * 重定向必须是绝对地址（相对地址会被 Next 服务器以 `TypeError: Invalid URL` 打成 500），
 * 所以用 resolvePublicOrigin 拼出用户那一侧的地址；拼不出来时才退回 request.nextUrl。
 */
function stripSelfHostedKeyParam(request: NextRequest): NextResponse {
  const url = request.nextUrl.clone();
  url.searchParams.delete(SELF_HOSTED_KEY_QUERY_PARAM);
  const origin = resolvePublicOrigin(request);
  if (origin) {
    try {
      return NextResponse.redirect(new URL(`${url.pathname}${url.search}`, origin));
    } catch {
      // origin 拼坏了就落回下面那条路，别让整页 500。
    }
  }
  return NextResponse.redirect(url);
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (isSelfHostedModeEnabled()) {
    return handleSelfHostedRequest(request, pathname);
  }

  if (isStaticRoute(pathname) || isPublicRoute(pathname)) {
    return NextResponse.next();
  }

  const sessionToken = request.cookies.get(ACCOUNT_SESSION_COOKIE)?.value ?? "";
  const gateCookie = request.cookies.get(ACCOUNT_GATE_COOKIE)?.value ?? "";
  const hasValidGate = await verifyAccountGateCookieValue(gateCookie, sessionToken);

  if (hasValidGate) return NextResponse.next();

  if (isApiRoute(pathname)) {
    return NextResponse.json(
      { ok: false, error: "请先登录账号。" },
      { status: 401, headers: { "Cache-Control": "no-store" } },
    );
  }

  // Existing logged-in browsers may only have the original account session
  // cookie until /api/auth/me refreshes the signed gate cookie.
  if (sessionToken || pathname === "/") return NextResponse.next();

  return rewriteToHome(request);
}

export const config = {
  matcher: [
    "/((?!_next/static|_next/image|.*\\.(?:avif|bin|css|gif|glb|gltf|hdr|ico|jpeg|jpg|js|json|map|mjs|mp3|ogg|otf|png|svg|ttf|txt|wasm|wav|webmanifest|webp|woff|woff2)$).*)",
  ],
};
