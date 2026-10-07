import { constantTimeEqual, hmacSha256 } from "./crypto-hmac";

/**
 * 自托管模式的站点访问密钥（SELF_HOSTED_ACCESS_KEY）。
 *
 * 为什么需要它：打开 NEXT_PUBLIC_SELF_HOSTED_MODE 之后 middleware 对**所有**请求
 * 无条件放行，于是 /api/** 在公网上等于零鉴权——/api/tool-proxy 成了任何人可用的
 * 开放代理，/api/image-hosting/imgbb 白送第三方额度，/api/supabase-admin 之类只要
 * 配了 env 就是全开的。自托管单机版没有账号系统，也就没有任何东西能挡在前面。
 *
 * 这里只加密钥门禁，不改自托管模式本身：
 *   - 没设 SELF_HOSTED_ACCESS_KEY 时行为与过去完全一致（一律不拦），保证升级不炸；
 *   - 设了之后 /api/** 要一枚由密钥派生出的 cookie；首次访问带 ?k=<密钥> 即可拿到，
 *     cookie 里存的是 HMAC 摘要而不是密钥原文；
 *   - 静态资源与 middleware 的 PUBLIC_ROUTE_PREFIXES（iOS 快捷指令、云端函数回调）
 *     始终放行——它们各自带 bridge token / 一次性票据，本来就没有 cookie。
 *
 * 注意 SELF_HOSTED_ACCESS_KEY 故意不带 NEXT_PUBLIC_ 前缀：它只给服务端的
 * middleware 读，不会被打包进浏览器。
 */
export const SELF_HOSTED_KEY_COOKIE = "ai_phone_self_hosted_key";
export const SELF_HOSTED_KEY_QUERY_PARAM = "k";
export const SELF_HOSTED_KEY_MAX_AGE_SECONDS = 60 * 60 * 24 * 365;

const SIGNATURE_INPUT = "ai-phone-self-hosted-access-v1";

export function readSelfHostedAccessKey(): string {
  return (process.env.SELF_HOSTED_ACCESS_KEY || "").trim();
}

export function isSelfHostedAccessGateEnabled(): boolean {
  return readSelfHostedAccessKey().length > 0;
}

export async function createSelfHostedKeyCookieValue(): Promise<string> {
  const key = readSelfHostedAccessKey();
  if (!key) return "";
  return hmacSha256(SIGNATURE_INPUT, key);
}

export async function verifySelfHostedKeyCookieValue(value: string): Promise<boolean> {
  if (!value) return false;
  const expected = await createSelfHostedKeyCookieValue();
  if (!expected) return false;
  return constantTimeEqual(value, expected);
}

export function matchesSelfHostedAccessKey(provided: string): boolean {
  const key = readSelfHostedAccessKey();
  if (!key || !provided) return false;
  return constantTimeEqual(provided, key);
}
