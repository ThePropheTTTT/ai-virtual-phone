/**
 * Web Crypto 的 HMAC-SHA256 原语。
 *
 * 只放最底层的一份实现：账号门禁 cookie 的签名（lib/account-gate-cookie.ts）与
 * 自托管模式的站点访问密钥（lib/self-hosted-access.ts）都用它。两处各自抄一遍
 * 的话，哪天只改了一边就会出现「签名能验过、密钥验不过」这种极难查的分叉。
 */
const encoder = new TextEncoder();

export function bytesToBase64Url(bytes: ArrayBuffer): string {
  const array = new Uint8Array(bytes);
  let binary = "";
  for (const byte of array) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function hmacSha256(input: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(input));
  return bytesToBase64Url(signature);
}

/** 定长比较：长度不同直接 false，否则按位累积差异，不提前 return。 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) {
    diff |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return diff === 0;
}
