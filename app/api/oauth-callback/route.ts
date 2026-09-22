import { NextRequest, NextResponse } from "next/server";

/**
 * OAuth callback endpoint.
 * Authorization server redirects here with ?code=xxx&state=xxx
 * We render a simple page that posts the result back to the opener window.
 */

/**
 * 把查询参数安全地嵌进内联 <script>。
 * JSON.stringify 不转义 `</script>`，直接把用户可控的 code/state/error 插进脚本会让
 * `?code=</script><script>...</script>` 逃出脚本标签，形成本站源上的反射型 XSS
 * （该 PWA 的 LLM API 密钥与聊天记录都在浏览器本地，XSS 可直接窃取）。
 * 这里转义 < > & 与行分隔符：JSON 数值/字符串语义不变，但无法再闭合标签。
 */
function safeJsonForInlineScript(value: unknown): string {
    return JSON.stringify(value)
        .replace(/</g, "\\u003c")
        .replace(/>/g, "\\u003e")
        .replace(/&/g, "\\u0026")
        .replace(/\u2028/g, "\\u2028")
        .replace(/\u2029/g, "\\u2029");
}

export async function GET(req: NextRequest) {
    const code = req.nextUrl.searchParams.get("code") || "";
    const state = req.nextUrl.searchParams.get("state") || "";
    const error = req.nextUrl.searchParams.get("error") || "";
    const callbackPayload = {
        state,
        code,
        error,
        createdAt: Date.now(),
    };

    // Return a minimal HTML page that communicates back to the opener
    const html = `<!DOCTYPE html><html><head><title>授权完成</title><meta name="viewport" content="width=device-width,initial-scale=1"></head><body>
<script>
  var payload = ${safeJsonForInlineScript(callbackPayload)};
  try {
    window.localStorage.setItem("ai_phone_mcp_oauth_callback_v1", JSON.stringify(payload));
  } catch(e) {}
  try {
    if (window.opener) {
      window.opener.postMessage({
        type: "mcp-oauth-callback",
        code: ${safeJsonForInlineScript(code)},
        state: ${safeJsonForInlineScript(state)},
        error: ${safeJsonForInlineScript(error)}
      }, window.location.origin);
    }
  } catch(e) {}
  setTimeout(function() {
    try {
      if (window.opener) {
        window.close();
        return;
      }
    } catch(e) {}
    window.location.replace("/");
  }, 800);
</script>
<p>授权完成，正在返回 Float...</p>
</body></html>`;

    return new NextResponse(html, {
        headers: {
            "Content-Type": "text/html",
            // 双保险：即便将来又引入注入点，也禁止页面加载外部脚本。
            "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff",
        },
    });
}
