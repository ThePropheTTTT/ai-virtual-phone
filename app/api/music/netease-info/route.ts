import { NextRequest, NextResponse } from "next/server";
import { fetch as undiciFetch } from "undici";

import {
    CLIENT_BASE_HEADER,
    CLIENT_BUILD_HEADER,
    requestOriginInfo,
    resolveUpstreamWithSource,
    upstreamDispatcher,
} from "@/lib/server/netease-upstream";

/**
 * 网易云代理状态与诊断。
 *
 * 让设置界面能展示当前实际使用的上游地址、并做一次连通性探测。上游地址的解析与
 * 代理路由共用同一份逻辑（含客户端传入地址的安全校验），保证「测试连接」的结论
 * 与真实转发一致。
 *
 * 返回里额外带上诊断字段，专门用来排查「电脑好、手机不行」这类只在某个设备上
 * 出现的问题——那种情况下光看地址分不清是哪一环：
 *   - source        地址来自用户填写 / 服务端环境变量 / 从请求 Host 推导
 *   - serverBuild   服务端构建标识（.next/BUILD_ID），判断服务器跑的是哪一版
 *   - clientBuild   客户端通过请求头自报的构建标识，判断**设备上跑的是不是新代码**
 *   - seenBaseHeader 服务端是否真的收到了客户端带来的地址头
 */

export const runtime = "nodejs";
export const maxDuration = 30;

/**
 * 服务端构建标识。读 .next/BUILD_ID：自定义 server（node scripts/local-next-server.mjs）
 * 不经过 Next CLI，构建期环境变量在这里读不到，而这个文件是构建产物、始终存在。
 */
async function serverBuildInfo(): Promise<{ buildId: string; builtAt: string }> {
    try {
        const fs = await import("node:fs/promises");
        const path = await import("node:path");
        const file = path.join(process.cwd(), ".next", "BUILD_ID");
        const buildId = (await fs.readFile(file, "utf8")).trim();
        let builtAt = "";
        try {
            const stat = await fs.stat(file);
            builtAt = stat.mtime.toISOString();
        } catch { /* 时间拿不到就算了 */ }
        return { buildId, builtAt };
    } catch {
        return { buildId: "", builtAt: "" };
    }
}

export async function GET(request: NextRequest) {
    const { host, protocol } = requestOriginInfo(request);
    const clientBaseHeader = request.headers.get(CLIENT_BASE_HEADER);
    const { baseUrl, source } = resolveUpstreamWithSource(clientBaseHeader, host, protocol);
    const clientBuild = request.headers.get(CLIENT_BUILD_HEADER) || "";
    const server = await serverBuildInfo();
    const diagnostics = {
        serverBuild: server.buildId,
        serverBuiltAt: server.builtAt,
        clientBuild,
        seenBaseHeader: Boolean(clientBaseHeader && clientBaseHeader.trim()),
        seenBaseHeaderValue: clientBaseHeader || "",
        seenHost: host || "",
        seenProtocol: protocol,
    };
    /** 顶层也暴露服务端构建标识：一条 curl 就能判断部署的是不是新版，不用翻设置页 */
    const buildEnvelope = {
        serverBuild: server.buildId,
        serverBuiltAt: server.builtAt,
    };
    if (!baseUrl) {
        return NextResponse.json({
            configured: false,
            reachable: false,
            baseUrl: "",
            source,
            diagnostics,
            ...buildEnvelope,
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
                source,
                diagnostics,
                ...buildEnvelope,
                message: `上游返回 HTTP ${probe.status}（地址可达但接口异常）`,
            });
        }
        const data = await probe.json().catch(() => null) as { result?: unknown; code?: number } | null;
        const hasResult = Boolean(data && (data.result || data.code === 200));
        return NextResponse.json({
            configured: true,
            reachable: hasResult,
            baseUrl,
            source,
            diagnostics,
            ...buildEnvelope,
            message: hasResult ? "连接成功" : "上游返回格式异常",
        });
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        return NextResponse.json({
            configured: true,
            reachable: false,
            baseUrl,
            source,
            diagnostics,
            ...buildEnvelope,
            message: `无法连接上游（${baseUrl}）：${detail}`,
        });
    }
}
