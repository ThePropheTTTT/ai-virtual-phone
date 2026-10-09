"use client";

import { useEffect } from "react";

import { getRuntimePwaDisplayMode, PWA_DISPLAY_MODE_CHANGED_EVENT } from "@/lib/pwa-display-mode";

export function PWAManifestInjector() {
  useEffect(() => {
    const root = document.documentElement;
    const displayModeQueries = ["fullscreen", "standalone", "minimal-ui"].map(mode => (
      window.matchMedia(`(display-mode: ${mode})`)
    ));

    const syncRuntimeDisplayMode = () => {
      // 独立窗口 / 最小 UI 下，顶部那条系统状态栏是真实存在且不透明的（iOS 从
      // apple-mobile-web-app-status-bar-style: default 起就是「内容在状态栏下面」），
      // 所以这时必须切到「用系统安全区、不再自留 48px 虚拟状态栏」的模式：
      // 否则顶上会重复空出一条、整页被往下推，底部还会被切掉、点不到。
      // fullscreen（真·全屏、没有系统栏）不挂标记，保持沉浸外观并继续画虚拟状态栏。
      const mode = getRuntimePwaDisplayMode();
      if (mode === "browser") {
        delete root.dataset.pwaDisplayMode;
      } else {
        root.dataset.pwaDisplayMode = mode;
      }
    };

    const refreshManifest = () => {
      const link = document.querySelector<HTMLLinkElement>('link[rel="manifest"]');
      if (!link) return;
      const base = (link.getAttribute("href") || "/manifest.webmanifest").split("?")[0];
      link.setAttribute("href", `${base}?v=${Date.now()}`);
    };

    const handleSettingsChanged = () => {
      syncRuntimeDisplayMode();
      refreshManifest();
    };

    syncRuntimeDisplayMode();
    refreshManifest();
    document.addEventListener("fullscreenchange", syncRuntimeDisplayMode);
    window.addEventListener("pageshow", syncRuntimeDisplayMode);
    window.addEventListener(PWA_DISPLAY_MODE_CHANGED_EVENT, handleSettingsChanged);
    displayModeQueries.forEach(query => query.addEventListener("change", syncRuntimeDisplayMode));

    return () => {
      document.removeEventListener("fullscreenchange", syncRuntimeDisplayMode);
      window.removeEventListener("pageshow", syncRuntimeDisplayMode);
      window.removeEventListener(PWA_DISPLAY_MODE_CHANGED_EVENT, handleSettingsChanged);
      displayModeQueries.forEach(query => query.removeEventListener("change", syncRuntimeDisplayMode));
      delete root.dataset.pwaDisplayMode;
    };
  }, []);

  return null;
}
