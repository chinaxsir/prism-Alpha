import { platform } from "@tauri-apps/plugin-os";

export enum Feature {
  MultiSubscription = "multiSubscription",
  Connections = "connections",
  Rules = "rules",
  GoAim = "goAim",
  GoLan = "goLan",
  GoCus = "goCus",
}

export const FEATURE_LABEL: Record<Feature, string> = {
  [Feature.MultiSubscription]: "多订阅",
  [Feature.Connections]: "连接管理",
  [Feature.Rules]: "规则自定义",
  [Feature.GoAim]: "Go AIM 解锁加速",
  [Feature.GoLan]: "Go Lan 回家网络",
  [Feature.GoCus]: "Go Cus 覆写引擎",
};

let cachedMobile: boolean | null = null;

/**
 * 是否移动端。移动端额外提供 StoreKit / Google Play 购买入口；
 * 桌面端通过激活码授权。授权本身全平台一致（服务端统一签发）。
 * 调试后门：URL query ?forceMobile=1 强制移动端，?forceMobile=0 强制桌面端。
 * 非 Tauri 环境（platform 调用失败）默认按桌面端处理。
 */
export function isMobile(): boolean {
  if (cachedMobile !== null) return cachedMobile;

  try {
    const force = new URLSearchParams(window.location.search).get(
      "forceMobile"
    );
    if (force === "1") {
      cachedMobile = true;
      return true;
    }
    if (force === "0") {
      cachedMobile = false;
      return false;
    }
  } catch {
    // ignore
  }

  try {
    const p = platform();
    cachedMobile = p === "ios" || p === "android";
  } catch {
    cachedMobile = false;
  }
  return cachedMobile;
}
