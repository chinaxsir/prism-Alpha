import { useSyncExternalStore } from "react";

/** 【APP49 任务6】App 前台可见性 Hook：后台（锁屏/切 App）时页面轮询
 *  定时器全部暂停清理，回前台立即补拉一次再恢复定时，降低待机功耗。 */
const subscribe = (onStoreChange: () => void) => {
  document.addEventListener("visibilitychange", onStoreChange);
  // pageshow：移动端 bfcache 恢复时 visibilitychange 可能不触发，兜底；
  // focus/blur：部分 WebView 切后台不触发 visibilitychange，兜底重查。
  window.addEventListener("pageshow", onStoreChange);
  window.addEventListener("focus", onStoreChange);
  window.addEventListener("blur", onStoreChange);
  return () => {
    document.removeEventListener("visibilitychange", onStoreChange);
    window.removeEventListener("pageshow", onStoreChange);
    window.removeEventListener("focus", onStoreChange);
    window.removeEventListener("blur", onStoreChange);
  };
};

const getSnapshot = () => document.visibilityState === "visible";

/** App 是否处于前台可见状态（响应式，切换时触发重渲染） */
export function useAppVisible(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot);
}
