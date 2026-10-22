import { create } from "zustand";

import {
  activatePro,
  deactivatePro,
  getEntitlement,
  getRevokeReason,
  refreshEntitlement,
  type Entitlement,
} from "@/api/ipc";

/** 授权被剥夺的原因：unbound=设备被官网解绑，expired=授权到期（IPA-3 任务2） */
export type RevokeReason = "unbound" | "expired" | null;

const INACTIVE: Entitlement = {
  status: "inactive",
  kind: null,
  expiresAt: null,
  source: null,
  lastVerifiedAt: 0,
  plan: null,
  maxSeats: null,
  usedSeats: null,
};

/** 可使用 Pro：仅服务端联网校验有效（active）；offline/expired/revoked/inactive 一律锁定 */
const unlockedOf = (e: Entitlement) => e.status === "active";

/** 前端本地到期巡检定时器（5 秒）；后端另有 10 秒巡检做最终收口 */
let expiryTimer: ReturnType<typeof setInterval> | null = null;

interface ProState {
  entitlement: Entitlement;
  /** 首次状态拉取完成（避免启动瞬间误弹 Pro 窗） */
  ready: boolean;
  unlocked: boolean;
  busy: boolean;
  error: string | null;
  /** 授权被剥夺的原因（unbound/expired）；重新激活成功后自动清空 */
  revokeReason: RevokeReason;

  init: () => Promise<void>;
  setEntitlement: (e: Entitlement) => void;
  setRevokeReason: (r: RevokeReason) => void;
  /** email 必填：服务端强制 License Key + 注册邮箱联合校验 */
  activate: (licenseKey: string, email?: string) => Promise<boolean>;
  refresh: () => Promise<void>;
  deactivate: () => Promise<void>;
  /** 本地到期检查：到点立即锁定 UI 并同步后端终止 Pro 功能 */
  checkExpiry: () => Promise<void>;
}

export const useProStore = create<ProState>((set, get) => ({
  entitlement: INACTIVE,
  ready: false,
  unlocked: false,
  busy: false,
  error: null,
  revokeReason: null,

  init: async () => {
    try {
      const e = await getEntitlement();
      set({ entitlement: e, unlocked: unlockedOf(e), ready: true });
      // 重启后按落盘原因还原横幅：解绑 ≠ 到期，严禁统一显示成「已到期」
      if (!unlockedOf(e)) {
        try {
          const reason = await getRevokeReason();
          if (reason) set({ revokeReason: reason });
        } catch {
          /* 读取失败按无横幅处理，不影响主流程 */
        }
      }
    } catch (err) {
      console.error("get entitlement failed:", err);
      set({ ready: true });
    }
    // 前端本地双重定时器：每 5 秒比对一次到期时间（后端另有 10 秒巡检收口）
    if (!expiryTimer) {
      expiryTimer = setInterval(() => {
        void useProStore.getState().checkExpiry();
      }, 5000);
    }
  },

  checkExpiry: async () => {
    const { entitlement, unlocked, ready } = get();
    if (!ready || !unlocked) return;
    const exp = entitlement.expiresAt;
    // 买断版 expiresAt 为 null，永久有效
    if (!exp || Date.now() < exp * 1000) return;

    // 到点：本地立即锁定，再同步后端（后端会把 license.dat 落盘为 expired
    // 并终止 Go AIM / Go Lan / Go Cus 与内核 Pro 路由）
    set({
      entitlement: { ...entitlement, status: "expired" },
      unlocked: false,
      revokeReason: "expired",
    });
    try {
      const e = await refreshEntitlement();
      set({ entitlement: e, unlocked: unlockedOf(e) });
    } catch {
      // 离线时后端已按本地到期判定锁定，网络错误忽略
    }
  },

  setEntitlement: (e) => {
    const unlocked = unlockedOf(e);
    set({
      entitlement: e,
      unlocked,
      error: null,
      // 重新激活成功（unlocked）→ 立即清除解绑/到期横幅；
      // 状态为 expired 时归因到「授权到期」；其余（含解绑后的 inactive）
      // 保留后端 pro://revoked 已写入的原因，避免横幅被误清。
      revokeReason: unlocked
        ? null
        : e.status === "expired"
          ? "expired"
          : get().revokeReason,
    });
  },

  setRevokeReason: (r) => set({ revokeReason: r }),

  activate: async (licenseKey, email) => {
    set({ busy: true, error: null });
    try {
      // 服务端要求「License Key + 注册邮箱」联合校验（两者必填）；
      // 缺项时后端会在本地拦截并返回明确错误，不会发起无效请求。
      const e = await activatePro(licenseKey, email ?? "");
      set({ entitlement: e, unlocked: unlockedOf(e), busy: false });
      return unlockedOf(e);
    } catch (err) {
      // 保留完整错误文本（429 限流时含 retry_after，UI 需解析）
      const message =
        typeof err === "string"
          ? err
          : err instanceof Error
            ? err.message
            : String(err);
      set({ busy: false, error: message || "激活失败" });
      return false;
    }
  },

  refresh: async () => {
    set({ busy: true, error: null });
    try {
      const e = await refreshEntitlement();
      set({ entitlement: e, unlocked: unlockedOf(e), busy: false });
    } catch (err) {
      set({ busy: false, error: String(err) });
    }
  },

  deactivate: async () => {
    const e = await deactivatePro();
    set({ entitlement: e, unlocked: unlockedOf(e), error: null });
  },
}));
