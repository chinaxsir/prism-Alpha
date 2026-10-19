import { create } from "zustand";

import {
  activatePro,
  deactivatePro,
  getEntitlement,
  refreshEntitlement,
  type Entitlement,
} from "@/api/ipc";

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

interface ProState {
  entitlement: Entitlement;
  /** 首次状态拉取完成（避免启动瞬间误弹 Pro 窗） */
  ready: boolean;
  unlocked: boolean;
  busy: boolean;
  error: string | null;

  init: () => Promise<void>;
  setEntitlement: (e: Entitlement) => void;
  /** email 必填：服务端强制 License Key + 注册邮箱联合校验 */
  activate: (licenseKey: string, email?: string) => Promise<boolean>;
  refresh: () => Promise<void>;
  deactivate: () => Promise<void>;
}

export const useProStore = create<ProState>((set) => ({
  entitlement: INACTIVE,
  ready: false,
  unlocked: false,
  busy: false,
  error: null,

  init: async () => {
    try {
      const e = await getEntitlement();
      set({ entitlement: e, unlocked: unlockedOf(e), ready: true });
    } catch (err) {
      console.error("get entitlement failed:", err);
      set({ ready: true });
    }
  },

  setEntitlement: (e) =>
    set({ entitlement: e, unlocked: unlockedOf(e), error: null }),

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
