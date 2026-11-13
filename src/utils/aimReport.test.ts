import { describe, expect, it } from "vitest";

import { formatStandardNodeAimReport } from "./aimReport";
import type { AimNodeResult } from "@/api/ipc";

const result: AimNodeResult = {
  nodeName: "2x专线-日本-1",
  unlockedTags: ["GPT"],
  aiUnlocked: true,
  mediaUnlocked: false,
  score: 44,
  delayMs: 86,
  updatedAt: 1_700_000_000,
  detectedAt: 1_700_000_000,
  egressIp: "203.0.113.8",
  egressCountry: "JP",
  probeVersion: 4,
  probed: true,
  services: {
    GPT: {
      service: "GPT",
      verdict: "PARTIAL",
      statusCode: 200,
      evidence: "server_status normal",
      elapsedMs: 320,
      verdictBasis: "server_status=normal",
    },
    Gemini: {
      service: "Gemini",
      verdict: "ACCESSIBLE",
      statusCode: 302,
      evidence: "normal redirect",
      elapsedMs: 180,
      verdictBasis: "首跳正常重定向",
    },
  },
};

describe("formatStandardNodeAimReport", () => {
  it("中文报告字段完整且按平台顺序输出", () => {
    const text = formatStandardNodeAimReport({
      node: "2x专线-日本-1",
      protocol: "VLESS",
      result,
      lang: "zh",
      now: new Date("2026-01-01T00:00:00.000Z"),
    });
    expect(text).toContain("节点名称: 2x专线-日本-1");
    expect(text).toContain("节点类型: VLESS");
    expect(text).toContain("出口IP: 203.0.113.8");
    expect(text).toContain("出口地区: JP");
    expect(text).toContain("综合评分: 44 / 140");
    expect(text).toContain("探测版本: v4");
    expect(text).toContain("- GPT: PARTIAL | HTTP 200 | 320ms | 判定依据:");
    expect(text).toContain("- Gemini: ACCESSIBLE | HTTP 302 | 180ms | 判定依据:");
    expect(text.indexOf("- GPT")).toBeLessThan(text.indexOf("- Gemini"));
  });

  it("英文报告使用英文标签", () => {
    const text = formatStandardNodeAimReport({
      node: "2x-JP-1",
      protocol: "VLESS",
      result,
      lang: "en",
      now: new Date("2026-01-01T00:00:00.000Z"),
    });
    expect(text).toContain("Node Name: 2x-JP-1");
    expect(text).toContain("Overall Score: 44 / 140");
    expect(text).toContain("Probe Version: v4");
    expect(text).toContain("- GPT: PARTIAL | HTTP 200 | 320ms | Basis:");
  });

  it("无平台数据时也给出可读占位", () => {
    const text = formatStandardNodeAimReport({
      node: "empty",
      lang: "zh",
      result: { ...result, services: {} },
    });
    expect(text).toContain("- 暂无平台数据");
  });
});
