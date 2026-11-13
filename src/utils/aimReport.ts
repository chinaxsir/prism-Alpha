import type { AimNodeResult, ServiceProbeResult } from "@/api/ipc";

const PLATFORM_ORDER = ["GPT", "Claude", "Gemini", "NF", "YT", "Disney+", "TK"];

export type AimReportLang = "zh" | "en";

export interface AimReportInput {
  node: string;
  protocol?: string;
  result?: AimNodeResult | null;
  lang: AimReportLang;
  now?: Date;
}

/**
 * 生成中英双语标准节点报告纯文本（APP73 任务4.2）。
 * 字段顺序固定，只包含证据级摘要，绝不包含完整 HTTP 响应正文。
 */
export function formatStandardNodeAimReport({
  node,
  protocol,
  result,
  lang,
  now = new Date(),
}: AimReportInput): string {
  const services = result?.services ?? {};
  const probed = Boolean(result?.probed);
  const exportedAt = now.toISOString();
  const detectedAt = result?.detectedAt
    ? new Date(result.detectedAt * 1000).toISOString()
    : "—";
  const score = result?.score ?? 0;
  const version = result?.probeVersion ?? 0;
  const lines: string[] =
    lang === "en"
      ? [
          `Node Name: ${node}`,
          `Node Type: ${protocol || "—"}`,
          `Detected At: ${detectedAt}`,
          `Exported At: ${exportedAt}`,
          `Egress IP: ${result?.egressIp || "—"}`,
          `Egress Region: ${result?.egressCountry || "—"}`,
          `Overall Score: ${score} / 140`,
          `Probe Version: v${version || "—"}`,
          `Probe Status: ${probed ? "Completed" : "Not probed"}`,
          "Platform Details:",
        ]
      : [
          `节点名称: ${node}`,
          `节点类型: ${protocol || "—"}`,
          `检测时间: ${detectedAt}`,
          `导出时间: ${exportedAt}`,
          `出口IP: ${result?.egressIp || "—"}`,
          `出口地区: ${result?.egressCountry || "—"}`,
          `综合评分: ${score} / 140`,
          `探测版本: v${version || "—"}`,
          `检测状态: ${probed ? "已完成完整探测" : "尚未探测"}`,
          "平台明细:",
        ];

  const rows = PLATFORM_ORDER.filter((name) => services[name]);
  if (rows.length === 0) {
    lines.push(lang === "en" ? "- No platform data" : "- 暂无平台数据");
  } else {
    for (const name of rows) {
      lines.push(formatRow(name, services[name], lang));
    }
  }
  return lines.join("\n");
}

function formatRow(
  name: string,
  service: ServiceProbeResult,
  lang: AimReportLang,
): string {
  const parts: string[] = [service.verdict];
  if (service.statusCode != null) {
    parts.push(`HTTP ${service.statusCode}`);
  }
  if (service.elapsedMs != null) {
    parts.push(`${service.elapsedMs}ms`);
  }
  const basis =
    service.verdictBasis ||
    service.evidence ||
    service.failureReason ||
    (lang === "en" ? "No evidence" : "无明确证据");
  parts.push(`${lang === "en" ? "Basis" : "判定依据"}: ${basis}`);
  return `- ${name}: ${parts.join(" | ")}`;
}
