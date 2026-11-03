/// 【APP43 任务3】域名工具：根域提取（规则页 / 连接快捷规则 / 目标选择器共用）
///
/// 常见多段公共后缀（两级 TLD）。不引入 200KB+ 的 PSL 数据，只覆盖
/// 国内/海外高频后缀，未命中时退化为「最后两段」，满足绝大多数字母级根域提取。
const MULTI_PART_SUFFIXES = new Set([
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  "co.uk", "org.uk", "me.uk", "com.au", "net.au", "org.au",
  "co.jp", "or.jp", "ne.jp", "com.br", "com.tw", "com.hk",
  "co.kr", "com.sg", "com.tr", "co.nz", "co.za", "com.mx",
]);

/// 从用户输入（完整 URL / 子域名 / 带路径的域名）中提取可注册根域名。
/// 如 https://www.example.com/path → example.com；a.b.example.co.uk → example.co.uk
export function extractRootDomain(raw: string): string {
  let host = raw.trim().toLowerCase();
  if (!host) return "";
  // 完整 URL：取 hostname
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(host)) {
    try {
      host = new URL(host).hostname;
    } catch {
      return raw.trim();
    }
  } else {
    host = host.split("/")[0].split("?")[0];
  }
  host = host.replace(/^[.]+/, "").replace(/^\*\./, "");
  // 纯 IP / localhost / 非域名不处理
  if (/^[\d.]+$/.test(host) || host === "localhost" || !host.includes(".")) {
    return host;
  }
  const labels = host.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join(".");
  }
  return lastTwo;
}

/// 纯 IPv4 / IPv6 字面量判断（快捷规则里区分域名与 IP）
export function isIpHost(host: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":");
}
