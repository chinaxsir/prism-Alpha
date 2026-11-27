import { describe, expect, it } from "vitest";
import {
  computeModuleStats,
  extractInlineScripts,
  parseUniversalModuleLocal,
  removeCustomHost,
  removeCustomMitmHost,
  removeCustomRewrite,
  removeCustomScript,
  upsertCustomHost,
  upsertCustomMitmHosts,
  upsertCustomRewrite,
  upsertCustomScript,
} from "./goCusParser";

describe("goCusParser", () => {
  it("parses Surge / QuanX / Loon sections accurately (no bracket bug)", () => {
    const raw = `#!name=Test Module
#!desc=Sample
[Rule]
DOMAIN-SUFFIX,doubleclick.net,REJECT
DOMAIN,api.example.com,DIRECT
[URL Rewrite]
^https?://ad\\.example\\.com/ url reject-img
^https?://short\\.example\\.com/(.*) url 302 https://target.example.com/$1
^https?://www\\.bar\\.com/ad - reject
^https?://hdr\\.example\\.com/ url request-header $(remove-X-Forwarded-For)
^https?://qx\\.example\\.com/api url script-response-body https://cdn.example.com/resp.js
[Script]
my-script = type=http-response,pattern=^https?://s\\.example\\.com/,requires-body=1,script-path=https://cdn.example.com/s.js
http-request, ^https?://in\\.example\\.com/, script-path=inline:deadbeef, tag=InlineTag, requires-body=1
# --- inline script deadbeef begin ---
# console.log("hi");
# $done({});
# --- inline script deadbeef end ---
[MITM]
hostname = %APPEND% *.google.com, -accounts.google.com, example.org
[Host]
printer.lan = 192.168.1.20
[General]
dns-server = 223.5.5.5, 1.1.1.1
`;
    const parsed = parseUniversalModuleLocal(raw);
    expect(parsed.rulesCount).toBe(2);
    // script-response-body must go into scripts, NOT rewrites
    expect(parsed.rewrites).toHaveLength(4);
    expect(parsed.rewrites.map((r) => r.action)).toEqual([
      "reject-img",
      "302",
      "reject",
      "request-header",
    ]);
    expect(parsed.rewrites[0].ruleIndex).toBe(0);
    expect(parsed.rewrites[3].ruleIndex).toBe(3);

    expect(parsed.scripts).toHaveLength(3);
    expect(parsed.scripts[0]).toMatchObject({
      name: "resp.js",
      type: "http-response",
      requiresBody: true,
      ruleIndex: 0,
    });
    expect(parsed.scripts[1]).toMatchObject({
      name: "my-script",
      type: "http-response",
      pattern: "^https?://s\\.example\\.com/",
      ruleIndex: 1,
    });
    expect(parsed.scripts[2]).toMatchObject({
      name: "InlineTag",
      type: "http-request",
      scriptPath: "inline:deadbeef",
      inlineCode: 'console.log("hi");\n$done({});',
      ruleIndex: 2,
    });

    expect(parsed.mitmHosts).toEqual([
      { raw: "*.google.com", host: "google.com", isWildcard: true, isExcluded: false },
      {
        raw: "-accounts.google.com",
        host: "accounts.google.com",
        isWildcard: false,
        isExcluded: true,
      },
      { raw: "example.org", host: "example.org", isWildcard: false, isExcluded: false },
    ]);

    expect(parsed.hosts).toHaveLength(1);
    expect(parsed.hosts[0]).toMatchObject({ domain: "printer.lan", value: "192.168.1.20" });
    expect(parsed.dnsServers).toEqual(["223.5.5.5", "1.1.1.1"]);

    expect(computeModuleStats(raw)).toEqual({
      rules: 2,
      rewrites: 4,
      scripts: 3,
      mitmHosts: 3,
      hosts: 1,
    });
  });

  it("supports Stash YAML rules counting", () => {
    const yaml = `name: Stash Rules
desc: Sample
rules:
  - DOMAIN-SUFFIX,ads.com,REJECT
  - DOMAIN-SUFFIX,cn.com,DIRECT
`;
    expect(computeModuleStats(yaml).rules).toBe(2);
  });

  it("cleanly upserts and removes inline scripts including full multi-line comment block", () => {
    const v1 = upsertCustomScript(undefined, "Custom Scripts", "desc", {
      name: "Demo",
      type: "http-request",
      pattern: "^https://a\\.com/",
      code: "const a = 1;\nconst b = 2;\n$done({});",
    });
    const parsed1 = parseUniversalModuleLocal(v1);
    expect(parsed1.scripts).toHaveLength(1);
    expect(parsed1.scripts[0].inlineCode).toBe("const a = 1;\nconst b = 2;\n$done({});");

    // Update code & type
    const v2 = upsertCustomScript(v1, "Custom Scripts", "desc", {
      name: "Demo",
      type: "http-response",
      pattern: "^https://a\\.com/",
      code: "const c = 3;\n$done({ response: { status: 200 } });",
      oldScriptPath: parsed1.scripts[0].scriptPath,
    });
    const parsed2 = parseUniversalModuleLocal(v2);
    expect(parsed2.scripts).toHaveLength(1);
    expect(parsed2.scripts[0].type).toBe("http-response");
    expect(parsed2.scripts[0].inlineCode).toBe(
      "const c = 3;\n$done({ response: { status: 200 } });",
    );
    expect(v2).not.toContain("const a = 1;");
    expect(Object.keys(extractInlineScripts(v2))).toHaveLength(1);

    // Delete script
    const v3 = removeCustomScript(v2, parsed2.scripts[0].scriptPath);
    expect(parseUniversalModuleLocal(v3).scripts).toHaveLength(0);
    expect(Object.keys(extractInlineScripts(v3))).toHaveLength(0);
  });

  it("supports rewrite, mitm, and host CRUD cleanly", () => {
    const rw1 = upsertCustomRewrite(
      undefined,
      "RW",
      "desc",
      "^https://a\\.com/ url reject",
    );
    expect(rw1.duplicate).toBe(false);
    const rwDup = upsertCustomRewrite(
      rw1.raw,
      "RW",
      "desc",
      "^https://a\\.com/ url reject",
    );
    expect(rwDup.duplicate).toBe(true);
    const rwEdit = upsertCustomRewrite(
      rw1.raw,
      "RW",
      "desc",
      "^https://a\\.com/ url reject-200",
      "^https://a\\.com/ url reject",
    );
    expect(parseUniversalModuleLocal(rwEdit.raw).rewrites[0].action).toBe("reject-200");
    const rwDel = removeCustomRewrite(rwEdit.raw, "^https://a\\.com/ url reject-200");
    expect(parseUniversalModuleLocal(rwDel).rewrites).toHaveLength(0);

    const m1 = upsertCustomMitmHosts(undefined, "MitM", "desc", [
      "*.example.com",
      "-skip.example.com",
    ]);
    expect(m1.added).toEqual(["*.example.com", "-skip.example.com"]);
    const m2 = removeCustomMitmHost(m1.raw, "MitM", "desc", "*.example.com");
    expect(m2.remaining).toBe(1);
    expect(parseUniversalModuleLocal(m2.raw).mitmHosts[0].raw).toBe("-skip.example.com");

    const h1 = upsertCustomHost(undefined, "Host", "desc", "nas.lan", "192.168.1.10");
    expect(parseUniversalModuleLocal(h1.raw).hosts).toHaveLength(1);
    const h2 = upsertCustomHost(h1.raw, "Host", "desc", "nas.lan", "192.168.1.20");
    expect(parseUniversalModuleLocal(h2.raw).hosts).toHaveLength(1);
    expect(parseUniversalModuleLocal(h2.raw).hosts[0].value).toBe("192.168.1.20");
    const h3 = removeCustomHost(h2.raw, "nas.lan");
    expect(parseUniversalModuleLocal(h3).hosts).toHaveLength(0);
  });
});
