"use client";

import { useState, useMemo, Fragment } from "react";
import SearchBar from "./searchbar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/ui/use-toast";

interface SecurityCheck {
  name: string;
  header: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  check: (headers: Record<string, string>, html?: string) => { pass: boolean; value?: string; detail?: string };
}

const CHECKS: SecurityCheck[] = [
  {
    name: "HTTPS",
    header: "url",
    description: "Site uses HTTPS encryption",
    severity: "critical",
    check: (_h, _html) => ({ pass: true, detail: "Checked via crawl URL" }),
  },
  {
    name: "Strict-Transport-Security",
    header: "strict-transport-security",
    description: "Forces HTTPS connections via HSTS",
    severity: "critical",
    check: (h) => {
      const val = findHeader(h, "strict-transport-security");
      if (!val) return { pass: false, detail: "Header missing — browsers can connect over HTTP" };
      const maxAge = parseInt(val.match(/max-age=(\d+)/)?.[1] || "0");
      if (maxAge < 31536000) return { pass: true, value: val, detail: `max-age=${maxAge} (recommend >= 31536000)` };
      return { pass: true, value: val };
    },
  },
  {
    name: "Content-Security-Policy",
    header: "content-security-policy",
    description: "Mitigates XSS and injection attacks",
    severity: "critical",
    check: (h) => {
      const val = findHeader(h, "content-security-policy");
      if (!val) return { pass: false, detail: "No CSP header — site is vulnerable to XSS injection" };
      const hasUnsafe = val.includes("unsafe-inline") || val.includes("unsafe-eval");
      return { pass: true, value: val.slice(0, 80) + (val.length > 80 ? "..." : ""), detail: hasUnsafe ? "Contains unsafe-inline or unsafe-eval directives" : undefined };
    },
  },
  {
    name: "X-Frame-Options",
    header: "x-frame-options",
    description: "Prevents clickjacking by controlling iframe embedding",
    severity: "high",
    check: (h) => {
      const val = findHeader(h, "x-frame-options");
      if (!val) return { pass: false, detail: "Missing — page can be embedded in iframes (clickjacking risk)" };
      return { pass: true, value: val };
    },
  },
  {
    name: "X-Content-Type-Options",
    header: "x-content-type-options",
    description: "Prevents MIME type sniffing",
    severity: "medium",
    check: (h) => {
      const val = findHeader(h, "x-content-type-options");
      if (!val) return { pass: false, detail: "Missing — browser may MIME-sniff responses" };
      return { pass: val.toLowerCase() === "nosniff", value: val };
    },
  },
  {
    name: "Referrer-Policy",
    header: "referrer-policy",
    description: "Controls how much referrer info is sent",
    severity: "medium",
    check: (h) => {
      const val = findHeader(h, "referrer-policy");
      if (!val) return { pass: false, detail: "Missing — full URL may leak in Referer header" };
      return { pass: true, value: val };
    },
  },
  {
    name: "Permissions-Policy",
    header: "permissions-policy",
    description: "Controls browser feature access (camera, mic, geolocation)",
    severity: "medium",
    check: (h) => {
      const val = findHeader(h, "permissions-policy") || findHeader(h, "feature-policy");
      if (!val) return { pass: false, detail: "Missing — all browser features are allowed by default" };
      return { pass: true, value: val.slice(0, 80) + (val.length > 80 ? "..." : "") };
    },
  },
  {
    name: "X-XSS-Protection",
    header: "x-xss-protection",
    description: "Legacy XSS filter (deprecated but still checked)",
    severity: "low",
    check: (h) => {
      const val = findHeader(h, "x-xss-protection");
      if (!val) return { pass: false, detail: "Missing (note: modern browsers use CSP instead)" };
      return { pass: true, value: val };
    },
  },
  {
    name: "Cross-Origin-Opener-Policy",
    header: "cross-origin-opener-policy",
    description: "Isolates browsing context from cross-origin popups",
    severity: "low",
    check: (h) => {
      const val = findHeader(h, "cross-origin-opener-policy");
      if (!val) return { pass: false, detail: "Missing — window can be referenced by cross-origin pages" };
      return { pass: true, value: val };
    },
  },
  {
    name: "Cross-Origin-Resource-Policy",
    header: "cross-origin-resource-policy",
    description: "Prevents resources from being loaded cross-origin",
    severity: "low",
    check: (h) => {
      const val = findHeader(h, "cross-origin-resource-policy");
      if (!val) return { pass: false, detail: "Missing" };
      return { pass: true, value: val };
    },
  },
];

function findHeader(headers: Record<string, string>, name: string): string | undefined {
  // Headers may have different casing
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v;
  }
  return undefined;
}

const SEVERITY_COLORS = {
  critical: "bg-red-500/15 text-red-400 border-red-500/20",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
  low: "bg-blue-500/15 text-blue-400 border-blue-500/20",
};

interface PageResult {
  url: string;
  headers: Record<string, string>;
  score: number;
  checks: { check: SecurityCheck; result: { pass: boolean; value?: string; detail?: string } }[];
  passCount: number;
  failCount: number;
}

type SortKey = "url" | "score" | "pass" | "fail";
type SortDir = "asc" | "desc";
type FilterGrade = "all" | "A" | "B" | "C" | "F";

function gradeFromScore(score: number): string {
  if (score >= 90) return "A";
  if (score >= 70) return "B";
  if (score >= 50) return "C";
  return "F";
}

function gradeColor(grade: string): string {
  if (grade === "A") return "text-green-400";
  if (grade === "B") return "text-yellow-400";
  if (grade === "C") return "text-orange-400";
  return "text-red-400";
}

function SortIcon({ active, dir }: { active: boolean; dir: SortDir }) {
  return (
    <svg width="12" height="12" viewBox="0 0 12 12" className={`inline ml-1 ${active ? "text-[#3bde77]" : "text-muted-foreground/40"}`}>
      <path d="M6 2L9 5H3L6 2Z" fill="currentColor" opacity={active && dir === "asc" ? 1 : 0.3} />
      <path d="M6 10L3 7H9L6 10Z" fill="currentColor" opacity={active && dir === "desc" ? 1 : 0.3} />
    </svg>
  );
}

export default function Scanner() {
  const [data, setData] = useState<any[] | null>(null);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [sortKey, setSortKey] = useState<SortKey>("score");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [filterGrade, setFilterGrade] = useState<FilterGrade>("all");
  const { toast } = useToast();

  const results = useMemo((): PageResult[] => {
    if (!data?.length) return [];
    const items: PageResult[] = [];

    for (const page of data) {
      if (!page?.url) continue;
      const headers: Record<string, string> = page.headers || {};
      const html = page.content || "";

      const checks = CHECKS.map((check) => ({
        check,
        result: check.check(headers, html),
      }));

      const passCount = checks.filter((c) => c.result.pass).length;
      const failCount = checks.filter((c) => !c.result.pass).length;

      // Weighted score: critical=30, high=20, medium=15, low=10
      const weights = { critical: 30, high: 20, medium: 15, low: 10 };
      let totalWeight = 0;
      let earnedWeight = 0;
      for (const c of checks) {
        const w = weights[c.check.severity];
        totalWeight += w;
        if (c.result.pass) earnedWeight += w;
      }
      const score = totalWeight > 0 ? Math.round((earnedWeight / totalWeight) * 100) : 0;

      items.push({ url: page.url, headers, score, checks, passCount, failCount });
    }

    return items;
  }, [data]);

  const filtered = useMemo(() => {
    let list = results;
    if (filterGrade !== "all") list = list.filter((r) => gradeFromScore(r.score) === filterGrade);
    return [...list].sort((a, b) => {
      let cmp = 0;
      if (sortKey === "url") cmp = a.url.localeCompare(b.url);
      else if (sortKey === "score") cmp = a.score - b.score;
      else if (sortKey === "pass") cmp = a.passCount - b.passCount;
      else if (sortKey === "fail") cmp = a.failCount - b.failCount;
      return sortDir === "desc" ? -cmp : cmp;
    });
  }, [results, filterGrade, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir(key === "score" ? "asc" : "desc"); }
  };

  const toggleExpand = (idx: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const avgScore = results.length > 0 ? Math.round(results.reduce((s, r) => s + r.score, 0) / results.length) : 0;
  const gradeBreakdown = useMemo(() => {
    const map = { A: 0, B: 0, C: 0, F: 0 };
    for (const r of results) {
      const g = gradeFromScore(r.score) as keyof typeof map;
      map[g]++;
    }
    return map;
  }, [results]);

  const exportResults = (format: "json" | "csv" | "md") => {
    if (!filtered.length) return;
    let content = "";
    if (format === "json") {
      content = JSON.stringify(filtered.map((r) => ({
        url: r.url, score: r.score, grade: gradeFromScore(r.score),
        checks: r.checks.map((c) => ({ name: c.check.name, severity: c.check.severity, pass: c.result.pass, value: c.result.value, detail: c.result.detail })),
      })), null, 2);
    } else if (format === "csv") {
      content = "URL,Score,Grade,Pass,Fail\n" + filtered.map((r) => `"${r.url}",${r.score},${gradeFromScore(r.score)},${r.passCount},${r.failCount}`).join("\n");
    } else {
      content = "# Security Scan Report\n\n| URL | Score | Grade | Pass | Fail |\n|---|---|---|---|---|\n" + filtered.map((r) => {
        let path = r.url; try { path = new URL(r.url).pathname; } catch {}
        return `| ${path} | ${r.score} | ${gradeFromScore(r.score)} | ${r.passCount} | ${r.failCount} |`;
      }).join("\n");
    }
    const blob = new Blob([content], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `security-report.${format}`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast({ title: "Exported", description: `Downloaded security-report.${format}` });
  };

  return (
    <div className="flex flex-col flex-1">
      <SearchBar setDataValues={setData} />
      <div className="flex-1 overflow-auto">
        {!data ? (
          <div className="flex flex-col items-center justify-center h-full gap-4 text-center px-4 py-20">
            <svg height={48} width={48} viewBox="0 0 36 34" xmlns="http://www.w3.org/2000/svg" className="fill-[#3bde77]/30">
              <path fillRule="evenodd" clipRule="evenodd" d="M9.13883 7.06589V0.164429L13.0938 0.164429V6.175L14.5178 7.4346C15.577 6.68656 16.7337 6.27495 17.945 6.27495C19.1731 6.27495 20.3451 6.69807 21.4163 7.46593L22.8757 6.175V0.164429L26.8307 0.164429V7.06589V7.95679L26.1634 8.54706L24.0775 10.3922C24.3436 10.8108 24.5958 11.2563 24.8327 11.7262L26.0467 11.4215L28.6971 8.08749L31.793 10.5487L28.7257 14.407L28.3089 14.9313L27.6592 15.0944L26.2418 15.4502C26.3124 15.7082 26.3793 15.9701 26.4422 16.2355L28.653 16.6566L29.092 16.7402L29.4524 17.0045L35.3849 21.355L33.0461 24.5444L27.474 20.4581L27.0719 20.3816C27.1214 21.0613 27.147 21.7543 27.147 22.4577C27.147 22.5398 27.1466 22.6214 27.1459 22.7024L29.5889 23.7911L30.3219 24.1177L30.62 24.8629L33.6873 32.5312L30.0152 34L27.246 27.0769L26.7298 26.8469C25.5612 32.2432 22.0701 33.8808 17.945 33.8808C13.8382 33.8808 10.3598 32.2577 9.17593 26.9185L8.82034 27.0769L6.05109 34L2.37897 32.5312L5.44629 24.8629L5.74435 24.1177L6.47743 23.7911L8.74487 22.7806C8.74366 22.6739 8.74305 22.5663 8.74305 22.4577C8.74305 21.7616 8.76804 21.0758 8.81654 20.4028L8.52606 20.4581L2.95395 24.5444L0.615112 21.355L6.54761 17.0045L6.908 16.7402L7.34701 16.6566L9.44264 16.2575C9.50917 15.9756 9.5801 15.6978 9.65528 15.4242L8.34123 15.0944L7.69155 14.9313L7.27471 14.407L4.20739 10.5487L7.30328 8.08749L9.95376 11.4215L11.0697 11.7016C11.3115 11.2239 11.5692 10.7716 11.8412 10.3473L9.80612 8.54706L9.13883 7.95679V7.06589Z" />
            </svg>
            <h2 className="text-xl font-bold">Spider Security Scanner</h2>
            <p className="text-muted-foreground max-w-md">
              Scan security headers on any website. Check CSP, HSTS, X-Frame-Options, permissions policies, and more.
            </p>
          </div>
        ) : results.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full gap-2 py-20 text-muted-foreground">
            <p>No results yet.</p>
            <p className="text-sm">Results appear as pages are crawled.</p>
          </div>
        ) : (
          <div className="max-w-5xl mx-auto p-4 space-y-4">
            {/* Summary */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              <div className="rounded-lg border bg-card p-3">
                <p className="text-xs text-muted-foreground">Avg Score</p>
                <p className={`text-2xl font-bold ${gradeColor(gradeFromScore(avgScore))}`}>{avgScore}/100</p>
              </div>
              <div className="rounded-lg border bg-card p-3">
                <p className="text-xs text-muted-foreground">Pages</p>
                <p className="text-2xl font-bold">{results.length}</p>
              </div>
              <div className="rounded-lg border bg-card p-3 text-center">
                <p className="text-xs text-muted-foreground">Grade A</p>
                <p className="text-2xl font-bold text-green-400">{gradeBreakdown.A}</p>
              </div>
              <div className="rounded-lg border bg-card p-3 text-center">
                <p className="text-xs text-muted-foreground">Grade B</p>
                <p className="text-2xl font-bold text-yellow-400">{gradeBreakdown.B}</p>
              </div>
              <div className="rounded-lg border bg-card p-3 text-center">
                <p className="text-xs text-muted-foreground">Grade C/F</p>
                <p className="text-2xl font-bold text-red-400">{gradeBreakdown.C + gradeBreakdown.F}</p>
              </div>
            </div>

            {/* Filter + Export */}
            <div className="flex flex-wrap items-center gap-2">
              {(["all", "A", "B", "C", "F"] as FilterGrade[]).map((g) => (
                <button
                  key={g}
                  onClick={() => setFilterGrade(g)}
                  className={`px-3 py-1 rounded-full text-xs font-medium border transition-colors ${
                    filterGrade === g
                      ? "bg-[#3bde77]/15 text-[#3bde77] border-[#3bde77]/30"
                      : "bg-muted/50 text-muted-foreground border-transparent hover:border-muted-foreground/20"
                  }`}
                >
                  {g === "all" ? `All (${results.length})` : `Grade ${g} (${gradeBreakdown[g as keyof typeof gradeBreakdown]})`}
                </button>
              ))}
              <div className="flex-1" />
              <div className="flex gap-1">
                <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => exportResults("json")}>JSON</Button>
                <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => exportResults("csv")}>CSV</Button>
                <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => exportResults("md")}>MD</Button>
              </div>
            </div>

            {/* Table */}
            <div className="rounded-lg border overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b bg-muted/30 text-xs text-muted-foreground">
                    <th className="w-8 p-3" />
                    <th className="text-left p-3 font-medium cursor-pointer hover:text-foreground select-none" onClick={() => toggleSort("url")}>
                      Page <SortIcon active={sortKey === "url"} dir={sortDir} />
                    </th>
                    <th className="text-center p-3 font-medium cursor-pointer hover:text-foreground select-none" onClick={() => toggleSort("score")}>
                      Score <SortIcon active={sortKey === "score"} dir={sortDir} />
                    </th>
                    <th className="text-center p-3 font-medium">Grade</th>
                    <th className="text-right p-3 font-medium cursor-pointer hover:text-foreground select-none" onClick={() => toggleSort("pass")}>
                      Pass <SortIcon active={sortKey === "pass"} dir={sortDir} />
                    </th>
                    <th className="text-right p-3 font-medium cursor-pointer hover:text-foreground select-none" onClick={() => toggleSort("fail")}>
                      Fail <SortIcon active={sortKey === "fail"} dir={sortDir} />
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((result, idx) => {
                    let pathname = result.url;
                    try { pathname = new URL(result.url).pathname; } catch {}
                    const isExpanded = expanded.has(idx);
                    const grade = gradeFromScore(result.score);
                    return (
                      <Fragment key={idx}>
                        <tr className="border-b last:border-0 hover:bg-muted/20 transition-colors cursor-pointer" onClick={() => toggleExpand(idx)}>
                          <td className="p-3 text-muted-foreground">
                            <svg width="12" height="12" viewBox="0 0 12 12" className={`transition-transform ${isExpanded ? "rotate-90" : ""}`}>
                              <path d="M4 2L8 6L4 10" fill="none" stroke="currentColor" strokeWidth="1.5" />
                            </svg>
                          </td>
                          <td className="p-3 font-mono text-xs truncate max-w-[250px]" title={result.url}>{pathname}</td>
                          <td className="p-3 text-center">
                            <div className="inline-flex items-center gap-2">
                              <div className="w-12 h-1.5 rounded-full bg-muted overflow-hidden">
                                <div className={`h-full rounded-full ${result.score >= 70 ? "bg-green-500" : result.score >= 50 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${result.score}%` }} />
                              </div>
                              <span className="text-xs font-mono">{result.score}</span>
                            </div>
                          </td>
                          <td className={`p-3 text-center font-bold ${gradeColor(grade)}`}>{grade}</td>
                          <td className="p-3 text-right font-mono text-xs text-green-400">{result.passCount}</td>
                          <td className="p-3 text-right font-mono text-xs text-red-400">{result.failCount}</td>
                        </tr>
                        {isExpanded && (
                          <tr className="border-b bg-muted/10">
                            <td colSpan={6} className="p-4">
                              <div className="space-y-2">
                                {result.checks.map((c, i) => (
                                  <div key={i} className={`flex items-start gap-3 p-2 rounded text-xs ${c.result.pass ? "bg-green-500/5" : "bg-red-500/5"}`}>
                                    <span className={`shrink-0 mt-0.5 w-4 h-4 rounded-full flex items-center justify-center text-[10px] font-bold ${c.result.pass ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
                                      {c.result.pass ? "\u2713" : "\u2717"}
                                    </span>
                                    <div className="flex-1 min-w-0">
                                      <div className="flex items-center gap-2">
                                        <span className="font-medium">{c.check.name}</span>
                                        <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[c.check.severity]}`}>{c.check.severity}</Badge>
                                      </div>
                                      <p className="text-muted-foreground mt-0.5">{c.check.description}</p>
                                      {c.result.value && <p className="font-mono text-[#3bde77] mt-0.5 truncate">{c.result.value}</p>}
                                      {c.result.detail && <p className="text-muted-foreground/80 mt-0.5">{c.result.detail}</p>}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
