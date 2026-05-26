/**
 * SENTINEL — Open Web Threat & Risk Detection System
 * lablab.ai Hackathon | Track 3: Security & Compliance
 * Author: Lingaraj Rawlo
 *
 * Bright Data tools:
 *  1. Web Unlocker     — bypass bot protection for HTTPS fetching
 *  2. SERP API         — structured Google search results via SERP zone
 *  3. Scraping Browser — full JS-rendered page scraping via Puppeteer
 *  4. Web Scraper API  — REST-based structured data extraction
 *  5. MCP Server       — AI-native tool integration (see README)
 *
 * Detection modules:
 *  1. Threat Surface Monitor    — credential leaks, breach mentions
 *  2. Regulatory Change Tracker — DORA, NIS2, GDPR, SEC updates
 *  3. Vendor Risk Radar         — supplier breaches, layoffs, distress
 */

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const Anthropic = require("@anthropic-ai/sdk");
const axios = require("axios");
const puppeteer = require("puppeteer-core");

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "YOUR_ANTHROPIC_KEY";
const BRIGHT_DATA_API_KEY = process.env.BRIGHT_DATA_API_KEY || "YOUR_BRIGHTDATA_KEY";
const BRIGHT_DATA_CUSTOMER_ID = process.env.BRIGHT_DATA_CUSTOMER_ID || "YOUR_CUSTOMER_ID";

// Tool 1: Web Unlocker
const BRIGHT_DATA_WU_ZONE = process.env.BRIGHT_DATA_ZONE || "YOUR_WU_ZONE";
const BRIGHT_DATA_WU_PASSWORD = process.env.BRIGHT_DATA_ZONE_PASSWORD || "YOUR_WU_PASSWORD";

// Tool 2: SERP API
const BRIGHT_DATA_SERP_ZONE = process.env.BRIGHT_DATA_SERP_ZONE || "";
const BRIGHT_DATA_SERP_PASSWORD = process.env.BRIGHT_DATA_SERP_PASSWORD || "";

// Tool 3: Scraping Browser
const BRIGHT_DATA_SB_ZONE = process.env.BRIGHT_DATA_SB_ZONE || "";
const BRIGHT_DATA_SB_PASSWORD = process.env.BRIGHT_DATA_SB_PASSWORD || "";

const anthropic = new Anthropic({ apiKey: ANTHROPIC_API_KEY });

const proxyBase = {
  host: "brd.superproxy.io",
  port: 33335,
};

// ─────────────────────────────────────────────
// TOOL 1: Web Unlocker
// Bypasses bot protection for standard HTTPS page fetching.
// Used by: Module 2 (regulatory sites)
// ─────────────────────────────────────────────
async function brightDataFetch(url) {
  try {
    const response = await axios.get(url, {
      proxy: {
        ...proxyBase,
        auth: {
          username: `brd-customer-${BRIGHT_DATA_CUSTOMER_ID}-zone-${BRIGHT_DATA_WU_ZONE}`,
          password: BRIGHT_DATA_WU_PASSWORD,
        },
      },
      timeout: 60000,
    });
    return response.data;
  } catch (err) {
    console.error(`[Web Unlocker] Failed for ${url}: ${err.message}`);
    return null;
  }
}

// ─────────────────────────────────────────────
// TOOL 2: SERP API
// Dedicated SERP zone returns structured Google results as JSON.
// Falls back to DuckDuckGo via Web Unlocker if SERP zone not configured.
// Used by: Module 1 (breach search), Module 3 (vendor search)
// ─────────────────────────────────────────────
async function brightDataSERP(query) {
  // If SERP zone is configured, use dedicated SERP API
  if (BRIGHT_DATA_SERP_ZONE) {
    try {
      const url = `https://www.google.com/search?q=${encodeURIComponent(query)}&num=5&brd_json=1`;
      const response = await axios.get(url, {
        proxy: {
          ...proxyBase,
          auth: {
            username: `brd-customer-${BRIGHT_DATA_CUSTOMER_ID}-zone-${BRIGHT_DATA_SERP_ZONE}`,
            password: BRIGHT_DATA_SERP_PASSWORD,
          },
        },
        timeout: 60000,
      });
      const results = response.data?.organic || [];
      if (results.length > 0) {
        console.log(`[SERP API] Got ${results.length} results for "${query}"`);
        return results.map((r) => ({
          title: r.title || query,
          link: r.link || "",
          snippet: r.description || r.snippet || "",
        }));
      }
    } catch (err) {
      console.error(`[SERP API] Failed for "${query}": ${err.message}`);
    }
  }

  // Fallback: DuckDuckGo HTML via Web Unlocker
  try {
    const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
    const response = await axios.get(url, {
      proxy: {
        ...proxyBase,
        auth: {
          username: `brd-customer-${BRIGHT_DATA_CUSTOMER_ID}-zone-${BRIGHT_DATA_WU_ZONE}`,
          password: BRIGHT_DATA_WU_PASSWORD,
        },
      },
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" },
      timeout: 60000,
    });
    const html = response.data || "";
    const snippets = [...html.matchAll(/<a class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g)]
      .map((m) => m[1].replace(/<[^>]+>/g, "").replace(/&#x27;/g, "'").replace(/&amp;/g, "&").replace(/&gt;/g, ">").trim())
      .filter((s) => s.length > 20)
      .slice(0, 5);
    const titles = [...html.matchAll(/<a[^>]*class="result__a"[^>]*>([\s\S]*?)<\/a>/g)]
      .map((m) => m[1].replace(/<[^>]+>/g, "").trim())
      .slice(0, 5);
    return snippets.map((snippet, i) => ({ title: titles[i] || query, link: url, snippet }));
  } catch (err) {
    console.error(`[SERP Fallback] Failed for "${query}": ${err.message}`);
    return [];
  }
}

// ─────────────────────────────────────────────
// TOOL 3: Scraping Browser
// Full cloud browser via Puppeteer — handles JavaScript-heavy pages,
// CAPTCHAs, and sites that block standard proxy requests.
// Falls back to Web Unlocker if Scraping Browser zone not configured.
// Used by: Module 2 (JS-heavy regulatory portals)
// ─────────────────────────────────────────────
async function scrapingBrowserFetch(url) {
  if (BRIGHT_DATA_SB_ZONE) {
    let browser;
    try {
      const wsEndpoint = `wss://brd-customer-${BRIGHT_DATA_CUSTOMER_ID}-zone-${BRIGHT_DATA_SB_ZONE}:${BRIGHT_DATA_SB_PASSWORD}@brd.superproxy.io:9222`;
      browser = await puppeteer.connect({ browserWSEndpoint: wsEndpoint });
      const page = await browser.newPage();
      await page.goto(url, { waitUntil: "networkidle2", timeout: 60000 });
      const content = await page.content();
      console.log(`[Scraping Browser] Successfully fetched ${url}`);
      return content;
    } catch (err) {
      console.error(`[Scraping Browser] Failed for ${url}: ${err.message}`);
    } finally {
      if (browser) await browser.close().catch(() => {});
    }
  }

  // Fallback to Web Unlocker
  console.log(`[Scraping Browser] Zone not configured — falling back to Web Unlocker for ${url}`);
  return brightDataFetch(url);
}

// ─────────────────────────────────────────────
// TOOL 4: Web Scraper API
// REST API endpoint for structured data extraction.
// Falls back to Web Unlocker proxy on failure.
// Used by: Module 3 (vendor intelligence)
// ─────────────────────────────────────────────
async function webScraperApiFetch(url) {
  try {
    const response = await axios.post(
      "https://api.brightdata.com/request",
      { zone: BRIGHT_DATA_WU_ZONE, url, format: "raw" },
      {
        headers: {
          Authorization: `Bearer ${BRIGHT_DATA_API_KEY}`,
          "Content-Type": "application/json",
        },
        timeout: 60000,
      }
    );
    console.log(`[Web Scraper API] Successfully fetched ${url}`);
    return response.data;
  } catch (err) {
    console.error(`[Web Scraper API] Failed for ${url}: ${err.message}`);
    // Fallback to Web Unlocker proxy
    return brightDataFetch(url);
  }
}

// ─────────────────────────────────────────────
// CLAUDE — Risk object generator
// ─────────────────────────────────────────────
async function analyzeWithClaude(rawContent, signalType, orgProfile) {
  const systemPrompt = `You are Sentinel, an AI security analyst. Analyze raw web content and extract structured risk intelligence.
Always respond with a valid JSON object only — no markdown, no preamble.

Risk object schema:
{
  "signal_id": "SNT-YYYY-XXXX",
  "type": "credential_leak | regulatory_change | vendor_risk | threat_indicator",
  "severity": "critical | high | medium | low | none",
  "confidence": 0.0-1.0,
  "affected_entity": "string",
  "summary": "plain-language description",
  "recommended_action": "specific next step for the security/compliance team",
  "deadline": "ISO date string or null",
  "indicators": ["list", "of", "specific", "signals", "found"],
  "requires_immediate_action": true/false
}

If no risk is detected, return severity: "none" with a brief summary.`;

  const userPrompt = `Org profile: ${JSON.stringify(orgProfile)}
Signal type being checked: ${signalType}
Raw content to analyze:
---
${String(rawContent).slice(0, 4000)}
---
Extract any risk signals relevant to this org. Return the risk object JSON.`;

  try {
    const msg = await anthropic.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 1024,
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }],
    });
    const text = msg.content[0].text.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/, "");
    return JSON.parse(text);
  } catch (err) {
    console.error("[Claude] Analysis failed:", err.message);
    return { type: signalType, severity: "unknown", summary: "Analysis failed", error: err.message };
  }
}

// ─────────────────────────────────────────────
// MODULE 1 — Threat Surface Monitor
// Bright Data tool: SERP API
// Scans for credential leaks, breach dumps, dark-web signals
// ─────────────────────────────────────────────
async function threatSurfaceMonitor(orgProfile) {
  console.log("\n🔍 [Module 1] Threat Surface Monitor — using SERP API...");

  const searchQueries = [
    `"${orgProfile.domain}" leaked credentials site:pastebin.com`,
    `"${orgProfile.name}" data breach 2024 2025`,
    `"${orgProfile.domain}" password dump`,
  ];

  const results = [];
  for (const query of searchQueries) {
    const serpResults = await brightDataSERP(query);
    if (serpResults.length > 0) {
      const topResult = serpResults[0];
      const content = `Title: ${topResult.title}\nURL: ${topResult.link}\nSnippet: ${topResult.snippet}`;
      const riskObj = await analyzeWithClaude(content, "credential_leak", orgProfile);
      riskObj.source_url = topResult.link;
      riskObj.detected_at = new Date().toISOString();
      results.push(riskObj);
    }
  }
  return results.filter((r) => r.severity !== "none");
}

// ─────────────────────────────────────────────
// MODULE 2 — Regulatory Change Tracker
// Bright Data tools: Scraping Browser (primary), Web Unlocker (fallback)
// Monitors DORA, NIS2, GDPR, SEC compliance updates
// ─────────────────────────────────────────────
async function regulatoryChangeTracker(orgProfile) {
  console.log("\n📋 [Module 2] Regulatory Change Tracker — using Scraping Browser...");

  const regulatorySources = [
    { name: "ENISA NIS2", url: "https://www.enisa.europa.eu/topics/cybersecurity-policy/nis-2-directive" },
    { name: "EU DORA", url: "https://www.digital-operational-resilience-act.com/" },
    { name: "SEC Cybersecurity", url: "https://www.sec.gov/spotlight/cybersecurity" },
  ];

  const results = [];
  for (const source of regulatorySources) {
    if (!orgProfile.industries.some((ind) => isSourceRelevant(source.name, ind))) continue;

    // Use Scraping Browser for JS-heavy regulatory portals
    const rawContent = await scrapingBrowserFetch(source.url);
    if (!rawContent) continue;

    const riskObj = await analyzeWithClaude(
      typeof rawContent === "string" ? rawContent.slice(0, 3000) : JSON.stringify(rawContent).slice(0, 3000),
      "regulatory_change",
      orgProfile
    );
    riskObj.source_name = source.name;
    riskObj.source_url = source.url;
    riskObj.detected_at = new Date().toISOString();
    results.push(riskObj);
  }
  return results.filter((r) => r.severity !== "none" && r.severity !== "unknown");
}

function isSourceRelevant(sourceName, industry) {
  const mapping = {
    "financial services": ["DORA", "SEC", "FCA", "Basel"],
    technology: ["NIS2", "ENISA", "GDPR", "DORA"],
    healthcare: ["HIPAA", "NIS2"],
    energy: ["NIS2", "ENISA"],
    retail: ["GDPR", "PCI"],
  };
  const relevantSources = mapping[industry.toLowerCase()] || ["NIS2", "ENISA"];
  return relevantSources.some((s) => sourceName.includes(s));
}

// ─────────────────────────────────────────────
// MODULE 3 — Vendor Risk Radar
// Bright Data tools: SERP API (search) + Web Scraper API (structured fetch)
// Monitors supplier breaches, layoffs, financial distress
// ─────────────────────────────────────────────
async function vendorRiskRadar(orgProfile) {
  console.log("\n🏢 [Module 3] Vendor Risk Radar — using SERP API + Web Scraper API...");

  const results = [];
  for (const vendor of orgProfile.vendors) {
    const queries = [
      `"${vendor}" layoffs OR "data breach" OR bankruptcy 2024 2025`,
      `"${vendor}" security incident OR breach OR hack`,
    ];

    for (const query of queries) {
      const serpResults = await brightDataSERP(query);
      if (serpResults.length === 0) continue;

      // Use Web Scraper API to fetch the top result for structured extraction
      let deepContent = null;
      if (serpResults[0].link && serpResults[0].link.startsWith("http")) {
        deepContent = await webScraperApiFetch(serpResults[0].link);
      }

      const content = deepContent
        ? String(deepContent).slice(0, 3000)
        : serpResults.slice(0, 3).map((r) => `${r.title}: ${r.snippet}`).join("\n");

      const riskObj = await analyzeWithClaude(content, "vendor_risk", { ...orgProfile, target_vendor: vendor });
      riskObj.vendor = vendor;
      riskObj.detected_at = new Date().toISOString();
      results.push(riskObj);
      break;
    }
  }
  return results.filter((r) => r.severity !== "none");
}

// ─────────────────────────────────────────────
// SENTINEL — Main orchestrator
// ─────────────────────────────────────────────
async function runSentinel(orgProfile) {
  console.log("═══════════════════════════════════════════════");
  console.log("  SENTINEL — Open Web Threat & Risk Detection");
  console.log(`  Target org: ${orgProfile.name} (${orgProfile.domain})`);
  console.log("  Bright Data tools: Web Unlocker | SERP API | Scraping Browser | Web Scraper API");
  console.log("═══════════════════════════════════════════════");

  const startTime = Date.now();
  const allAlerts = [];

  const [threatAlerts, regulatoryAlerts, vendorAlerts] = await Promise.allSettled([
    threatSurfaceMonitor(orgProfile),
    regulatoryChangeTracker(orgProfile),
    vendorRiskRadar(orgProfile),
  ]);

  if (threatAlerts.status === "fulfilled") allAlerts.push(...threatAlerts.value);
  if (regulatoryAlerts.status === "fulfilled") allAlerts.push(...regulatoryAlerts.value);
  if (vendorAlerts.status === "fulfilled") allAlerts.push(...vendorAlerts.value);

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, none: 4, unknown: 5 };
  allAlerts.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

  const report = {
    scan_id: `SENTINEL-${Date.now()}`,
    org: orgProfile.name,
    scanned_at: new Date().toISOString(),
    duration_ms: Date.now() - startTime,
    total_alerts: allAlerts.length,
    critical: allAlerts.filter((a) => a.severity === "critical").length,
    high: allAlerts.filter((a) => a.severity === "high").length,
    medium: allAlerts.filter((a) => a.severity === "medium").length,
    alerts: allAlerts,
  };

  console.log("\n═══════════════════════════════════════════════");
  console.log("  SENTINEL REPORT");
  console.log(`  Total alerts: ${report.total_alerts}`);
  console.log(`  Critical: ${report.critical} | High: ${report.high} | Medium: ${report.medium}`);
  console.log(`  Scan time: ${report.duration_ms}ms`);
  console.log("═══════════════════════════════════════════════");
  console.log(JSON.stringify(report, null, 2));

  return report;
}

// ─────────────────────────────────────────────
// DEMO — Run with example org profile
// ─────────────────────────────────────────────
const exampleOrgProfile = {
  name: "Acme Financial Services",
  domain: "acme-financial.com",
  industries: ["financial services", "technology"],
  vendors: ["Salesforce", "AWS", "Okta", "Twilio"],
  keywords: ["acme financial", "acmefin", "acme-financial"],
  regulatory_frameworks: ["DORA", "NIS2", "GDPR"],
};

runSentinel(exampleOrgProfile).catch(console.error);

module.exports = { runSentinel, threatSurfaceMonitor, regulatoryChangeTracker, vendorRiskRadar };
