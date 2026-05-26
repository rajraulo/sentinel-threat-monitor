/**
 * SENTINEL — Open Web Threat & Risk Detection System
 * lablab.ai Hackathon | Track 3: Security & Compliance
 * 
 * Powered by: Bright Data + Claude AI
 *
 * Three detection modules:
 *  1. Threat Surface Monitor   — credential leaks, breach mentions, dark-web signals
 *  2. Regulatory Change Tracker — DORA, NIS2, GDPR, SEC regulatory updates
 *  3. Vendor Risk Radar         — supplier financial distress, leadership exits, breach news
 */

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const Anthropic = require("@anthropic-ai/sdk");
const axios = require("axios");

// ─────────────────────────────────────────────
// CONFIG — replace with your keys
// ─────────────────────────────────────────────
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "YOUR_ANTHROPIC_KEY";
const BRIGHT_DATA_API_KEY = process.env.BRIGHT_DATA_API_KEY || "YOUR_BRIGHTDATA_KEY";
const BRIGHT_DATA_CUSTOMER_ID = process.env.BRIGHT_DATA_CUSTOMER_ID || "YOUR_CUSTOMER_ID";
const BRIGHT_DATA_ZONE = process.env.BRIGHT_DATA_ZONE || "YOUR_ZONE";
const BRIGHT_DATA_ZONE_PASSWORD = process.env.BRIGHT_DATA_ZONE_PASSWORD || "YOUR_ZONE_PASSWORD";

const anthropic = new Anthropic({ apiKey: ANTHROPIC_API_KEY });

// ─────────────────────────────────────────────
// BRIGHT DATA — Web Unlocker fetch
// ─────────────────────────────────────────────
async function brightDataFetch(url) {
  try {
    const response = await axios.get(url, {
      proxy: {
        host: "brd.superproxy.io",
        port: 33335,
        auth: {
          username: `brd-customer-${BRIGHT_DATA_CUSTOMER_ID}-zone-${BRIGHT_DATA_ZONE}`,
          password: BRIGHT_DATA_ZONE_PASSWORD,
        },
      },
      timeout: 60000,
    });
    return response.data;
  } catch (err) {
    console.error(`[BrightData] Fetch failed for ${url}: ${err.message}`);
    return null;
  }
}

// BRIGHT DATA — DuckDuckGo search via Web Unlocker proxy
async function brightDataSERP(query) {
  try {
    const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
    const response = await axios.get(url, {
      proxy: {
        host: "brd.superproxy.io",
        port: 33335,
        auth: {
          username: `brd-customer-${BRIGHT_DATA_CUSTOMER_ID}-zone-${BRIGHT_DATA_ZONE}`,
          password: BRIGHT_DATA_ZONE_PASSWORD,
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
    console.error(`[BrightData SERP] Failed for "${query}": ${err.message}`);
    return [];
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
// ─────────────────────────────────────────────
async function threatSurfaceMonitor(orgProfile) {
  console.log("\n🔍 [Module 1] Threat Surface Monitor — scanning for credential leaks & breach signals...");

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
// ─────────────────────────────────────────────
async function regulatoryChangeTracker(orgProfile) {
  console.log("\n📋 [Module 2] Regulatory Change Tracker — scanning for compliance updates...");

  // Key regulatory sources (scraped via Bright Data Web Unlocker)
  const regulatorySources = [
    { name: "ENISA NIS2", url: "https://www.enisa.europa.eu/topics/cybersecurity-policy/nis-2-directive" },
    { name: "EU DORA", url: "https://www.digital-operational-resilience-act.com/" },
    { name: "SEC Cybersecurity", url: "https://www.sec.gov/spotlight/cybersecurity" },
  ];

  const results = [];

  for (const source of regulatorySources) {
    // Only scrape sources relevant to org's industries
    if (!orgProfile.industries.some((ind) => isSourceRelevant(source.name, ind))) continue;

    const rawContent = await brightDataFetch(source.url);
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
// ─────────────────────────────────────────────
async function vendorRiskRadar(orgProfile) {
  console.log("\n🏢 [Module 3] Vendor Risk Radar — monitoring supplier risk signals...");

  const results = [];

  for (const vendor of orgProfile.vendors) {
    const queries = [
      `"${vendor}" layoffs OR "data breach" OR bankruptcy 2024 2025`,
      `"${vendor}" security incident OR breach OR hack`,
    ];

    for (const query of queries) {
      const serpResults = await brightDataSERP(query);
      if (serpResults.length === 0) continue;

      const content = serpResults
        .slice(0, 3)
        .map((r) => `${r.title}: ${r.snippet}`)
        .join("\n");

      const riskObj = await analyzeWithClaude(content, "vendor_risk", { ...orgProfile, target_vendor: vendor });
      riskObj.vendor = vendor;
      riskObj.detected_at = new Date().toISOString();
      results.push(riskObj);
      break; // one query per vendor is enough for demo
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
  console.log("═══════════════════════════════════════════════");

  const startTime = Date.now();
  const allAlerts = [];

  // Run all three modules
  const [threatAlerts, regulatoryAlerts, vendorAlerts] = await Promise.allSettled([
    threatSurfaceMonitor(orgProfile),
    regulatoryChangeTracker(orgProfile),
    vendorRiskRadar(orgProfile),
  ]);

  if (threatAlerts.status === "fulfilled") allAlerts.push(...threatAlerts.value);
  if (regulatoryAlerts.status === "fulfilled") allAlerts.push(...regulatoryAlerts.value);
  if (vendorAlerts.status === "fulfilled") allAlerts.push(...vendorAlerts.value);

  // Severity sort
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
