# Sentinel — Open Web Threat & Risk Detection System

> lablab.ai Hackathon | Track 3: Security & Compliance
> Powered by **Bright Data** + **Claude AI (Anthropic)**

Sentinel is an AI-powered security intelligence tool that monitors the open web for threats relevant to your organization. Given a company profile, it scans for credential leaks, regulatory changes, and vendor risk signals — then uses Claude to analyze and structure findings into actionable alerts.

---

## Live Demo

**Try it now (no setup needed):** [sentinel-threat-monitor.vercel.app](https://sentinel-threat-monitor.vercel.app)

1. Edit the org profile (name, domain, industries, vendors, frameworks)
2. Click **Run Scan**
3. Sentinel runs all three detection modules and returns severity-ranked alerts

---

## Frontend — Run Locally

The interactive demo UI lives in the `frontend/` folder (React + Vite).

**Prerequisites:** Node.js 18+

```bash
# 1. Go into the frontend folder
cd frontend

# 2. Install dependencies
npm install

# 3. Add your Anthropic key
# Create frontend/.env.local and add:
# VITE_ANTHROPIC_KEY=sk-ant-your-key-here

# 4. Start the dev server
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## Frontend — Deploy to Vercel

```bash
# 1. Push the repo to GitHub (already done)
git push origin main
```

2. Go to [vercel.com](https://vercel.com) → **Add New Project** → import `rajraulo/sentinel-threat-monitor`
3. Leave **Root Directory** as default (repo root) — `vercel.json` handles the rest
4. Click **Deploy**
5. After deploy: **Settings → Environment Variables** → add:
   ```
   ANTHROPIC_API_KEY = sk-ant-your-key-here
   ```
6. Go to **Deployments** → **Redeploy** to pick up the key

Every `git push` to `main` auto-redeploys.

---

## The Problem

Security teams have SIEMs, firewalls, and vulnerability scanners. But none of those tools monitor:

- **Paste sites & breach forums** where credentials get dumped publicly
- **Regulator portals** where compliance rules quietly change
- **Open web news** signaling that a key vendor is breached or in financial distress

Sentinel fills that gap using Bright Data's Web Unlocker infrastructure and Claude's AI reasoning.

---

## Bright Data Tools Used

| Tool | Purpose | Module |
|---|---|---|
| **Web Unlocker** | Bypass bot protection for HTTPS page fetching | Module 2 (fallback) |
| **SERP API** | Structured Google search results via dedicated SERP zone | Module 1, Module 3 |
| **Scraping Browser** | Full JS-rendered scraping via cloud Puppeteer | Module 2 (regulatory portals) |
| **Web Scraper API** | REST-based structured data extraction from top search results | Module 3 (vendor intel) |
| **MCP Server** | AI-native tool integration — lets Claude query the web directly | Optional (see below) |

---

## Three Detection Modules

| Module | What It Scans | Bright Data Tool | Signal Type |
|---|---|---|---|
| Threat Surface Monitor | Credential leaks, breach dumps, paste sites | SERP API | `credential_leak` |
| Regulatory Change Tracker | DORA, NIS2, GDPR, SEC updates | Scraping Browser | `regulatory_change` |
| Vendor Risk Radar | Supplier breaches, layoffs, financial distress | SERP API + Web Scraper API | `vendor_risk` |

All three modules run **in parallel**. Results are merged and sorted by severity into a single JSON report.

---

## Sample Output

Real output from a scan against "Acme Financial Services":

```json
{
  "scan_id": "SENTINEL-1779753773173",
  "org": "Acme Financial Services",
  "scanned_at": "2026-05-26T00:02:53.173Z",
  "total_alerts": 6,
  "critical": 3,
  "high": 3,
  "alerts": [
    {
      "signal_id": "SNT-2025-0127",
      "type": "vendor_risk",
      "severity": "critical",
      "confidence": 0.82,
      "affected_entity": "AWS (Amazon Web Services) — vendor to Acme Financial Services",
      "summary": "A data breach directly involving AWS was publicly reported on January 27, 2025. Attributed to threat actor 'GDLockerSec', involving ~9GB of leaked data. As a confirmed AWS customer under DORA, NIS2, and GDPR, Acme Financial Services faces potential exposure of cloud-hosted data and infrastructure configuration.",
      "recommended_action": "Immediately audit AWS IAM roles and access keys. Review CloudTrail logs since Jan 27 2025. Rotate all root and IAM credentials. Assess DORA and GDPR incident reporting obligations.",
      "deadline": "2025-01-30",
      "indicators": [
        "Threat actor 'GDLockerSec' claimed responsibility",
        "~9GB of data allegedly leaked",
        "AWS is a confirmed vendor in Acme's tech stack",
        "GDPR 72-hour breach notification window may apply"
      ],
      "requires_immediate_action": true,
      "vendor": "AWS",
      "detected_at": "2026-05-26T00:01:32.453Z"
    }
  ]
}
```

---

## Getting Started

Follow these steps exactly to get Sentinel running from scratch.

---

### Step 1 — Install Node.js

Download and install **Node.js 18 or higher** from [nodejs.org](https://nodejs.org/).

Verify your installation:

```bash
node --version   # should print v18.x.x or higher
npm --version
```

---

### Step 2 — Download the project

**Option A — Clone with Git:**
```bash
git clone <repo-url>
cd sentinel-threat-monitor
```

**Option B — Download ZIP:**
1. Click **Code → Download ZIP** on GitHub
2. Extract the ZIP
3. Open a terminal inside the extracted folder

---

### Step 3 — Install dependencies

```bash
npm install
```

This installs `@anthropic-ai/sdk`, `axios`, and `puppeteer-core`. You should see a `node_modules/` folder appear.

---

### Step 4 — Get your API keys

You need two accounts:

#### A. Anthropic (Claude AI)

1. Go to [console.anthropic.com](https://console.anthropic.com/) and sign up
2. Navigate to **API Keys** → **Create Key**
3. Copy the key — it starts with `sk-ant-...`

#### B. Bright Data

1. Go to [brightdata.com](https://brightdata.com/) and sign up
2. From the dashboard, create **three zones** by clicking **Add Zone** for each:

| Zone type | Purpose |
|---|---|
| **Web Unlocker** | General HTTPS fetching with bot bypass (required) |
| **SERP API** | Structured Google search results (recommended) |
| **Scraping Browser** | JS-heavy regulatory portal scraping (recommended) |

3. For each zone, go to → **Access parameters** and copy the zone name and password

Your **Customer ID** is at Dashboard → avatar (top right) → Account Settings (format: `hl_xxxxxxxx`)

---

### Step 5 — Create your `.env` file

In the project folder, create a file named `.env` (no extension) and paste the following:

```env
ANTHROPIC_API_KEY=sk-ant-your-key-here
BRIGHT_DATA_API_KEY=your-bright-data-api-key
BRIGHT_DATA_CUSTOMER_ID=hl_xxxxxxxx

# Tool 1: Web Unlocker (required)
BRIGHT_DATA_ZONE=your-web-unlocker-zone-name
BRIGHT_DATA_ZONE_PASSWORD=your-web-unlocker-password

# Tool 2: SERP API (recommended — falls back to Web Unlocker if blank)
BRIGHT_DATA_SERP_ZONE=your-serp-zone-name
BRIGHT_DATA_SERP_PASSWORD=your-serp-zone-password

# Tool 3: Scraping Browser (recommended — falls back to Web Unlocker if blank)
BRIGHT_DATA_SB_ZONE=your-scraping-browser-zone-name
BRIGHT_DATA_SB_PASSWORD=your-scraping-browser-password
```

> **Never commit `.env` to Git.** It contains your private API keys.

---

### Step 6 — Configure your organization profile

Open `sentinel.js` and scroll to the bottom. Edit the `exampleOrgProfile` object to match the organization you want to monitor:

```js
const exampleOrgProfile = {
  name: "Your Company Name",          // full legal name
  domain: "yourcompany.com",          // primary domain to scan for leaks
  industries: ["financial services"], // drives which regulations are checked
  vendors: ["Salesforce", "AWS"],     // key suppliers to monitor
  keywords: ["yourco", "your-co"],    // search aliases / abbreviations
  regulatory_frameworks: ["DORA", "NIS2", "GDPR"],
};
```

You can add as many vendors and keywords as needed.

---

### Step 7 — Run Sentinel

```bash
node sentinel.js
```

The scan runs all three modules in parallel and prints a live report to the terminal. A full scan typically takes **1–3 minutes** depending on how many vendors you're monitoring.

**Expected output:**

```
═══════════════════════════════════════════════
  SENTINEL — Open Web Threat & Risk Detection
  Target org: Your Company Name (yourcompany.com)
  Bright Data tools: Web Unlocker | SERP API | Scraping Browser | Web Scraper API
═══════════════════════════════════════════════

🔍 [Module 1] Threat Surface Monitor — using SERP API...
📋 [Module 2] Regulatory Change Tracker — using Scraping Browser...
🏢 [Module 3] Vendor Risk Radar — using SERP API + Web Scraper API...

═══════════════════════════════════════════════
  SENTINEL REPORT
  Total alerts: 6
  Critical: 3 | High: 3 | Medium: 0
  Scan time: 167004ms
═══════════════════════════════════════════════
{ ... full JSON report ... }
```

---

### Troubleshooting

| Error | Fix |
|---|---|
| `407 Proxy Authentication Required` | Wrong Customer ID or Zone Password — double check your `.env` |
| `model: claude-sonnet-4-6 not found` | Your Anthropic API key may not have access to this model — check your plan at console.anthropic.com |
| `502 Bad Gateway` | The target site is blocking the scraper — this is expected for some government sites |
| `timeout of 60000ms exceeded` | The site took too long to respond — safe to ignore, other modules still run |
| `Analysis failed` errors | Usually a JSON parse issue — already handled gracefully, does not stop the scan |

---

## Configure Your Org Profile

Edit the `exampleOrgProfile` object at the bottom of `sentinel.js`:

```js
const exampleOrgProfile = {
  name: "Acme Financial Services",
  domain: "acme-financial.com",
  industries: ["financial services", "technology"],
  vendors: ["Salesforce", "AWS", "Okta", "Twilio"],
  keywords: ["acme financial", "acmefin", "acme-financial"],
  regulatory_frameworks: ["DORA", "NIS2", "GDPR"],
};
```

**Industry → Regulatory framework mapping:**

| Industry | Frameworks monitored |
|---|---|
| `financial services` | DORA, SEC, FCA, Basel |
| `technology` | NIS2, ENISA, GDPR, DORA |
| `healthcare` | HIPAA, NIS2 |
| `energy` | NIS2, ENISA |
| `retail` | GDPR, PCI |

---

## Architecture

```
                    ┌──────────────────────────────────┐
                    │       SENTINEL ORCHESTRATOR       │
                    │    (3 modules run in parallel)    │
                    └───────┬────────────┬─────────────┘
                            │            │            │
           ┌────────────────▼─┐  ┌───────▼──────┐  ┌─▼────────────────┐
           │  Threat Surface  │  │  Regulatory  │  │   Vendor Risk    │
           │     Monitor      │  │    Change    │  │      Radar       │
           │   [SERP API]     │  │   Tracker    │  │ [SERP API]       │
           │                  │  │[Scraping     │  │ [Web Scraper API]│
           │                  │  │  Browser]    │  │                  │
           └────────┬─────────┘  └──────┬───────┘  └────────┬─────────┘
                    └───────────────────┴───────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │            BRIGHT DATA                 │
                    │  ┌─────────────┐  ┌─────────────────┐ │
                    │  │ Web Unlocker│  │   SERP API      │ │
                    │  ├─────────────┤  ├─────────────────┤ │
                    │  │  Scraping   │  │  Web Scraper    │ │
                    │  │  Browser    │  │      API        │ │
                    │  └─────────────┘  └─────────────────┘ │
                    │         brd.superproxy.io              │
                    └───────────────────┬───────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │              CLAUDE AI                 │
                    │           claude-sonnet-4-6            │
                    │   Risk classification & severity       │
                    │   Indicator extraction & actions       │
                    └───────────────────┬───────────────────┘
                                        │
                    ┌───────────────────▼───────────────────┐
                    │             RISK REPORT                │
                    │          JSON output / SIEM            │
                    └───────────────────────────────────────┘
```

**Key functions:**

| Function | Bright Data Tool | Role |
|---|---|---|
| `brightDataFetch(url)` | Web Unlocker | Fetches any URL bypassing bot protection |
| `brightDataSERP(query)` | SERP API → Web Unlocker fallback | Structured search results via SERP zone, falls back to DuckDuckGo |
| `scrapingBrowserFetch(url)` | Scraping Browser → Web Unlocker fallback | Full JS-rendered page via cloud Puppeteer |
| `webScraperApiFetch(url)` | Web Scraper API → Web Unlocker fallback | REST-based structured data extraction |
| `analyzeWithClaude(content, type, org)` | — | Sends raw content to Claude, returns structured risk JSON |
| `threatSurfaceMonitor(org)` | SERP API | Module 1 — credential leak signals |
| `regulatoryChangeTracker(org)` | Scraping Browser | Module 2 — compliance update signals |
| `vendorRiskRadar(org)` | SERP API + Web Scraper API | Module 3 — vendor risk signals |

---

## Risk Object Schema

```json
{
  "signal_id": "SNT-YYYY-XXXX",
  "type": "credential_leak | regulatory_change | vendor_risk | threat_indicator",
  "severity": "critical | high | medium | low | none",
  "confidence": 0.0,
  "affected_entity": "string",
  "summary": "plain-language description",
  "recommended_action": "specific next step for the security/compliance team",
  "deadline": "ISO date string or null",
  "indicators": ["list of specific signals found"],
  "requires_immediate_action": true
}
```

---

## MCP Server Integration (Tool 5)

Bright Data's MCP Server exposes all Bright Data tools as native AI functions, letting Claude query the web directly without any API wiring.

**Setup:**

```bash
npm install -g @brightdata/mcp-server
brightdata-mcp --api-key YOUR_BRIGHT_DATA_API_KEY
```

Then add to your Claude Desktop `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "brightdata": {
      "command": "brightdata-mcp",
      "args": ["--api-key", "YOUR_BRIGHT_DATA_API_KEY"]
    }
  }
}
```

Once connected, Claude can use tools like `web_search`, `scrape_url`, and `get_serp_results` natively in conversation — no code changes needed.

---

## Dependencies

```json
{
  "@anthropic-ai/sdk": "^0.39.0",
  "axios": "^1.7.0",
  "puppeteer-core": "^25.0.0"
}
```

---

## Built With

- [Bright Data Web Unlocker](https://brightdata.com/products/web-unlocker) — proxy infrastructure for open web access with bot bypass
- [Claude (claude-sonnet-4-6)](https://www.anthropic.com/) — AI risk analysis and structured data extraction
- Node.js + Axios — runtime and HTTP client

---

## Author

**Lingaraj Rawlo**

---

## License

MIT
