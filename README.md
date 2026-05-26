# Sentinel — Open Web Threat & Risk Detection System

> lablab.ai Hackathon | Track 3: Security & Compliance
> Powered by **Bright Data** + **Claude AI (Anthropic)**

Sentinel is an AI-powered security intelligence tool that monitors the open web for threats relevant to your organization. Given a company profile, it scans for credential leaks, regulatory changes, and vendor risk signals — then uses Claude to analyze and structure findings into actionable alerts.

---

## The Problem

Security teams have SIEMs, firewalls, and vulnerability scanners. But none of those tools monitor:

- **Paste sites & breach forums** where credentials get dumped publicly
- **Regulator portals** where compliance rules quietly change
- **Open web news** signaling that a key vendor is breached or in financial distress

Sentinel fills that gap using Bright Data's Web Unlocker infrastructure and Claude's AI reasoning.

---

## Three Detection Modules

| Module | What It Scans | Signal Type |
|---|---|---|
| Threat Surface Monitor | Credential leaks, breach mentions, paste sites | `credential_leak` |
| Regulatory Change Tracker | DORA, NIS2, GDPR, SEC updates | `regulatory_change` |
| Vendor Risk Radar | Supplier breaches, layoffs, financial distress | `vendor_risk` |

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

This installs `@anthropic-ai/sdk` and `axios`. You should see a `node_modules/` folder appear.

---

### Step 4 — Get your API keys

You need two accounts:

#### A. Anthropic (Claude AI)

1. Go to [console.anthropic.com](https://console.anthropic.com/) and sign up
2. Navigate to **API Keys** → **Create Key**
3. Copy the key — it starts with `sk-ant-...`

#### B. Bright Data (Web Unlocker)

1. Go to [brightdata.com](https://brightdata.com/) and sign up
2. From the dashboard, click **Add Zone**
3. Select product type: **Web Unlocker**
4. Give your zone any name (e.g. `sentinel`)
5. Save the zone

Now collect these three values:

| What you need | Where to find it |
|---|---|
| **Customer ID** | Dashboard → click your avatar (top right) → Account Settings. Looks like `hl_xxxxxxxx` |
| **Zone name** | The name you gave the zone (e.g. `sentinel`) |
| **Zone password** | Proxies & Scraping → your zone → **Access parameters** → Password field |

---

### Step 5 — Create your `.env` file

In the project folder, create a file named `.env` (no extension) and paste the following, replacing the placeholder values:

```env
ANTHROPIC_API_KEY=sk-ant-your-key-here
BRIGHT_DATA_API_KEY=your-bright-data-api-key
BRIGHT_DATA_CUSTOMER_ID=hl_xxxxxxxx
BRIGHT_DATA_ZONE=sentinel
BRIGHT_DATA_ZONE_PASSWORD=your-zone-password
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
═══════════════════════════════════════════════

🔍 [Module 1] Threat Surface Monitor — scanning for credential leaks & breach signals...
📋 [Module 2] Regulatory Change Tracker — scanning for compliance updates...
🏢 [Module 3] Vendor Risk Radar — monitoring supplier risk signals...

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
                    ┌────────────────────────────┐
                    │     SENTINEL ORCHESTRATOR   │
                    │  (3 modules run in parallel) │
                    └──────┬──────────┬───────────┘
                           │          │          │
              ┌────────────▼─┐  ┌─────▼────┐  ┌─▼──────────┐
              │    Threat    │  │Regulatory│  │   Vendor   │
              │   Surface    │  │  Change  │  │    Risk    │
              │   Monitor    │  │  Tracker │  │    Radar   │
              └──────┬───────┘  └────┬─────┘  └─────┬──────┘
                     └───────────────┴───────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │   BRIGHT DATA        │
                          │   Web Unlocker       │
                          │   (brd.superproxy.io)│
                          └──────────┬───────────┘
                                     │
                          ┌──────────▼──────────┐
                          │     CLAUDE AI        │
                          │  claude-sonnet-4-6   │
                          │  Risk classification │
                          │  Severity scoring    │
                          │  Action generation   │
                          └──────────┬───────────┘
                                     │
                          ┌──────────▼──────────┐
                          │    RISK REPORT       │
                          │    JSON output       │
                          └─────────────────────┘
```

**Key functions:**

| Function | Role |
|---|---|
| `brightDataFetch(url)` | Scrapes a URL through the Web Unlocker proxy |
| `brightDataSERP(query)` | Searches DuckDuckGo via proxy, parses HTML results |
| `analyzeWithClaude(content, type, org)` | Sends raw content to Claude, returns structured risk JSON |
| `threatSurfaceMonitor(org)` | Module 1 — credential leak signals |
| `regulatoryChangeTracker(org)` | Module 2 — compliance update signals |
| `vendorRiskRadar(org)` | Module 3 — vendor risk signals |

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

## Dependencies

```json
{
  "@anthropic-ai/sdk": "^0.39.0",
  "axios": "^1.7.0"
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
