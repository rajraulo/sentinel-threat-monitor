const SYSTEM_PROMPT = `You are Sentinel, an AI security analyst. Generate realistic threat intelligence findings for a live interactive demo.
Return ONLY a valid JSON array — no markdown, no preamble, no trailing text.

Each object schema:
{
  "signal_id": "SNT-2025-XXXX",
  "module": "threat_surface" | "regulatory" | "vendor_risk",
  "type": "credential_leak" | "regulatory_change" | "vendor_risk" | "threat_indicator",
  "severity": "critical" | "high" | "medium" | "low",
  "confidence": 0.0-1.0,
  "affected_entity": "string",
  "summary": "1-2 sentence plain-English description specific to this org",
  "recommended_action": "specific actionable next step for the security team",
  "deadline": "ISO date string or null",
  "indicators": ["3-5", "specific", "observable", "signals"],
  "requires_immediate_action": true | false
}`;

module.exports = async (req, res) => {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { org } = req.body || {};
  if (!org) return res.status(400).json({ error: "Missing org profile" });

  const apiKey = process.env.ANTHROPIC_API_KEY || process.env.VITE_ANTHROPIC_KEY;
  if (!apiKey) return res.status(500).json({ error: "ANTHROPIC_API_KEY not set in Vercel environment variables" });

  const prompt = `Analyze this organization and generate 7–9 realistic threat intelligence findings covering all three modules (threat_surface, regulatory, vendor_risk). Include at least 1 critical and 2 high severity findings. Be specific to their industry, vendors, and regulatory frameworks — name them explicitly.

Organization:
  Name: ${org.name}
  Domain: ${org.domain}
  Industries: ${(org.industries || []).join(", ")}
  Key Vendors: ${(org.vendors || []).join(", ")}
  Regulatory Frameworks: ${(org.frameworks || []).join(", ")}

Return a JSON array of findings only.`;

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-haiku-4-5-20251001",
        max_tokens: 3000,
        system: [{ type: "text", text: SYSTEM_PROMPT, cache_control: { type: "ephemeral" } }],
        messages: [{ role: "user", content: prompt }],
      }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      return res.status(502).json({ error: err.error?.message || `Anthropic API error ${response.status}` });
    }

    const data = await response.json();
    const raw = data.content[0].text.trim()
      .replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "").trim();

    const findings = JSON.parse(raw);
    res.status(200).json({ findings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
