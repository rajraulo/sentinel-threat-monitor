module.exports = async (req, res) => {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;

  if (!webhookUrl) {
    return res.status(500).json({ error: "SLACK_WEBHOOK_URL is not set in environment variables" });
  }

  try {
    const response = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: "✅ Sentinel Slack test — webhook is working!",
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      return res.status(502).json({ error: `Slack returned ${response.status}: ${body}` });
    }

    res.status(200).json({ ok: true, message: "Message sent to Slack successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
