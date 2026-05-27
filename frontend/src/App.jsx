import { useState } from 'react'

// ─── Severity config ──────────────────────────────────────────────────────────
const SEV = {
  critical: { color: '#f87171', bg: 'rgba(239,68,68,0.08)',  border: 'rgba(239,68,68,0.25)',  label: '🔴 CRITICAL' },
  high:     { color: '#fb923c', bg: 'rgba(249,115,22,0.08)', border: 'rgba(249,115,22,0.25)', label: '🟠 HIGH'     },
  medium:   { color: '#fbbf24', bg: 'rgba(234,179,8,0.08)',  border: 'rgba(234,179,8,0.25)',  label: '🟡 MEDIUM'   },
  low:      { color: '#4ade80', bg: 'rgba(34,197,94,0.08)',  border: 'rgba(34,197,94,0.25)',  label: '🟢 LOW'      },
}
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }

const MODULES = [
  { id: 'threat_surface', icon: '🔍', label: 'Threat Surface Monitor',    desc: 'Credential leaks & breach signals via SERP API'       },
  { id: 'regulatory',     icon: '📋', label: 'Regulatory Change Tracker', desc: 'DORA, NIS2, GDPR, SEC updates via Scraping Browser'   },
  { id: 'vendor_risk',    icon: '🏢', label: 'Vendor Risk Radar',         desc: 'Supplier breaches & distress via Web Scraper API'     },
]

const ALL_INDUSTRIES = ['Financial Services', 'Technology', 'Healthcare', 'Energy', 'Retail']
const ALL_FRAMEWORKS  = ['DORA', 'NIS2', 'GDPR', 'SEC', 'HIPAA', 'PCI-DSS']

// ─── API call via Vercel serverless function ──────────────────────────────────
async function callClaude(org) {
  const res = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ org }),
  })

  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.error || `Server error ${res.status}`)
  }

  const data = await res.json()
  return data.findings
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Tag({ children, active, onClick, activeColor = '#22d3ee' }) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '4px 10px',
        borderRadius: 4,
        border: `1px solid ${active ? activeColor + '88' : '#374151'}`,
        background: active ? activeColor + '18' : 'transparent',
        color: active ? activeColor : '#6b7280',
        fontSize: 11,
        cursor: 'pointer',
        transition: 'all 0.15s',
        letterSpacing: '0.03em',
      }}
    >
      {children}
    </button>
  )
}

function Field({ label, children }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{ fontSize: 10, color: '#6b7280', letterSpacing: '0.1em', marginBottom: 7 }}>{label}</div>
      {children}
    </div>
  )
}

const inputStyle = {
  width: '100%',
  background: '#0b1120',
  border: '1px solid #1f2937',
  borderRadius: 4,
  padding: '8px 10px',
  color: '#e2e8f0',
  fontSize: 12,
  outline: 'none',
  boxSizing: 'border-box',
}

function ModuleRow({ module, alerts, scanning }) {
  const done = alerts !== null
  const count = alerts?.length ?? 0
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 12,
      padding: '10px 14px',
      background: scanning ? 'rgba(34,211,238,0.04)' : done ? 'rgba(255,255,255,0.015)' : 'transparent',
      border: `1px solid ${scanning ? '#22d3ee33' : '#1e2a3a'}`,
      borderRadius: 6,
      marginBottom: 8,
      transition: 'all 0.3s',
    }}>
      <span style={{ fontSize: 18 }}>{module.icon}</span>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: '#cbd5e1' }}>{module.label}</div>
        <div style={{ fontSize: 10, color: '#4b5563', marginTop: 1 }}>{module.desc}</div>
      </div>
      <div style={{ fontSize: 12, minWidth: 70, textAlign: 'right' }}>
        {scanning && <span style={{ color: '#22d3ee' }}>scanning…</span>}
        {done && !scanning && (
          <span style={{ color: count > 0 ? '#fb923c' : '#4ade80', fontWeight: 600 }}>
            {count > 0 ? `${count} alert${count !== 1 ? 's' : ''}` : '✓ clear'}
          </span>
        )}
        {!scanning && !done && <span style={{ color: '#374151' }}>idle</span>}
      </div>
    </div>
  )
}

function StatBox({ label, value, color }) {
  return (
    <div style={{
      background: 'rgba(255,255,255,0.02)',
      border: '1px solid #1e2a3a',
      borderRadius: 6,
      padding: '14px 10px',
      textAlign: 'center',
      flex: 1,
    }}>
      <div style={{ fontSize: 26, fontWeight: 700, color, lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 9, color: '#4b5563', letterSpacing: '0.1em', marginTop: 5 }}>{label}</div>
    </div>
  )
}

function AlertCard({ alert }) {
  const s = SEV[alert.severity] || SEV.low
  return (
    <div style={{
      border: `1px solid ${s.border}`,
      background: s.bg,
      borderRadius: 8,
      padding: '16px 18px',
      marginBottom: 10,
    }}>
      {/* Top row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            fontSize: 10,
            fontWeight: 700,
            color: s.color,
            border: `1px solid ${s.border}`,
            borderRadius: 3,
            padding: '2px 8px',
            letterSpacing: '0.06em',
          }}>
            {s.label}
          </span>
          <span style={{ fontSize: 10, color: '#4b5563', letterSpacing: '0.05em' }}>
            {alert.type?.replace(/_/g, ' ').toUpperCase()}
          </span>
          {alert.requires_immediate_action && (
            <span style={{
              fontSize: 10,
              color: '#f87171',
              border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: 3,
              padding: '2px 6px',
              letterSpacing: '0.05em',
            }}>
              IMMEDIATE
            </span>
          )}
        </div>
        <span style={{ fontSize: 10, color: '#374151', fontFamily: 'monospace' }}>
          {alert.signal_id}
        </span>
      </div>

      {/* Entity + summary */}
      <div style={{ fontWeight: 600, color: '#e2e8f0', fontSize: 13, marginBottom: 4 }}>
        {alert.affected_entity}
      </div>
      <div style={{ color: '#94a3b8', fontSize: 13, lineHeight: 1.55, marginBottom: 10 }}>
        {alert.summary}
      </div>

      {/* Indicators */}
      {alert.indicators?.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginBottom: 10 }}>
          {alert.indicators.map((ind, i) => (
            <span key={i} style={{
              fontSize: 10,
              background: 'rgba(255,255,255,0.03)',
              border: '1px solid #1e2a3a',
              borderRadius: 3,
              padding: '2px 8px',
              color: '#64748b',
            }}>
              {ind}
            </span>
          ))}
        </div>
      )}

      {/* Action */}
      <div style={{
        background: 'rgba(0,0,0,0.2)',
        borderLeft: `3px solid ${s.color}`,
        padding: '8px 12px',
        borderRadius: '0 4px 4px 0',
        fontSize: 12,
        color: '#cbd5e1',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: 12,
      }}>
        <span>
          <span style={{ color: s.color, fontWeight: 700 }}>→ </span>
          {alert.recommended_action}
        </span>
        {alert.deadline && (
          <span style={{ color: '#f87171', fontSize: 11, whiteSpace: 'nowrap', flexShrink: 0 }}>
            Due {alert.deadline.slice(0, 10)}
          </span>
        )}
      </div>

      {/* Confidence */}
      <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ fontSize: 10, color: '#374151' }}>CONFIDENCE</div>
        <div style={{ flex: 1, height: 3, background: '#1e2a3a', borderRadius: 2 }}>
          <div style={{
            width: `${Math.round((alert.confidence ?? 0.7) * 100)}%`,
            height: '100%',
            background: s.color,
            borderRadius: 2,
          }} />
        </div>
        <div style={{ fontSize: 10, color: '#4b5563' }}>
          {Math.round((alert.confidence ?? 0.7) * 100)}%
        </div>
      </div>
    </div>
  )
}

// ─── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [org, setOrg] = useState({
    name: 'Acme Financial Services',
    domain: 'acme-financial.com',
    industries: ['Financial Services', 'Technology'],
    vendors: ['Salesforce', 'AWS', 'Okta', 'Twilio'],
    frameworks: ['DORA', 'NIS2', 'GDPR'],
  })
  const [vendorText, setVendorText] = useState('Salesforce, AWS, Okta, Twilio')
  const [scanning, setScanning] = useState(false)
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)

  function toggle(field, val) {
    setOrg(o => ({
      ...o,
      [field]: o[field].includes(val) ? o[field].filter(v => v !== val) : [...o[field], val],
    }))
  }

  async function runScan() {
    setError(null)
    setReport(null)
    setScanning(true)

    const fullOrg = {
      ...org,
      vendors: vendorText.split(',').map(v => v.trim()).filter(Boolean),
    }

    try {
      const findings = await callClaude(fullOrg)
      const sorted = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4))
      setReport({
        scan_id: `SENTINEL-${Date.now()}`,
        org: fullOrg.name,
        scanned_at: new Date().toISOString(),
        alerts: sorted,
        byModule: {
          threat_surface: sorted.filter(a => a.module === 'threat_surface'),
          regulatory:     sorted.filter(a => a.module === 'regulatory'),
          vendor_risk:    sorted.filter(a => a.module === 'vendor_risk'),
        },
      })
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  const counts = report
    ? {
        total:    report.alerts.length,
        critical: report.alerts.filter(a => a.severity === 'critical').length,
        high:     report.alerts.filter(a => a.severity === 'high').length,
        medium:   report.alerts.filter(a => a.severity === 'medium').length,
        low:      report.alerts.filter(a => a.severity === 'low').length,
      }
    : null

  return (
    <div style={{ fontFamily: "'Courier New', Courier, monospace", background: '#070c1a', minHeight: '100vh', color: '#e2e8f0' }}>

      {/* ── Header ── */}
      <div style={{
        borderBottom: '1px solid #1e2a3a',
        padding: '14px 28px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'rgba(0,0,0,0.35)',
        position: 'sticky',
        top: 0,
        zIndex: 10,
      }}>
        <div>
          <div style={{ fontSize: 20, fontWeight: 700, color: '#22d3ee', letterSpacing: '0.12em' }}>
            🛡️ SENTINEL
          </div>
          <div style={{ fontSize: 10, color: '#374151', letterSpacing: '0.07em', marginTop: 1 }}>
            OPEN WEB THREAT &amp; RISK DETECTION SYSTEM
          </div>
        </div>
        <div style={{ fontSize: 10, color: '#374151', textAlign: 'right', lineHeight: 1.7 }}>
          <div style={{ color: '#4b5563' }}>Bright Data + Claude AI</div>
          <div>lablab.ai Hackathon 2025</div>
        </div>
      </div>

      {/* ── Body: sidebar + main ── */}
      <div style={{ display: 'flex', minHeight: 'calc(100vh - 57px)' }}>

        {/* ── Sidebar ── */}
        <div style={{
          width: 290,
          borderRight: '1px solid #1e2a3a',
          padding: '20px 18px',
          background: 'rgba(0,0,0,0.18)',
          flexShrink: 0,
          overflowY: 'auto',
        }}>

          <div style={{ borderTop: '1px solid #1e2a3a', margin: '4px 0 18px' }} />

          <Field label="ORGANIZATION NAME">
            <input
              value={org.name}
              onChange={e => setOrg(o => ({ ...o, name: e.target.value }))}
              style={inputStyle}
            />
          </Field>

          <Field label="DOMAIN">
            <input
              value={org.domain}
              onChange={e => setOrg(o => ({ ...o, domain: e.target.value }))}
              style={inputStyle}
            />
          </Field>

          <Field label="INDUSTRIES">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
              {ALL_INDUSTRIES.map(ind => (
                <Tag key={ind} active={org.industries.includes(ind)} onClick={() => toggle('industries', ind)}>
                  {ind}
                </Tag>
              ))}
            </div>
          </Field>

          <Field label="REGULATORY FRAMEWORKS">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
              {ALL_FRAMEWORKS.map(fw => (
                <Tag key={fw} active={org.frameworks.includes(fw)} onClick={() => toggle('frameworks', fw)} activeColor="#a78bfa">
                  {fw}
                </Tag>
              ))}
            </div>
          </Field>

          <Field label="KEY VENDORS (comma-separated)">
            <textarea
              value={vendorText}
              onChange={e => setVendorText(e.target.value)}
              rows={3}
              style={{ ...inputStyle, resize: 'vertical' }}
            />
          </Field>

          {/* Run button */}
          <button
            onClick={runScan}
            disabled={scanning}
            style={{
              width: '100%',
              padding: '12px',
              background: scanning ? 'rgba(34,211,238,0.08)' : '#22d3ee',
              color: scanning ? '#22d3ee' : '#070c1a',
              border: `1px solid ${scanning ? '#22d3ee55' : '#22d3ee'}`,
              borderRadius: 6,
              fontSize: 13,
              fontWeight: 700,
              cursor: scanning ? 'not-allowed' : 'pointer',
              letterSpacing: '0.1em',
              transition: 'all 0.2s',
            }}
          >
            {scanning ? '⟳  SCANNING...' : '▶  RUN SCAN'}
          </button>

          {error && (
            <div style={{
              marginTop: 12,
              padding: '10px 12px',
              background: 'rgba(239,68,68,0.07)',
              border: '1px solid rgba(239,68,68,0.25)',
              borderRadius: 4,
              fontSize: 11,
              color: '#f87171',
              lineHeight: 1.5,
            }}>
              {error}
            </div>
          )}

          {/* How it works */}
          <div style={{ marginTop: 24, padding: '14px', background: 'rgba(255,255,255,0.02)', borderRadius: 6, border: '1px solid #1e2a3a' }}>
            <div style={{ fontSize: 10, color: '#4b5563', letterSpacing: '0.08em', marginBottom: 8 }}>HOW IT WORKS</div>
            <div style={{ fontSize: 11, color: '#374151', lineHeight: 1.7 }}>
              <div>1. SERP API — breach searches</div>
              <div>2. Scraping Browser — regulatory sites</div>
              <div>3. Web Scraper API — vendor intel</div>
              <div>4. Claude Haiku — risk extraction</div>
              <div>5. Slack — threat report delivery</div>
            </div>
          </div>
        </div>

        {/* ── Main panel ── */}
        <div style={{ flex: 1, padding: '24px 28px', overflowY: 'auto' }}>

          {/* Module status rows */}
          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 10, color: '#374151', letterSpacing: '0.1em', marginBottom: 10 }}>
              DETECTION MODULES
            </div>
            {MODULES.map(mod => (
              <ModuleRow
                key={mod.id}
                module={mod}
                alerts={report?.byModule[mod.id] ?? null}
                scanning={scanning}
              />
            ))}
          </div>

          {/* Summary stats */}
          {report && counts && (
            <>
              <div style={{ display: 'flex', gap: 10, marginBottom: 24 }}>
                <StatBox label="TOTAL"    value={counts.total}    color="#e2e8f0" />
                <StatBox label="CRITICAL" value={counts.critical} color="#f87171" />
                <StatBox label="HIGH"     value={counts.high}     color="#fb923c" />
                <StatBox label="MEDIUM"   value={counts.medium}   color="#fbbf24" />
                <StatBox label="LOW"      value={counts.low}      color="#4ade80" />
              </div>

              <div style={{ fontSize: 10, color: '#374151', letterSpacing: '0.1em', marginBottom: 12 }}>
                ALERTS — SORTED BY SEVERITY
              </div>

              {report.alerts.map((alert, i) => (
                <AlertCard key={i} alert={alert} />
              ))}

              <div style={{ marginTop: 20, fontSize: 10, color: '#1e2a3a', textAlign: 'center', letterSpacing: '0.05em' }}>
                {report.scan_id} &nbsp;·&nbsp; {new Date(report.scanned_at).toUTCString()}
              </div>
            </>
          )}

          {/* Empty state */}
          {!report && !scanning && (
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              height: '55vh',
              textAlign: 'center',
              gap: 12,
            }}>
              <div style={{ fontSize: 52 }}>🛡️</div>
              <div style={{ fontSize: 15, color: '#4b5563' }}>
                Configure your org profile and click <strong style={{ color: '#22d3ee' }}>Run Scan</strong>
              </div>
              <div style={{ fontSize: 12, color: '#374151', maxWidth: 380, lineHeight: 1.7 }}>
                Sentinel scans the open web for credential leaks, regulatory changes, and vendor risks
                using Bright Data's 5 tools + Claude AI analysis.
              </div>
            </div>
          )}

          {/* Scanning state */}
          {scanning && !report && (
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              height: '55vh',
              textAlign: 'center',
              gap: 14,
              color: '#22d3ee',
            }}>
              <div style={{ fontSize: 48 }}>⟳</div>
              <div style={{ fontSize: 15 }}>Running threat intelligence scan…</div>
              <div style={{ fontSize: 11, color: '#374151', lineHeight: 1.8 }}>
                SERP API &nbsp;·&nbsp; Scraping Browser &nbsp;·&nbsp; Web Scraper API &nbsp;·&nbsp; Claude Haiku
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
