package handler

import (
	"encoding/json"
	"net/http"

	"github.com/dssp-protocol/gateway/internal/store"
	"github.com/dssp-protocol/gateway/internal/types"
)

// apiState returns the full gateway state as JSON (used by the dashboard).
func (h *Handler) apiState(w http.ResponseWriter, r *http.Request) {
	manifests, mTotal, _ := h.store.ListManifests(store.ListOptions{Limit: 100})
	contracts, cTotal, _ := h.store.ListContracts(store.ListOptions{Limit: 100})
	sessions, sTotal, _ := h.store.ListSessions(store.ListOptions{Limit: 100})
	events, eTotal, _ := h.store.GetEvents(store.EventListOptions{Limit: 200})

	// Collect results for completed sessions.
	type sessionWithResult struct {
		Session *types.Session `json:"session"`
		Result  *types.Result  `json:"result,omitempty"`
	}
	sessionsWithResults := make([]sessionWithResult, 0, len(sessions))
	for _, s := range sessions {
		sr := sessionWithResult{Session: s}
		if s.Status == types.SessionCompleted || s.ResultID != "" {
			if result, err := h.store.GetResult(s.SessionID); err == nil {
				sr.Result = result
			}
		}
		sessionsWithResults = append(sessionsWithResults, sr)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"manifests":  map[string]interface{}{"items": manifests, "total": mTotal},
		"contracts":  map[string]interface{}{"items": contracts, "total": cTotal},
		"sessions":   map[string]interface{}{"items": sessionsWithResults, "total": sTotal},
		"audit":      map[string]interface{}{"items": events, "total": eTotal},
		"dssp_version": types.DSPVersion,
	})
}

// dashboard serves the HTML dashboard.
func (h *Handler) dashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	state, _ := h.buildStateJSON()
	html := dashboardHTML(state)
	_, _ = w.Write([]byte(html))
}

func (h *Handler) buildStateJSON() (string, error) {
	manifests, _, _ := h.store.ListManifests(store.ListOptions{Limit: 100})
	contracts, _, _ := h.store.ListContracts(store.ListOptions{Limit: 100})
	sessions, _, _ := h.store.ListSessions(store.ListOptions{Limit: 100})
	events, _, _ := h.store.GetEvents(store.EventListOptions{Limit: 200})

	type sessionWithResult struct {
		Session *types.Session `json:"session"`
		Result  *types.Result  `json:"result,omitempty"`
	}
	swr := make([]sessionWithResult, 0, len(sessions))
	for _, s := range sessions {
		sr := sessionWithResult{Session: s}
		if result, err := h.store.GetResult(s.SessionID); err == nil {
			sr.Result = result
		}
		swr = append(swr, sr)
	}

	data := map[string]interface{}{
		"manifests": manifests,
		"contracts": contracts,
		"sessions":  swr,
		"events":    events,
	}

	b, err := json.Marshal(data)
	if err != nil {
		return "{}", err
	}
	return string(b), nil
}

func dashboardHTML(stateJSON string) string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DSSP Gateway — Dashboard</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a;
    --text: #e4e4e7; --muted: #9ca3af; --accent: #6366f1;
    --green: #22c55e; --yellow: #eab308; --red: #ef4444; --blue: #3b82f6;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: var(--bg); color: var(--text); min-height: 100vh; }
  .header { background: var(--surface); border-bottom: 1px solid var(--border);
            padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem; }
  .header h1 { font-size: 1.25rem; font-weight: 600; }
  .header .badge { background: var(--accent); color: #fff; padding: 2px 10px;
                   border-radius: 99px; font-size: 0.75rem; font-weight: 500; }
  .header .refresh { margin-left: auto; background: var(--border); color: var(--text);
                     border: none; padding: 6px 14px; border-radius: 6px; cursor: pointer;
                     font-size: 0.8rem; }
  .header .refresh:hover { background: var(--accent); }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
          gap: 1rem; padding: 1.5rem 2rem; }
  .stat { background: var(--surface); border: 1px solid var(--border);
          border-radius: 10px; padding: 1.25rem; }
  .stat .label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase;
                 letter-spacing: 0.05em; margin-bottom: 0.5rem; }
  .stat .value { font-size: 2rem; font-weight: 700; }
  .stat .sub { color: var(--muted); font-size: 0.8rem; margin-top: 0.25rem; }
  .main { padding: 0 2rem 2rem; }
  .tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 1rem; }
  .tab { padding: 0.75rem 1.25rem; cursor: pointer; color: var(--muted);
         border-bottom: 2px solid transparent; font-size: 0.875rem; transition: all 0.15s; }
  .tab:hover { color: var(--text); }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .panel { display: none; }
  .panel.active { display: block; }
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: 10px; padding: 1.25rem; margin-bottom: 1rem; }
  .card h3 { font-size: 0.95rem; margin-bottom: 0.75rem; display: flex;
             align-items: center; gap: 0.5rem; }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 4px;
         font-size: 0.7rem; font-weight: 600; text-transform: uppercase; }
  .tag.green { background: rgba(34,197,94,0.15); color: var(--green); }
  .tag.yellow { background: rgba(234,179,8,0.15); color: var(--yellow); }
  .tag.red { background: rgba(239,68,68,0.15); color: var(--red); }
  .tag.blue { background: rgba(59,130,246,0.15); color: var(--blue); }
  .tag.purple { background: rgba(99,102,241,0.15); color: var(--accent); }
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th { text-align: left; color: var(--muted); font-weight: 500; padding: 0.5rem 0.75rem;
       border-bottom: 1px solid var(--border); font-size: 0.7rem; text-transform: uppercase;
       letter-spacing: 0.05em; }
  td { padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border); }
  .mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.75rem; }
  .kv { display: grid; grid-template-columns: 140px 1fr; gap: 0.4rem 1rem; font-size: 0.8rem; }
  .kv dt { color: var(--muted); }
  .kv dd { word-break: break-all; }
  .json-toggle { background: var(--border); border: none; color: var(--muted);
                 padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 0.7rem;
                 margin-top: 0.5rem; }
  .json-toggle:hover { background: var(--accent); color: #fff; }
  pre.json { background: #0d0f14; border: 1px solid var(--border); border-radius: 6px;
             padding: 1rem; overflow-x: auto; font-size: 0.7rem; line-height: 1.5;
             max-height: 400px; overflow-y: auto; display: none; margin-top: 0.5rem; }
  pre.json.open { display: block; }
  .empty { color: var(--muted); text-align: center; padding: 3rem; font-size: 0.9rem; }
  .pii-bar { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.5rem; }
  .pii-chip { padding: 2px 8px; background: rgba(239,68,68,0.1); color: var(--red);
              border-radius: 4px; font-size: 0.7rem; }
  .pii-chip.redacted { background: rgba(34,197,94,0.1); color: var(--green); }
  .extraction { border-left: 3px solid var(--accent); padding-left: 1rem; margin: 1rem 0; }
  .extraction h4 { font-size: 0.85rem; margin-bottom: 0.5rem; }
  .field-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
                gap: 0.5rem; }
  .field-item { background: var(--bg); padding: 0.5rem 0.75rem; border-radius: 6px;
                font-size: 0.75rem; }
  .field-item .fname { color: var(--muted); font-size: 0.65rem; text-transform: uppercase; }
  .timeline { position: relative; padding-left: 1.5rem; }
  .timeline::before { content: ''; position: absolute; left: 6px; top: 0; bottom: 0;
                      width: 1px; background: var(--border); }
  .tl-item { position: relative; padding-bottom: 1rem; }
  .tl-item::before { content: ''; position: absolute; left: -1.5rem; top: 0.4rem;
                     width: 9px; height: 9px; border-radius: 50%; background: var(--border); }
  .tl-item.success::before { background: var(--green); }
  .tl-item.warning::before { background: var(--yellow); }
  .tl-item.error::before { background: var(--red); }
  .tl-item .tl-type { font-size: 0.75rem; font-weight: 600; }
  .tl-item .tl-time { font-size: 0.65rem; color: var(--muted); }
  .tl-item .tl-detail { font-size: 0.7rem; color: var(--muted); margin-top: 2px; }
</style>
</head>
<body>

<div class="header">
  <h1>🔒 DSSP Gateway</h1>
  <span class="badge">v0.1</span>
  <span style="color:var(--muted);font-size:0.8rem">Document Sovereignty Protocol — Reference Implementation</span>
  <button class="refresh" onclick="location.reload()">↻ Refresh</button>
</div>

<div class="grid" id="stats"></div>

<div class="main">
  <div class="tabs" id="tabs">
    <div class="tab active" data-panel="sessions">Sessions & Results</div>
    <div class="tab" data-panel="contracts">Contracts</div>
    <div class="tab" data-panel="manifests">Manifests</div>
    <div class="tab" data-panel="audit">Audit Trail</div>
  </div>
  <div class="panel active" id="sessions"></div>
  <div class="panel" id="contracts"></div>
  <div class="panel" id="manifests"></div>
  <div class="panel" id="audit"></div>
</div>

<script>
const S = ` + "`" + stateJSON + "`" + `;
const D = JSON.parse(S);

// Stats
const stats = document.getElementById('stats');
const totalDocs = (D.manifests||[]).reduce((a,m) => a + (m.documents||[]).length, 0);
const completedSessions = (D.sessions||[]).filter(s => s.session?.status === 'completed').length;
stats.innerHTML = [
  {label:'Manifests', value: (D.manifests||[]).length, sub: totalDocs + ' documents'},
  {label:'Contracts', value: (D.contracts||[]).length, sub: 'active'},
  {label:'Sessions', value: (D.sessions||[]).length,
   sub: completedSessions + ' completed'},
  {label:'Audit Events', value: (D.events||[]).length, sub: 'merkle-chained'},
].map(s => '<div class="stat"><div class="label">'+s.label+'</div><div class="value">'+s.value+'</div><div class="sub">'+s.sub+'</div></div>').join('');

// Tabs
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  document.getElementById(t.dataset.panel).classList.add('active');
}));

function statusTag(s) {
  const colors = {active:'blue', completed:'green', failed:'red', terminated:'red', suspended:'yellow', revoked:'red'};
  return '<span class="tag '+(colors[s]||'blue')+'">'+s+'</span>';
}

function toggleJson(btn) {
  const pre = btn.nextElementSibling;
  pre.classList.toggle('open');
  btn.textContent = pre.classList.contains('open') ? '▾ Hide JSON' : '▸ Show JSON';
}

function shortId(id) { return id ? id.substring(0, 20) + '…' : '—'; }

// Sessions & Results
const sessDiv = document.getElementById('sessions');
if (!D.sessions || D.sessions.length === 0) {
  sessDiv.innerHTML = '<div class="empty">No sessions yet</div>';
} else {
  sessDiv.innerHTML = D.sessions.map(({session: s, result: r}) => {
    let html = '<div class="card"><h3>Session ' + statusTag(s.status) + '</h3>';
    html += '<dl class="kv">';
    html += '<dt>Session ID</dt><dd class="mono">' + s.session_id + '</dd>';
    html += '<dt>Contract</dt><dd class="mono">' + (s.contract_id||'') + '</dd>';
    html += '<dt>Enclave</dt><dd>' + (s.enclave_type||'none') + '</dd>';
    html += '<dt>Started</dt><dd>' + (s.started_at||'') + '</dd>';
    if (s.completed_at) html += '<dt>Completed</dt><dd>' + s.completed_at + '</dd>';
    html += '</dl>';

    if (r) {
      html += '<h3 style="margin-top:1rem">📊 Result ' + statusTag('completed') + '</h3>';
      html += '<dl class="kv">';
      html += '<dt>Result ID</dt><dd class="mono">' + r.result_id + '</dd>';
      html += '<dt>Produced</dt><dd>' + (r.produced_at||'') + '</dd>';
      html += '<dt>Extractions</dt><dd>' + (r.extractions||[]).length + ' documents</dd>';
      html += '</dl>';

      // PII Report
      if (r.pii_report) {
        const p = r.pii_report;
        html += '<h3 style="margin-top:1rem">🛡️ PII Report <span class="tag '+(p.compliance_status==='compliant'?'green':'red')+'">'+p.compliance_status+'</span></h3>';
        html += '<div class="pii-bar">';
        (p.fields_encountered||[]).forEach(f => {
          const redacted = (p.fields_redacted||[]).includes(f);
          html += '<span class="pii-chip '+(redacted?'redacted':'')+'">'+f+(redacted?' ✓':' ⚠')+'</span>';
        });
        html += '</div>';
      }

      // Result Scan
      if (r.result_scan && r.result_scan.performed) {
        const sc = r.result_scan;
        const verdict = sc.overall_verdict || (sc.overall_passed ? 'pass' : 'fail');
        html += '<h3 style="margin-top:1rem">🔍 Result Scan <span class="tag '+(verdict==='pass'?'green':'yellow')+'">'+verdict+'</span></h3>';
        if (sc.verdicts) {
          html += '<table><tr><th>Scanner</th><th>Verdict</th><th>Findings</th></tr>';
          sc.verdicts.forEach(raw => {
            const v = typeof raw === 'string' ? JSON.parse(raw) : raw;
            html += '<tr><td>'+v.scanner_type+'</td><td>'+statusTag(v.verdict||v.passed?'pass':'fail')+'</td><td>'+(v.findings_count||0)+'</td></tr>';
          });
          html += '</table>';
        }
      }

      // Attestation
      if (r.attestation) {
        const a = r.attestation;
        html += '<h3 style="margin-top:1rem">🔐 Attestation <span class="tag purple">'+a.enclave_type+'</span></h3>';
        html += '<dl class="kv">';
        html += '<dt>Measurement</dt><dd class="mono" style="font-size:0.65rem">' + (a.measurement||'').substring(0,40) + '…</dd>';
        html += '<dt>Signed by</dt><dd>' + (a.signed_by||'') + '</dd>';
        if (a.claims) {
          if (a.claims.network_destinations)
            html += '<dt>Network</dt><dd>' + a.claims.network_destinations.join(', ') + '</dd>';
          if (a.claims.sub_agent_chain)
            html += '<dt>Sub-agents</dt><dd>' + a.claims.sub_agent_chain.length + ' in chain</dd>';
        }
        html += '</dl>';
      }

      // Extractions
      if (r.extractions && r.extractions.length > 0) {
        html += '<h3 style="margin-top:1rem">📄 Extractions</h3>';
        r.extractions.forEach((ext, i) => {
          const e = typeof ext === 'string' ? JSON.parse(ext) : ext;
          html += '<div class="extraction">';
          html += '<h4>' + (e.extraction_type||'extraction') + ' — ' + (e.document_id||'doc-'+i) + '</h4>';
          if (e.fields) {
            html += '<div class="field-grid">';
            Object.entries(e.fields).forEach(([k,v]) => {
              html += '<div class="field-item"><div class="fname">'+k+'</div><div>'+v+'</div></div>';
            });
            html += '</div>';
          }
          if (e.tables) {
            e.tables.forEach(t => {
              html += '<h4 style="margin-top:0.75rem">Table: '+(t.table_id||t.name||'')+'</h4>';
              const cols = t.column_definitions || t.columns || [];
              const headers = t.headers || cols.map(c=>c.name);
              html += '<div style="overflow-x:auto"><table><tr>';
              headers.forEach(h => html += '<th>'+h+'</th>');
              html += '</tr>';
              const rows = t.rows || [];
              rows.forEach(row => {
                html += '<tr>';
                if (Array.isArray(row)) {
                  row.forEach(c => html += '<td>'+c+'</td>');
                } else {
                  headers.forEach(h => html += '<td>'+(row[h]!==undefined?row[h]:'')+'</td>');
                }
                html += '</tr>';
              });
              html += '</table></div>';
            });
          }
          html += '</div>';
        });
      }

      // End of session attestation
      if (r.end_of_session_attestation) {
        const eos = r.end_of_session_attestation;
        html += '<h3 style="margin-top:1rem">✅ End-of-Session Attestation</h3>';
        html += '<dl class="kv">';
        html += '<dt>Measurement match</dt><dd>' + (eos.measurement_matches_start ? '✅ Yes' : '❌ No') + '</dd>';
        html += '<dt>Timestamp</dt><dd>' + (eos.timestamp||'') + '</dd>';
        html += '</dl>';
      }

      html += '<button class="json-toggle" onclick="toggleJson(this)">▸ Show Full JSON</button>';
      html += '<pre class="json">' + JSON.stringify(r, null, 2) + '</pre>';
    }

    html += '</div>';
    return html;
  }).join('');
}

// Contracts
const ctDiv = document.getElementById('contracts');
if (!D.contracts || D.contracts.length === 0) {
  ctDiv.innerHTML = '<div class="empty">No contracts yet</div>';
} else {
  ctDiv.innerHTML = D.contracts.map(c => {
    let html = '<div class="card"><h3>Contract ' + statusTag(c.status||'active') + '</h3>';
    html += '<dl class="kv">';
    html += '<dt>Contract ID</dt><dd class="mono">' + c.contract_id + '</dd>';
    html += '<dt>Consumer</dt><dd>' + (c.consumer?.org_id||'') + '</dd>';
    html += '<dt>Operations</dt><dd>' + (c.permissions?.operations||[]).join(', ') + '</dd>';
    html += '<dt>Enclaves</dt><dd>' + (c.attestation_requirements?.enclave_types||[]).join(', ') + '</dd>';
    html += '</dl>';
    html += '<button class="json-toggle" onclick="toggleJson(this)">▸ Show Full JSON</button>';
    html += '<pre class="json">' + JSON.stringify(c, null, 2) + '</pre>';
    html += '</div>';
    return html;
  }).join('');
}

// Manifests
const mfDiv = document.getElementById('manifests');
if (!D.manifests || D.manifests.length === 0) {
  mfDiv.innerHTML = '<div class="empty">No manifests yet</div>';
} else {
  mfDiv.innerHTML = D.manifests.map(m => {
    let html = '<div class="card"><h3>Manifest — ' + (m.owner?.org_name||m.owner?.org_id||'') + '</h3>';
    html += '<dl class="kv">';
    html += '<dt>Manifest ID</dt><dd class="mono">' + m.manifest_id + '</dd>';
    html += '<dt>Documents</dt><dd>' + (m.documents||[]).length + '</dd>';
    html += '<dt>Created</dt><dd>' + (m.created_at||'') + '</dd>';
    html += '</dl>';
    if (m.documents) {
      html += '<table><tr><th>Document ID</th><th>Classification</th><th>Sensitivity</th><th>Format</th></tr>';
      m.documents.forEach(d => {
        html += '<tr><td class="mono" style="font-size:0.7rem">'+d.document_id+'</td>';
        html += '<td>'+( d.classification||'')+'</td><td>'+(d.sensitivity||'')+'</td>';
        html += '<td>'+(d.format||d.mime_type||'')+'</td></tr>';
      });
      html += '</table>';
    }
    html += '<button class="json-toggle" onclick="toggleJson(this)">▸ Show Full JSON</button>';
    html += '<pre class="json">' + JSON.stringify(m, null, 2) + '</pre>';
    html += '</div>';
    return html;
  }).join('');
}

// Audit Trail
const auDiv = document.getElementById('audit');
if (!D.events || D.events.length === 0) {
  auDiv.innerHTML = '<div class="empty">No audit events yet</div>';
} else {
  let html = '<div class="card"><h3>Audit Timeline (' + D.events.length + ' events)</h3>';
  html += '<div class="timeline">';
  D.events.forEach(e => {
    const cls = (e.outcome?.status === 'success') ? 'success' : (e.outcome?.status === 'denied' ? 'error' : 'warning');
    html += '<div class="tl-item '+cls+'">';
    html += '<div class="tl-type">' + e.event_type + '</div>';
    html += '<div class="tl-time">' + (e.timestamp||'') + '</div>';
    if (e.actor) html += '<div class="tl-detail">Actor: ' + (e.actor.type||'') + (e.actor.org_id?' ('+e.actor.org_id+')':'') + '</div>';
    if (e.subject) html += '<div class="tl-detail">Subject: ' + (e.subject.type||'') + (e.subject.session_id?' session:'+e.subject.session_id.substring(0,16)+'…':'') + '</div>';
    html += '</div>';
  });
  html += '</div>';
  html += '</div>';
  auDiv.innerHTML = html;
}
</script>
</body>
</html>`;
}

