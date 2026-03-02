"""DSP Gateway — Reference Implementation

A minimal DSP Gateway that demonstrates the full protocol flow:
  1. Register manifests and contracts (from document owner)
  2. Handle agent sessions (attestation verification, token issuance)
  3. Receive and validate results
  4. Maintain an auditable Merkle-chained event log
  5. Serve a live dashboard at /

IMPORTANT: This is a REFERENCE IMPLEMENTATION for development and testing.
Attestation verification is SIMULATED. Production deployments MUST use
real hardware attestation (SGX, SEV-SNP, TDX, Nitro).
"""

import datetime
import hashlib
import json
import os
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

app = FastAPI(
    title="DSP Gateway",
    description="Document Sovereignty Protocol — Reference Gateway",
    version="0.1.0",
)

# ── In-memory stores (production uses a database) ──────────
manifests: dict[str, dict] = {}
contracts: dict[str, dict] = {}
sessions: dict[str, dict] = {}
results: dict[str, dict] = {}
audit_events: list[dict] = []
event_sequence = 0
flow_steps: list[dict] = []  # Human-readable timeline


# ── Helpers ─────────────────────────────────────────────────

def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:16]}"


def hash_dict(data: dict) -> dict:
    raw = json.dumps(data, sort_keys=True, default=str)
    return {"algorithm": "sha-256", "value": hashlib.sha256(raw.encode()).hexdigest()}


def add_audit_event(event_type: str, **details: Any) -> dict:
    """Create and store an audit event, maintaining the Merkle chain."""
    global event_sequence
    actor = details.pop("actor", {"type": "system"})
    status = details.pop("status", "success")

    event: dict[str, Any] = {
        "event_id": make_id("ev"),
        "sequence_number": event_sequence,
        "timestamp": now_utc(),
        "event_type": event_type,
        "actor": actor,
        "action": {k: v for k, v in details.items() if v is not None},
        "outcome": {"status": status},
    }

    if event_sequence > 0 and audit_events:
        event["previous_event_hash"] = audit_events[-1].get("event_hash")

    event["event_hash"] = hash_dict(
        {k: v for k, v in event.items() if k != "event_hash"}
    )

    audit_events.append(event)
    event_sequence += 1
    return event


def add_flow_step(icon: str, title: str, detail: str) -> None:
    """Add a human-readable step to the flow timeline."""
    flow_steps.append({
        "icon": icon,
        "title": title,
        "detail": detail,
        "time": now_utc(),
    })


def validate_result(result_data: dict, contract_data: dict | None) -> dict:
    """Validate a result envelope against its contract. Returns validation report."""
    issues: list[str] = []
    warnings: list[str] = []

    if not contract_data:
        warnings.append("No contract found — skipping compliance checks")
        return {"valid": True, "issues": issues, "warnings": warnings, "checked_at": now_utc()}

    # Contract ID match
    if result_data.get("contract_id") != contract_data.get("contract_id"):
        issues.append("Contract ID mismatch between result and contract")

    # Network policy
    claims = result_data.get("attestation", {}).get("claims", {})
    net_policy = contract_data.get("restrictions", {}).get("network_policy", {})
    if net_policy.get("egress") == "allow_listed":
        allowed = set()
        for d in net_policy.get("allowed_destinations", []):
            allowed.add(f"{d['host']}:{d['port']}")
        for dest in claims.get("network_destinations", []):
            if dest not in allowed:
                issues.append(f"Unauthorized network destination: {dest}")

    # Result scanning
    scan = result_data.get("result_scan", {})
    scanning_cfg = contract_data.get("restrictions", {}).get("result_scanning", {})
    if scanning_cfg.get("enabled") and not scan.get("performed"):
        issues.append("Result scanning required but not performed")
    if scan.get("performed"):
        required_scanners = set(scanning_cfg.get("scanners_required", []))
        actual_scanners = {v.get("scanner_type") for v in scan.get("verdicts", [])}
        missing = required_scanners - actual_scanners
        if missing:
            issues.append(f"Missing required scanners: {', '.join(missing)}")

    # Raw content policy
    pii = result_data.get("pii_report", {})
    result_policy = contract_data.get("restrictions", {}).get("result_policy", {})
    if pii.get("raw_content_included") and not result_policy.get("raw_content_allowed"):
        issues.append("Raw content included but not allowed by contract")

    # PII compliance
    if pii.get("compliance_status") == "violation_detected":
        issues.append("PII compliance violation detected by agent")

    # End-of-session attestation
    eos = result_data.get("end_of_session_attestation", {})
    runtime = contract_data.get("attestation_requirements", {}).get("runtime_verification", {})
    if runtime.get("end_of_session_attestation_required") and not eos:
        warnings.append("End-of-session attestation expected but not present")
    if eos and not eos.get("measurement_matches_start", True):
        issues.append("End-of-session measurement does not match start — possible tampering")

    # Sub-agent chain
    chain = claims.get("sub_agent_chain", [])
    sub_policy = contract_data.get("consumer", {}).get("sub_agent_policy", {})
    if sub_policy:
        max_steps = sub_policy.get("max_pipeline_steps")
        if max_steps and len(chain) > max_steps:
            issues.append(f"Sub-agent chain has {len(chain)} steps, max allowed is {max_steps}")
        if not sub_policy.get("llm_sub_agent_allowed", False):
            for step in chain:
                if step.get("agent_type") == "llm_freeform":
                    issues.append(f"LLM sub-agent at step {step.get('step_index')} not allowed")

    # Numeric precision
    precision = result_policy.get("numeric_precision_policy", {})
    if precision:
        max_dp = precision.get("max_decimal_places", 2)
        for ext in result_data.get("extractions", []):
            for key, val in ext.get("fields", {}).items():
                if isinstance(val, float):
                    s = f"{val:.20f}".rstrip("0")
                    if "." in s:
                        decimals = len(s.split(".")[1])
                        if decimals > max_dp:
                            issues.append(f"Field '{key}' has {decimals} decimals (max {max_dp})")

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "warnings": warnings,
        "checked_at": now_utc(),
    }


# ── API Endpoints ───────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "dsp_version": "0.1", "gateway": "reference-impl"}


@app.post("/manifests")
async def register_manifest(request: Request):
    data = await request.json()
    mid = data.get("manifest_id")
    if not mid:
        raise HTTPException(400, "manifest_id required")
    manifests[mid] = data
    doc_count = len(data.get("documents", []))
    add_audit_event("manifest.created", manifest_id=mid, document_count=doc_count)
    add_flow_step("📋", "Manifest registered",
                  f"{doc_count} documents from {data.get('owner', {}).get('org_name', '?')}")
    return {"status": "registered", "manifest_id": mid}


@app.get("/manifests/{manifest_id}")
async def get_manifest(manifest_id: str):
    if manifest_id not in manifests:
        raise HTTPException(404, "Manifest not found")
    return manifests[manifest_id]


@app.post("/contracts")
async def register_contract(request: Request):
    data = await request.json()
    cid = data.get("contract_id")
    if not cid:
        raise HTTPException(400, "contract_id required")
    contracts[cid] = data
    consumer = data.get("consumer", {})
    add_audit_event("contract.created", contract_id=cid,
                    consumer_org=consumer.get("org_id"))
    add_flow_step("📜", "Contract created",
                  f"{consumer.get('org_name', '?')} → {consumer.get('agent_type', '?')}")
    return {"status": "registered", "contract_id": cid}


@app.get("/contracts/{contract_id}")
async def get_contract(contract_id: str):
    if contract_id not in contracts:
        raise HTTPException(404, "Contract not found")
    return contracts[contract_id]


@app.post("/sessions")
async def start_session(request: Request):
    data = await request.json()
    contract_id = data.get("contract_id")
    manifest_id = data.get("manifest_id")
    attestation = data.get("attestation", {})

    contract = contracts.get(contract_id)
    if not contract:
        raise HTTPException(404, f"Contract {contract_id} not found")

    manifest = manifests.get(manifest_id)
    if not manifest:
        raise HTTPException(404, f"Manifest {manifest_id} not found")

    # Verify attestation (SIMULATED)
    enclave_type = attestation.get("enclave_type", "sandbox")
    allowed = contract.get("attestation_requirements", {}).get("enclave_types", [])
    if enclave_type not in allowed:
        add_audit_event("session.rejected",
                        reason=f"Enclave type '{enclave_type}' not accepted",
                        actor={"type": "agent", "org_id": data.get("agent_org_id")})
        add_flow_step("🚫", "Session rejected",
                      f"Enclave type '{enclave_type}' not in allowed list")
        raise HTTPException(403, f"Enclave type '{enclave_type}' not accepted by contract")

    session_id = make_id("ps")
    doc_ids = [d["document_id"] for d in manifest.get("documents", [])]
    operations = contract.get("permissions", {}).get("operations", [])
    duration = contract.get("permissions", {}).get("max_session_duration_seconds", 3600)

    token = {
        "token": f"dsp-tok-{uuid.uuid4().hex}",
        "expires_at": (
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(seconds=duration)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {"document_ids": doc_ids, "operations": operations},
    }

    # Provide MinIO credentials scoped to this session (in production, use STS)
    token["storage_credentials"] = {
        "access_key": os.environ.get("MINIO_AGENT_ACCESS_KEY", "dsp-owner"),
        "secret_key": os.environ.get("MINIO_AGENT_SECRET_KEY", "dsp-owner-secret-key"),
    }

    sessions[session_id] = {
        "session_id": session_id,
        "contract_id": contract_id,
        "manifest_id": manifest_id,
        "status": "active",
        "started_at": now_utc(),
        "enclave_type": enclave_type,
    }

    add_audit_event("session.started", session_id=session_id,
                    contract_id=contract_id, enclave_type=enclave_type,
                    actor={"type": "agent", "org_id": data.get("agent_org_id")})
    add_flow_step("🔐", "Session started",
                  f"Enclave: {enclave_type} | Token issued for {len(doc_ids)} docs")

    return {"session_id": session_id, "token": token, "manifest": manifest}


@app.post("/sessions/{session_id}/results")
async def submit_result(session_id: str, request: Request):
    if session_id not in sessions:
        raise HTTPException(404, f"Session {session_id} not found")

    session = sessions[session_id]
    if session["status"] != "active":
        raise HTTPException(409, f"Session is {session['status']}")

    data = await request.json()
    contract = contracts.get(session["contract_id"])

    validation = validate_result(data, contract)

    results[session_id] = {
        "result": data,
        "validation": validation,
        "received_at": now_utc(),
    }

    session["status"] = "completed" if validation["valid"] else "completed_with_issues"
    session["completed_at"] = now_utc()

    add_audit_event("result.delivered", session_id=session_id,
                    result_id=data.get("result_id"),
                    valid=validation["valid"],
                    issue_count=len(validation["issues"]))

    pii = data.get("pii_report", {})
    scan = data.get("result_scan", {})

    if scan.get("performed"):
        add_flow_step("🔍", "Result scanned",
                      f"{len(scan.get('verdicts', []))} scanners | "
                      f"Fields modified: {scan.get('fields_modified_by_scan', 0)}")

    pii_status = pii.get("compliance_status", "unknown")
    add_flow_step("🛡️", "PII report",
                  f"Encountered: {len(pii.get('fields_encountered', []))} | "
                  f"Redacted: {len(pii.get('fields_redacted', []))} | "
                  f"Status: {pii_status}")

    if validation["valid"]:
        add_audit_event("result.validated", session_id=session_id)
        add_flow_step("✅", "Result validated",
                      f"All {len(validation.get('warnings', []))} warnings, 0 issues")
    else:
        for issue in validation["issues"]:
            add_audit_event("violation.detected", session_id=session_id,
                            description=issue)
        add_flow_step("⚠️", "Validation issues",
                      f"{len(validation['issues'])} issues found")

    return {"status": "accepted", "validation": validation}


@app.get("/api/state")
async def api_state():
    """Full gateway state — consumed by dashboard polling."""
    return {
        "manifests": list(manifests.values()),
        "contracts": list(contracts.values()),
        "sessions": list(sessions.values()),
        "results": {k: v for k, v in results.items()},
        "audit_events": audit_events,
        "flow_steps": flow_steps,
        "stats": {
            "manifests": len(manifests),
            "contracts": len(contracts),
            "sessions": len(sessions),
            "active_sessions": sum(1 for s in sessions.values() if s["status"] == "active"),
            "completed": sum(1 for s in sessions.values() if "completed" in s["status"]),
            "results": len(results),
            "valid_results": sum(1 for r in results.values() if r["validation"]["valid"]),
            "audit_events": len(audit_events),
        },
    }


# ── Dashboard ───────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return DASHBOARD_HTML


# Genesis event
add_audit_event("ledger.genesis", reason="DSP Gateway reference implementation started")
add_flow_step("🚀", "Gateway started", "DSP v0.1 reference implementation ready")


# ── Dashboard HTML ──────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DSP Gateway — Reference Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body { background: #0f172a; color: #e2e8f0; font-family: 'Inter', system-ui, sans-serif; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; }
  .badge { display: inline-flex; align-items: center; padding: 2px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
  .badge-green { background: #064e3b; color: #6ee7b7; }
  .badge-yellow { background: #713f12; color: #fde68a; }
  .badge-red { background: #7f1d1d; color: #fca5a5; }
  .badge-blue { background: #1e3a5f; color: #93c5fd; }
  .stat-value { font-size: 2rem; font-weight: 700; line-height: 1; }
  .flow-item { border-left: 2px solid #334155; padding-left: 16px; margin-left: 12px; }
  .flow-item:last-child { border-left-color: transparent; }
  pre { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; overflow-x: auto; font-size: 0.8rem; }
  .pulse { animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
  .collapsible { max-height: 0; overflow: hidden; transition: max-height 0.3s ease; }
  .collapsible.open { max-height: 2000px; }
  .toggle-btn { cursor: pointer; user-select: none; }
</style>
</head>
<body class="min-h-screen">

<div class="max-w-7xl mx-auto px-4 py-8">
  <!-- Header -->
  <div class="flex items-center justify-between mb-8">
    <div>
      <h1 class="text-3xl font-bold text-white">
        🏛️ DSP Gateway
      </h1>
      <p class="text-slate-400 mt-1">Document Sovereignty Protocol — Reference Implementation v0.1</p>
    </div>
    <div id="status" class="badge badge-blue pulse">Connecting...</div>
  </div>

  <!-- Stats -->
  <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
    <div class="card p-4 text-center">
      <div class="text-slate-400 text-sm mb-1">Manifests</div>
      <div class="stat-value text-blue-400" id="stat-manifests">0</div>
    </div>
    <div class="card p-4 text-center">
      <div class="text-slate-400 text-sm mb-1">Contracts</div>
      <div class="stat-value text-purple-400" id="stat-contracts">0</div>
    </div>
    <div class="card p-4 text-center">
      <div class="text-slate-400 text-sm mb-1">Sessions</div>
      <div class="stat-value text-amber-400" id="stat-sessions">0</div>
    </div>
    <div class="card p-4 text-center">
      <div class="text-slate-400 text-sm mb-1">Results</div>
      <div class="stat-value" id="stat-results">0</div>
    </div>
  </div>

  <!-- Main grid -->
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

    <!-- Processing Flow -->
    <div class="card p-6 lg:col-span-2">
      <h2 class="text-lg font-semibold text-white mb-4">⚡ Processing Flow</h2>
      <div id="flow-timeline" class="space-y-3">
        <div class="text-slate-500 italic">Waiting for events...</div>
      </div>
    </div>

    <!-- PII Safety Report -->
    <div class="card p-6">
      <h2 class="text-lg font-semibold text-white mb-4">🛡️ PII Safety Report</h2>
      <div id="pii-report" class="text-slate-400">No results yet.</div>
    </div>

    <!-- Validation -->
    <div class="card p-6">
      <h2 class="text-lg font-semibold text-white mb-4">✅ Validation</h2>
      <div id="validation-report" class="text-slate-400">No results yet.</div>
    </div>

    <!-- Audit Trail -->
    <div class="card p-6 lg:col-span-2">
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-semibold text-white">📒 Audit Trail</h2>
        <span class="badge badge-blue" id="audit-count">0 events</span>
      </div>
      <div id="audit-trail" class="space-y-1 max-h-96 overflow-y-auto">
        <div class="text-slate-500 italic">No events yet.</div>
      </div>
    </div>

    <!-- Sub-Agent Chain -->
    <div class="card p-6">
      <h2 class="text-lg font-semibold text-white mb-4">🔗 Sub-Agent Chain</h2>
      <div id="sub-agent-chain" class="text-slate-400">No chain reported yet.</div>
    </div>

    <!-- Contract Details -->
    <div class="card p-6">
      <h2 class="text-lg font-semibold text-white mb-4 toggle-btn" onclick="toggleSection('contract-json')">
        📜 Contract Details <span class="text-sm text-slate-500">(click to expand)</span>
      </h2>
      <div id="contract-json" class="collapsible">
        <pre class="text-slate-300">Loading...</pre>
      </div>
    </div>

  </div>

  <!-- Footer -->
  <div class="text-center text-slate-600 text-sm mt-8">
    DSP v0.1 · Apache 2.0 · Reference Implementation — Not for production
  </div>
</div>

<script>
function toggleSection(id) {
  document.getElementById(id).classList.toggle('open');
}

function formatTime(ts) {
  if (!ts) return '';
  try { return new Date(ts).toLocaleTimeString(); } catch(e) { return ts; }
}

function renderFlow(steps) {
  const el = document.getElementById('flow-timeline');
  if (!steps || steps.length === 0) {
    el.innerHTML = '<div class="text-slate-500 italic">Waiting for events...</div>';
    return;
  }
  el.innerHTML = steps.map(s => `
    <div class="flow-item py-2">
      <div class="flex items-center gap-2">
        <span class="text-xl">${s.icon}</span>
        <span class="font-semibold text-white">${s.title}</span>
        <span class="text-slate-500 text-xs ml-auto">${formatTime(s.time)}</span>
      </div>
      <div class="text-slate-400 text-sm mt-1">${s.detail}</div>
    </div>
  `).join('');
}

function renderPII(results) {
  const el = document.getElementById('pii-report');
  const entries = Object.values(results);
  if (entries.length === 0) { el.innerHTML = '<span class="text-slate-500">No results yet.</span>'; return; }
  const r = entries[0].result;
  const pii = r.pii_report || {};
  const enc = (pii.fields_encountered || []);
  const red = (pii.fields_redacted || []);
  const methods = (pii.redaction_methods_used || []);
  const status = pii.compliance_status || 'unknown';
  const badge = status === 'compliant' ? 'badge-green' : status === 'violation_detected' ? 'badge-red' : 'badge-yellow';
  el.innerHTML = `
    <div class="space-y-3">
      <div class="flex justify-between"><span class="text-slate-400">Fields encountered</span><span class="text-white font-mono">${enc.length}</span></div>
      <div class="flex justify-between"><span class="text-slate-400">Fields redacted</span><span class="text-white font-mono">${red.length}</span></div>
      <div class="flex justify-between"><span class="text-slate-400">Redaction methods</span><span class="text-white font-mono text-right">${methods.join(', ') || 'none'}</span></div>
      <div class="flex justify-between"><span class="text-slate-400">Raw content included</span><span class="text-white font-mono">${pii.raw_content_included ? '❌ YES' : '✅ NO'}</span></div>
      <div class="flex justify-between items-center"><span class="text-slate-400">Compliance</span><span class="badge ${badge}">${status.toUpperCase()}</span></div>
      <div class="mt-3">
        <div class="text-slate-500 text-xs mb-1">Encountered fields:</div>
        <div class="flex flex-wrap gap-1">${enc.map(f => `<span class="badge badge-blue">${f}</span>`).join('')}</div>
      </div>
      <div class="mt-2">
        <div class="text-slate-500 text-xs mb-1">Redacted fields:</div>
        <div class="flex flex-wrap gap-1">${red.map(f => `<span class="badge badge-green">${f}</span>`).join('')}</div>
      </div>
    </div>
  `;
}

function renderValidation(results) {
  const el = document.getElementById('validation-report');
  const entries = Object.values(results);
  if (entries.length === 0) { el.innerHTML = '<span class="text-slate-500">No results yet.</span>'; return; }
  const v = entries[0].validation;
  const badge = v.valid ? 'badge-green' : 'badge-red';
  el.innerHTML = `
    <div class="space-y-3">
      <div class="flex justify-between items-center">
        <span class="text-slate-400">Status</span>
        <span class="badge ${badge}">${v.valid ? 'PASSED' : 'FAILED'}</span>
      </div>
      <div class="flex justify-between"><span class="text-slate-400">Issues</span><span class="text-white font-mono">${v.issues.length}</span></div>
      <div class="flex justify-between"><span class="text-slate-400">Warnings</span><span class="text-white font-mono">${v.warnings.length}</span></div>
      <div class="flex justify-between"><span class="text-slate-400">Checked at</span><span class="text-white font-mono text-sm">${formatTime(v.checked_at)}</span></div>
      ${v.issues.length > 0 ? `
        <div class="mt-2">
          <div class="text-red-400 text-xs mb-1">Issues:</div>
          ${v.issues.map(i => `<div class="text-red-300 text-sm">• ${i}</div>`).join('')}
        </div>
      ` : ''}
      ${v.warnings.length > 0 ? `
        <div class="mt-2">
          <div class="text-amber-400 text-xs mb-1">Warnings:</div>
          ${v.warnings.map(w => `<div class="text-amber-300 text-sm">• ${w}</div>`).join('')}
        </div>
      ` : ''}
    </div>
  `;
}

function renderAudit(events) {
  const el = document.getElementById('audit-trail');
  document.getElementById('audit-count').textContent = events.length + ' events';
  if (events.length === 0) { el.innerHTML = '<div class="text-slate-500 italic">No events yet.</div>'; return; }
  el.innerHTML = events.map(e => {
    const badge = e.outcome.status === 'success' ? 'badge-green' : 'badge-red';
    return `
      <div class="flex items-center gap-3 py-1 px-2 rounded hover:bg-slate-700/30 text-sm">
        <span class="text-slate-500 font-mono w-6 text-right">#${e.sequence_number}</span>
        <span class="badge ${badge} w-40 justify-center">${e.event_type}</span>
        <span class="text-slate-400 flex-1 truncate">${Object.entries(e.action || {}).map(([k,v]) => k+'='+v).join(' ') || ''}</span>
        <span class="text-slate-600 text-xs">${formatTime(e.timestamp)}</span>
      </div>
    `;
  }).join('');
  el.scrollTop = el.scrollHeight;
}

function renderSubAgentChain(results) {
  const el = document.getElementById('sub-agent-chain');
  const entries = Object.values(results);
  if (entries.length === 0) { el.innerHTML = '<span class="text-slate-500">No chain reported yet.</span>'; return; }
  const chain = entries[0].result?.attestation?.claims?.sub_agent_chain || [];
  if (chain.length === 0) { el.innerHTML = '<span class="text-slate-500">No sub-agents declared.</span>'; return; }
  el.innerHTML = chain.map((s, i) => `
    <div class="flex items-center gap-3 py-2 ${i < chain.length - 1 ? 'border-b border-slate-700' : ''}">
      <div class="w-8 h-8 rounded-full bg-slate-700 flex items-center justify-center text-sm font-bold text-blue-400">${s.step_index}</div>
      <div class="flex-1">
        <div class="text-white font-medium">${s.agent_id || 'unknown'}</div>
        <div class="text-slate-400 text-xs">${s.purpose} · ${s.agent_type} · v${s.agent_version || '?'}</div>
      </div>
      <div class="text-xs font-mono text-slate-500">${(s.agent_hash?.value || '').substring(0, 12)}…</div>
    </div>
  `).join('');
}

function renderContractDetails(contracts) {
  const el = document.getElementById('contract-json').querySelector('pre');
  if (contracts.length === 0) { el.textContent = 'No contracts registered.'; return; }
  el.textContent = JSON.stringify(contracts[0], null, 2);
}

async function poll() {
  try {
    const r = await fetch('/api/state');
    const data = await r.json();
    const s = data.stats;

    document.getElementById('stat-manifests').textContent = s.manifests;
    document.getElementById('stat-contracts').textContent = s.contracts;
    document.getElementById('stat-sessions').textContent = `${s.completed}/${s.sessions}`;
    document.getElementById('stat-results').textContent = s.results;
    document.getElementById('stat-results').className =
      `stat-value ${s.valid_results > 0 ? 'text-green-400' : s.results > 0 ? 'text-red-400' : 'text-slate-400'}`;

    const statusEl = document.getElementById('status');
    if (s.completed > 0) {
      statusEl.textContent = s.valid_results > 0 ? 'Completed ✓' : 'Completed (issues)';
      statusEl.className = `badge ${s.valid_results > 0 ? 'badge-green' : 'badge-yellow'}`;
    } else if (s.active_sessions > 0) {
      statusEl.textContent = 'Processing...';
      statusEl.className = 'badge badge-yellow pulse';
    } else if (s.manifests > 0) {
      statusEl.textContent = 'Ready';
      statusEl.className = 'badge badge-blue';
    }

    renderFlow(data.flow_steps);
    renderPII(data.results);
    renderValidation(data.results);
    renderAudit(data.audit_events);
    renderSubAgentChain(data.results);
    renderContractDetails(data.contracts);
  } catch (e) {
    document.getElementById('status').textContent = 'Disconnected';
    document.getElementById('status').className = 'badge badge-red';
  }
}

setInterval(poll, 2000);
poll();
</script>
</body>
</html>
"""

