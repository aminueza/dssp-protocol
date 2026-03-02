// Package handler implements the HTTP handlers for all DSP gateway endpoints.
// It uses Go 1.22's enhanced http.ServeMux pattern matching for routing.
package handler

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/dsp-protocol/gateway/internal/audit"
	"github.com/dsp-protocol/gateway/internal/storage"
	"github.com/dsp-protocol/gateway/internal/store"
	"github.com/dsp-protocol/gateway/internal/types"
	"github.com/google/uuid"
)

// Handler holds dependencies for all HTTP handlers.
type Handler struct {
	store   store.Store
	chain   *audit.Chain
	log     *slog.Logger
	storage storage.Adapter
}

// New creates a new Handler with the given dependencies.
func New(s store.Store, c *audit.Chain, log *slog.Logger, sa storage.Adapter) *Handler {
	return &Handler{
		store:   s,
		chain:   c,
		log:     log,
		storage: sa,
	}
}

// RegisterRoutes registers all DSP endpoints on the given mux.
// Uses Go 1.22 method-aware routing patterns.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Manifests
	mux.HandleFunc("POST /v0.1/manifests", h.createManifest)
	mux.HandleFunc("GET /v0.1/manifests/{id}", h.getManifest)
	mux.HandleFunc("GET /v0.1/manifests", h.listManifests)

	// Contracts
	mux.HandleFunc("POST /v0.1/contracts", h.createContract)
	mux.HandleFunc("GET /v0.1/contracts/{id}", h.getContract)
	mux.HandleFunc("PATCH /v0.1/contracts/{id}", h.updateContract)
	mux.HandleFunc("GET /v0.1/contracts", h.listContracts)

	// Sessions
	mux.HandleFunc("POST /v0.1/sessions", h.createSession)
	mux.HandleFunc("GET /v0.1/sessions/{id}", h.getSession)
	mux.HandleFunc("POST /v0.1/sessions/{id}/heartbeat", h.heartbeat)
	mux.HandleFunc("POST /v0.1/sessions/{id}/complete", h.completeSession)

	// Results
	mux.HandleFunc("POST /v0.1/sessions/{id}/result", h.postResult)
	mux.HandleFunc("GET /v0.1/sessions/{id}/result", h.getResult)

	// Audit
	mux.HandleFunc("POST /v0.1/audit/events", h.appendAuditEvent)
	mux.HandleFunc("GET /v0.1/audit/events", h.listAuditEvents)

	// Storage
	mux.HandleFunc("POST /v0.1/storage/grant-access", h.grantAccess)

	// Well-known configuration
	mux.HandleFunc("GET /v0.1/.well-known/dsp-configuration", h.getConfiguration)

	// Health check
	mux.HandleFunc("GET /health", h.healthCheck)

	// Dashboard UI
	mux.HandleFunc("GET /", h.dashboard)
	mux.HandleFunc("GET /api/state", h.apiState)
}

// ──────────────────────────────────────────────────────────────
// ID generation
// ──────────────────────────────────────────────────────────────

// makeID generates a DSP identifier with the given prefix.
// Format: <prefix>-<hex> where hex is the full UUID bytes.
func makeID(prefix string) string {
	u := uuid.New()
	b, _ := u.MarshalBinary()
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// ──────────────────────────────────────────────────────────────
// JSON helpers
// ──────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, types.DSPError{
		Error:     http.StatusText(status),
		Code:      code,
		Message:   message,
		Timestamp: types.NowUTC(),
	})
}

func decodeBody(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

// ──────────────────────────────────────────────────────────────
// Audit event emission helper
// ──────────────────────────────────────────────────────────────

func (h *Handler) emitEvent(
	eventType string,
	actor types.AuditActor,
	subject *types.AuditSubject,
	action map[string]interface{},
	outcome types.AuditOutcome,
) {
	event, err := h.chain.NewEvent(eventType, actor, subject, action, outcome)
	if err != nil {
		h.log.Error("failed to create audit event", "type", eventType, "error", err)
		return
	}
	if err := h.store.AppendEvent(event); err != nil {
		h.log.Error("failed to store audit event", "type", eventType, "error", err)
	}
}

// ──────────────────────────────────────────────────────────────
// Health
// ──────────────────────────────────────────────────────────────

func (h *Handler) healthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"dsp_version": types.DSPVersion,
		"gateway":     "reference-impl-go",
		"timestamp":   types.NowUTC(),
	})
}

// ──────────────────────────────────────────────────────────────
// Manifests
// ──────────────────────────────────────────────────────────────

func (h *Handler) createManifest(w http.ResponseWriter, r *http.Request) {
	var m types.Manifest
	if err := decodeBody(r, &m); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	// Assign ID if not provided.
	if m.ManifestID == "" {
		m.ManifestID = makeID(types.PrefixManifest)
	}
	if m.Schema == "" {
		m.Schema = types.SchemaManifest
	}
	if m.DSPVersion == "" {
		m.DSPVersion = types.DSPVersion
	}
	if m.CreatedAt == "" {
		m.CreatedAt = types.NowUTC()
	}

	// Compute summary if not provided.
	if m.Summary == nil && len(m.Documents) > 0 {
		m.Summary = computeSummary(m.Documents)
	}

	if err := h.store.CreateManifest(&m); err != nil {
		writeError(w, http.StatusConflict, "manifest_exists", err.Error())
		return
	}

	h.log.Info("manifest created", "manifest_id", m.ManifestID, "documents", len(m.Documents))

	h.emitEvent("manifest.created",
		audit.OwnerActor(m.Owner.OrgID),
		&types.AuditSubject{Type: "manifest", ManifestID: m.ManifestID},
		map[string]interface{}{
			"document_count": len(m.Documents),
		},
		audit.SuccessOutcome(),
	)

	writeJSON(w, http.StatusCreated, m)
}

func (h *Handler) getManifest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m, err := h.store.GetManifest(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (h *Handler) listManifests(w http.ResponseWriter, r *http.Request) {
	opts := parseListOptions(r)
	manifests, total, err := h.store.ListManifests(opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": manifests,
		"total": total,
	})
}

// ──────────────────────────────────────────────────────────────
// Contracts
// ──────────────────────────────────────────────────────────────

func (h *Handler) createContract(w http.ResponseWriter, r *http.Request) {
	var c types.Contract
	if err := decodeBody(r, &c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	// Assign defaults.
	if c.ContractID == "" {
		c.ContractID = makeID(types.PrefixContract)
	}
	if c.Schema == "" {
		c.Schema = types.SchemaContract
	}
	if c.DSPVersion == "" {
		c.DSPVersion = types.DSPVersion
	}
	if c.Status == "" {
		c.Status = "active"
	}
	if c.Version == 0 {
		c.Version = 1
	}
	if c.CreatedAt == "" {
		c.CreatedAt = types.NowUTC()
	}

	// Validate required fields.
	if len(c.Permissions.Operations) == 0 {
		writeError(w, http.StatusBadRequest, "missing_field", "permissions.operations is required")
		return
	}
	if c.Consumer.OrgID == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "consumer.org_id is required")
		return
	}
	if len(c.AttestationRequirements.EnclaveTypes) == 0 {
		writeError(w, http.StatusBadRequest, "missing_field", "attestation_requirements.enclave_types is required")
		return
	}
	if len(c.AttestationRequirements.MustInclude) == 0 {
		writeError(w, http.StatusBadRequest, "missing_field", "attestation_requirements.must_include is required")
		return
	}

	if err := h.store.CreateContract(&c); err != nil {
		writeError(w, http.StatusConflict, "contract_exists", err.Error())
		return
	}

	h.log.Info("contract created",
		"contract_id", c.ContractID,
		"consumer_org", c.Consumer.OrgID,
		"operations", c.Permissions.Operations,
	)

	h.emitEvent("contract.created",
		audit.OwnerActor(c.Owner.OrgID),
		&types.AuditSubject{Type: "contract", ContractID: c.ContractID},
		map[string]interface{}{
			"consumer_org": c.Consumer.OrgID,
			"operations":   c.Permissions.Operations,
		},
		audit.SuccessOutcome(),
	)

	writeJSON(w, http.StatusCreated, c)
}

func (h *Handler) getContract(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := h.store.GetContract(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h *Handler) updateContract(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	// Verify contract exists.
	contract, err := h.store.GetContract(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	var req types.ContractUpdateRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	// Validate status transitions.
	if req.Status != "" {
		if !isValidStatusTransition(contract.Status, req.Status) {
			writeError(w, http.StatusConflict, "invalid_transition",
				fmt.Sprintf("Cannot transition from '%s' to '%s'", contract.Status, req.Status))
			return
		}
	}

	update := store.ContractUpdate{
		Status:           req.Status,
		RevocationReason: req.RevocationReason,
		Version:          req.Version,
	}

	if err := h.store.UpdateContract(id, update); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}

	// Determine audit event type.
	eventType := "contract.updated"
	switch req.Status {
	case "suspended":
		eventType = "contract.suspended"
	case "revoked":
		eventType = "contract.revoked"
	case "expired":
		eventType = "contract.expired"
	}

	h.emitEvent(eventType,
		audit.OwnerActor(contract.Owner.OrgID),
		&types.AuditSubject{Type: "contract", ContractID: id},
		map[string]interface{}{
			"new_status": req.Status,
			"reason":     req.RevocationReason,
		},
		audit.SuccessOutcome(),
	)

	// Re-fetch to return updated state.
	updated, _ := h.store.GetContract(id)
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) listContracts(w http.ResponseWriter, r *http.Request) {
	opts := parseListOptions(r)
	contracts, total, err := h.store.ListContracts(opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": contracts,
		"total": total,
	})
}

// ──────────────────────────────────────────────────────────────
// Sessions
// ──────────────────────────────────────────────────────────────

func (h *Handler) createSession(w http.ResponseWriter, r *http.Request) {
	var req types.CreateSessionRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	if req.ContractID == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "contract_id is required")
		return
	}
	if req.ManifestID == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "manifest_id is required")
		return
	}

	// Fetch contract.
	contract, err := h.store.GetContract(req.ContractID)
	if err != nil {
		writeError(w, http.StatusNotFound, "contract_not_found", err.Error())
		return
	}

	// Fetch manifest.
	manifest, err := h.store.GetManifest(req.ManifestID)
	if err != nil {
		writeError(w, http.StatusNotFound, "manifest_not_found", err.Error())
		return
	}

	// Count active sessions for this contract.
	activeSessions, err := h.store.CountActiveSessions(req.ContractID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	// Validate against contract rules.
	violations := validateSessionRequest(contract, &req, activeSessions)

	// Check privacy budget.
	if contract.Restrictions.PrivacyBudget != nil {
		budgetViolations := checkPrivacyBudget(contract, contract.Restrictions.PrivacyBudget.BudgetConsumed)
		violations = append(violations, budgetViolations...)
	}

	if len(violations) > 0 {
		// Find the worst severity.
		hasCritical := false
		for _, v := range violations {
			if v.Severity == "critical" {
				hasCritical = true
				break
			}
		}

		agentActor := audit.AgentActor(req.AgentOrgID, req.AgentID)
		if hasCritical {
			h.emitEvent("session.terminated",
				agentActor,
				&types.AuditSubject{Type: "contract", ContractID: req.ContractID},
				map[string]interface{}{
					"reason":     "contract_violation",
					"violations": violations,
				},
				audit.DeniedOutcome("Contract violations prevent session creation"),
			)

			writeJSON(w, http.StatusForbidden, map[string]interface{}{
				"error":      "contract_violation",
				"message":    "Session request violates contract rules",
				"violations": violations,
				"timestamp":  types.NowUTC(),
			})
			return
		}

		// Warnings only: proceed but log.
		h.log.Warn("session created with warnings",
			"contract_id", req.ContractID,
			"warnings", violations,
		)
	}

	// Determine session duration.
	duration := contract.Permissions.MaxSessionDuration
	if duration <= 0 {
		duration = 3600 // default 1 hour
	}

	// Build document list and scoped token.
	docIDs := make([]string, 0, len(manifest.Documents))
	for _, d := range manifest.Documents {
		docIDs = append(docIDs, d.DocumentID)
	}

	enclaveType := ""
	if req.Attestation != nil {
		enclaveType = req.Attestation.EnclaveType
	}

	sessionID := makeID(types.PrefixSession)
	expiresAt := types.FutureUTC(time.Duration(duration) * time.Second)

	token := &types.ScopedToken{
		Token:     fmt.Sprintf("dsp-tok-%s", hex.EncodeToString(uuid.New().NodeID())),
		ExpiresAt: expiresAt,
		Scope: types.TokenScope{
			DocumentIDs: docIDs,
			Operations:  contract.Permissions.Operations,
		},
	}

	session := &types.Session{
		SessionID:   sessionID,
		ContractID:  req.ContractID,
		ManifestID:  req.ManifestID,
		Status:      types.SessionActive,
		EnclaveType: enclaveType,
		AgentOrgID:  req.AgentOrgID,
		AgentID:     req.AgentID,
		Token:       token,
		StartedAt:   types.NowUTC(),
		ExpiresAt:   expiresAt,
	}

	if err := h.store.CreateSession(session); err != nil {
		writeError(w, http.StatusInternalServerError, "session_create_failed", err.Error())
		return
	}

	h.log.Info("session started",
		"session_id", sessionID,
		"contract_id", req.ContractID,
		"enclave_type", enclaveType,
		"documents", len(docIDs),
	)

	h.emitEvent("session.started",
		audit.AgentActor(req.AgentOrgID, req.AgentID),
		&types.AuditSubject{
			Type:       "session",
			SessionID:  sessionID,
			ContractID: req.ContractID,
			ManifestID: req.ManifestID,
		},
		map[string]interface{}{
			"enclave_type":    enclaveType,
			"document_count":  len(docIDs),
			"expires_at":      expiresAt,
		},
		audit.SuccessOutcome(),
	)

	// Emit attestation.verified if attestation was provided.
	if req.Attestation != nil {
		h.emitEvent("attestation.verified",
			audit.GatewayActor(),
			&types.AuditSubject{Type: "session", SessionID: sessionID},
			map[string]interface{}{
				"enclave_type": enclaveType,
				"note":         "SIMULATED - reference implementation does not verify real attestation",
			},
			audit.SuccessOutcome(),
		)
	}

	writeJSON(w, http.StatusCreated, types.CreateSessionResponse{
		SessionID: sessionID,
		Token:     token,
		Manifest:  manifest,
		ExpiresAt: expiresAt,
	})
}

func (h *Handler) getSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess, err := h.store.GetSession(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

func (h *Handler) heartbeat(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	sess, err := h.store.GetSession(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	contract, err := h.store.GetContract(sess.ContractID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "contract_not_found", err.Error())
		return
	}

	var req types.HeartbeatRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	violations := validateHeartbeat(sess, contract, &req)

	if len(violations) > 0 {
		hasCritical := false
		for _, v := range violations {
			if v.Severity == "critical" || v.Severity == "error" {
				hasCritical = true
				break
			}
		}

		if hasCritical {
			// Terminate session.
			_ = h.store.UpdateSession(id, store.SessionUpdate{
				Status:      types.SessionTerminated,
				CompletedAt: types.NowUTC(),
			})

			h.emitEvent("session.terminated",
				audit.GatewayActor(),
				&types.AuditSubject{Type: "session", SessionID: id, ContractID: sess.ContractID},
				map[string]interface{}{
					"reason":     "heartbeat_violation",
					"violations": violations,
				},
				audit.FailureOutcome("heartbeat_violation", "Session terminated due to heartbeat violations"),
			)

			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"error":      "session_terminated",
				"message":    "Session terminated due to heartbeat violations",
				"violations": violations,
				"timestamp":  types.NowUTC(),
			})
			return
		}
	}

	// Update heartbeat timestamp.
	now := types.NowUTC()
	if err := h.store.UpdateSession(id, store.SessionUpdate{LastHeartbeat: now}); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}

	h.emitEvent("attestation.heartbeat",
		audit.AgentActor(sess.AgentOrgID, sess.AgentID),
		&types.AuditSubject{Type: "session", SessionID: id},
		map[string]interface{}{"heartbeat_at": now},
		audit.SuccessOutcome(),
	)

	// Compute next deadline.
	nextDeadline := ""
	if contract.AttestationRequirements.RuntimeVerification != nil {
		hbSecs := contract.AttestationRequirements.RuntimeVerification.PeriodicHeartbeatSecs
		if hbSecs > 0 {
			nextDeadline = types.FutureUTC(time.Duration(hbSecs) * time.Second)
		}
	}

	writeJSON(w, http.StatusOK, types.HeartbeatResponse{
		Acknowledged: true,
		NextDeadline: nextDeadline,
	})
}

func (h *Handler) completeSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	sess, err := h.store.GetSession(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}

	if sess.Status != types.SessionActive {
		writeError(w, http.StatusConflict, "invalid_state",
			fmt.Sprintf("Session is '%s', can only complete 'active' sessions", sess.Status))
		return
	}

	var req types.CompleteSessionRequest
	if err := decodeBody(r, &req); err != nil {
		// Allow empty body for simple completion.
		req.Status = types.SessionCompleted
	}

	finalStatus := types.SessionCompleted
	if req.Status == types.SessionFailed {
		finalStatus = types.SessionFailed
	}

	// If a result was submitted inline, store it.
	if req.ResultID != "" {
		_ = h.store.UpdateSession(id, store.SessionUpdate{ResultID: req.ResultID})
	}

	if err := h.store.UpdateSession(id, store.SessionUpdate{
		Status:      finalStatus,
		CompletedAt: types.NowUTC(),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}

	eventType := "session.completed"
	if finalStatus == types.SessionFailed {
		eventType = "session.failed"
	}

	h.emitEvent(eventType,
		audit.AgentActor(sess.AgentOrgID, sess.AgentID),
		&types.AuditSubject{Type: "session", SessionID: id, ContractID: sess.ContractID},
		map[string]interface{}{
			"final_status": finalStatus,
			"reason":       req.Reason,
			"result_id":    req.ResultID,
		},
		audit.SuccessOutcome(),
	)

	updated, _ := h.store.GetSession(id)
	writeJSON(w, http.StatusOK, updated)
}

// ──────────────────────────────────────────────────────────────
// Results
// ──────────────────────────────────────────────────────────────

func (h *Handler) getResult(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")

	// Check the session exists.
	if _, err := h.store.GetSession(sessionID); err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}

	result, err := h.store.GetResult(sessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "result_not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) postResult(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")

	sess, err := h.store.GetSession(sessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}

	h.submitResult(w, r, sess)
}

func (h *Handler) submitResult(w http.ResponseWriter, r *http.Request, sess *types.Session) {
	if sess.Status != types.SessionActive && sess.Status != types.SessionCompleted {
		writeError(w, http.StatusConflict, "invalid_state",
			fmt.Sprintf("Session is '%s', cannot accept results", sess.Status))
		return
	}

	var result types.Result
	if err := decodeBody(r, &result); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	// Assign defaults.
	if result.ResultID == "" {
		result.ResultID = makeID(types.PrefixResult)
	}
	if result.Schema == "" {
		result.Schema = types.SchemaResult
	}
	if result.DSPVersion == "" {
		result.DSPVersion = types.DSPVersion
	}
	if result.SessionID == "" {
		result.SessionID = sess.SessionID
	}
	if result.ContractID == "" {
		result.ContractID = sess.ContractID
	}
	if result.ProducedAt == "" {
		result.ProducedAt = types.NowUTC()
	}

	// Validate against contract.
	contract, err := h.store.GetContract(sess.ContractID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "contract_not_found", err.Error())
		return
	}

	validation := enforceResultPolicy(contract, &result)

	// Store result regardless of validation outcome.
	if err := h.store.StoreResult(&result); err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}

	// Update session.
	newStatus := types.SessionCompleted
	if !validation.Valid {
		newStatus = types.SessionCompleted // Still mark completed, but with issues.
	}
	_ = h.store.UpdateSession(sess.SessionID, store.SessionUpdate{
		Status:      newStatus,
		CompletedAt: types.NowUTC(),
		ResultID:    result.ResultID,
	})

	// Emit audit events.
	h.emitEvent("result.delivered",
		audit.AgentActor(sess.AgentOrgID, sess.AgentID),
		&types.AuditSubject{
			Type:       "result",
			SessionID:  sess.SessionID,
			ContractID: sess.ContractID,
			ResultID:   result.ResultID,
		},
		map[string]interface{}{
			"valid":       validation.Valid,
			"issue_count": len(validation.Issues),
		},
		audit.SuccessOutcome(),
	)

	if validation.Valid {
		h.emitEvent("result.scan_passed",
			audit.GatewayActor(),
			&types.AuditSubject{Type: "result", ResultID: result.ResultID, SessionID: sess.SessionID},
			map[string]interface{}{"validation": "passed"},
			audit.SuccessOutcome(),
		)
	} else {
		for _, issue := range validation.Issues {
			h.emitEvent("violation.detected",
				audit.GatewayActor(),
				&types.AuditSubject{Type: "result", ResultID: result.ResultID, SessionID: sess.SessionID},
				map[string]interface{}{
					"rule":        issue.Rule,
					"description": issue.Description,
					"severity":    issue.Severity,
				},
				audit.FailureOutcome("contract_violation", issue.Description),
			)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "accepted",
		"result_id":  result.ResultID,
		"validation": validation,
		"timestamp":  types.NowUTC(),
	})
}

// ──────────────────────────────────────────────────────────────
// Audit
// ──────────────────────────────────────────────────────────────

func (h *Handler) appendAuditEvent(w http.ResponseWriter, r *http.Request) {
	var event types.AuditEvent
	if err := decodeBody(r, &event); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	// Validate required fields.
	if event.EventType == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "event_type is required")
		return
	}

	// For externally submitted events, we wrap them through the chain
	// to maintain proper sequencing and hashing.
	chainedEvent, err := h.chain.NewEvent(
		event.EventType,
		event.Actor,
		event.Subject,
		event.Action,
		event.Outcome,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "chain_error", err.Error())
		return
	}

	// Preserve violation details if provided.
	if event.ViolationDetails != nil {
		chainedEvent.ViolationDetails = event.ViolationDetails
	}

	if err := h.store.AppendEvent(chainedEvent); err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, chainedEvent)
}

func (h *Handler) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	opts := store.EventListOptions{
		Limit:      parseIntParam(r, "limit", 100),
		Offset:     parseIntParam(r, "offset", 0),
		EventType:  r.URL.Query().Get("event_type"),
		SessionID:  r.URL.Query().Get("session_id"),
		ContractID: r.URL.Query().Get("contract_id"),
		Since:      r.URL.Query().Get("since"),
	}

	events, total, err := h.store.GetEvents(opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": events,
		"total": total,
	})
}

// ──────────────────────────────────────────────────────────────
// Storage
// ──────────────────────────────────────────────────────────────

func (h *Handler) grantAccess(w http.ResponseWriter, r *http.Request) {
	var req types.GrantAccessRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}

	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "session_id is required")
		return
	}

	// Verify session.
	sess, err := h.store.GetSession(req.SessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}

	if sess.Status != types.SessionActive {
		writeError(w, http.StatusConflict, "session_not_active",
			fmt.Sprintf("Session is '%s', must be 'active' for access grant", sess.Status))
		return
	}

	// Verify contract.
	contract, err := h.store.GetContract(sess.ContractID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "contract_not_found", err.Error())
		return
	}

	// Check requested operations are permitted by contract.
	allowedOps := make(map[string]bool)
	for _, op := range contract.Permissions.Operations {
		allowedOps[op] = true
	}
	for _, op := range req.Operations {
		if !allowedOps[op] {
			writeError(w, http.StatusForbidden, "operation_not_permitted",
				fmt.Sprintf("Operation '%s' not permitted by contract", op))

			h.emitEvent("access.denied",
				audit.GatewayActor(),
				&types.AuditSubject{Type: "session", SessionID: req.SessionID},
				map[string]interface{}{
					"denied_operation": op,
					"contract_id":     sess.ContractID,
				},
				audit.DeniedOutcome(fmt.Sprintf("Operation '%s' not in contract permissions", op)),
			)
			return
		}
	}

	// Verify each requested document exists via the storage adapter.
	ctx := r.Context()
	for _, docID := range req.DocumentIDs {
		_, err := h.storage.VerifyDocument(ctx, docID)
		if err != nil {
			writeError(w, http.StatusNotFound, "document_not_found",
				fmt.Sprintf("Document '%s' not found in storage backend: %v", docID, err))

			h.emitEvent("access.denied",
				audit.GatewayActor(),
				&types.AuditSubject{Type: "session", SessionID: req.SessionID, DocumentIDs: []string{docID}},
				map[string]interface{}{
					"reason":      "document_not_found",
					"document_id": docID,
					"error":       err.Error(),
				},
				audit.DeniedOutcome(fmt.Sprintf("Document '%s' not found in storage", docID)),
			)
			return
		}
	}

	// Issue scoped token.
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 3600
	}

	// Generate presigned URLs for each document via the storage adapter.
	presignedURLs := make(map[string]string, len(req.DocumentIDs))
	for _, docID := range req.DocumentIDs {
		presignedURL, err := h.storage.GeneratePresignedURL(ctx, docID, ttl)
		if err != nil {
			h.log.Warn("failed to generate presigned URL",
				"document_id", docID,
				"error", err,
			)
			// Non-fatal: include an empty URL. The token is still valid
			// for protocol-level access; the agent can fall back to
			// ReadDocument via the storage adapter's token path.
			presignedURL = ""
		}
		if presignedURL != "" {
			presignedURLs[docID] = presignedURL
		}
	}

	token := &types.ScopedToken{
		Token:     fmt.Sprintf("dsp-tok-%s", hex.EncodeToString(uuid.New().NodeID())),
		ExpiresAt: types.FutureUTC(time.Duration(ttl) * time.Second),
		Scope: types.TokenScope{
			DocumentIDs: req.DocumentIDs,
			Operations:  req.Operations,
		},
	}

	h.emitEvent("access.granted",
		audit.GatewayActor(),
		&types.AuditSubject{
			Type:        "session",
			SessionID:   req.SessionID,
			ContractID:  sess.ContractID,
			DocumentIDs: req.DocumentIDs,
		},
		map[string]interface{}{
			"operations":     req.Operations,
			"document_count": len(req.DocumentIDs),
			"ttl_seconds":    ttl,
			"presigned_urls": len(presignedURLs) > 0,
		},
		audit.SuccessOutcome(),
	)

	resp := types.GrantAccessResponse{
		Token:         token,
		PresignedURLs: presignedURLs,
	}
	writeJSON(w, http.StatusOK, resp)
}

// ──────────────────────────────────────────────────────────────
// Well-known configuration
// ──────────────────────────────────────────────────────────────

func (h *Handler) getConfiguration(w http.ResponseWriter, r *http.Request) {
	config := types.DSPConfiguration{
		DSPVersion: types.DSPVersion,
		GatewayID:  "dsp-gateway-reference-go",
		Endpoints: types.Endpoints{
			Manifests: "/v0.1/manifests",
			Contracts: "/v0.1/contracts",
			Sessions:  "/v0.1/sessions",
			Audit:     "/v0.1/audit",
			Storage:   "/v0.1/storage",
		},
		SupportedEnclaveTypes: []string{"sgx", "sev-snp", "tdx", "nitro", "cca", "sandbox"},
		StorageAdapters:       []string{"memory", "s3"},
		Features: []string{
			"merkle_audit_chain",
			"contract_enforcement",
			"privacy_budget_tracking",
			"result_scanning_validation",
			"sub_agent_chain_validation",
			"numeric_precision_enforcement",
		},
	}
	writeJSON(w, http.StatusOK, config)
}

// ──────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────

func parseListOptions(r *http.Request) store.ListOptions {
	return store.ListOptions{
		Limit:      parseIntParam(r, "limit", 100),
		Offset:     parseIntParam(r, "offset", 0),
		Status:     r.URL.Query().Get("status"),
		OwnerOrgID: r.URL.Query().Get("owner_org_id"),
	}
}

func parseIntParam(r *http.Request, name string, defaultVal int) int {
	s := r.URL.Query().Get(name)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

func isValidStatusTransition(from, to string) bool {
	transitions := map[string][]string{
		"active":    {"suspended", "revoked", "expired"},
		"suspended": {"active", "revoked"},
		"revoked":   {},
		"expired":   {},
	}
	allowed, ok := transitions[from]
	if !ok {
		return false
	}
	for _, a := range allowed {
		if a == to {
			return true
		}
	}
	return false
}

func computeSummary(docs []types.DocumentEntry) *types.ManifestSummary {
	s := &types.ManifestSummary{
		TotalDocuments:    len(docs),
		Classifications:  make(map[string]int),
		SensitivityLevels: make(map[string]int),
		Formats:          make(map[string]int),
		Languages:        make(map[string]int),
	}
	for _, d := range docs {
		s.TotalSizeBytes += d.SizeBytes
		s.Classifications[d.Classification]++
		s.SensitivityLevels[d.Sensitivity]++
		s.Formats[d.Format]++
		if d.Language != "" {
			s.Languages[d.Language]++
		}
	}
	return s
}
