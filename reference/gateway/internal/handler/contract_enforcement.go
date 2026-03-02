package handler

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/dssp-protocol/gateway/internal/types"
)

// ContractViolation describes a single contract rule violation.
type ContractViolation struct {
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // warning, error, critical
}

// validateSessionRequest checks whether a new session is permitted under the
// given contract. It returns a list of violations (empty = allowed).
func validateSessionRequest(
	contract *types.Contract,
	req *types.CreateSessionRequest,
	activeSessions int,
) []ContractViolation {
	var violations []ContractViolation

	if contract.Status != "active" {
		violations = append(violations, ContractViolation{
			Rule:        "contract_status",
			Description: fmt.Sprintf("Contract is '%s', must be 'active'", contract.Status),
			Severity:    "critical",
		})
		return violations // No point checking further.
	}

	if contract.Permissions.ValidUntil != "" {
		expiry, err := time.Parse(time.RFC3339, contract.Permissions.ValidUntil)
		if err == nil && time.Now().UTC().After(expiry) {
			violations = append(violations, ContractViolation{
				Rule:        "contract_expired",
				Description: fmt.Sprintf("Contract expired at %s", contract.Permissions.ValidUntil),
				Severity:    "critical",
			})
		}
	}

	if contract.Permissions.ValidFrom != "" {
		from, err := time.Parse(time.RFC3339, contract.Permissions.ValidFrom)
		if err == nil && time.Now().UTC().Before(from) {
			violations = append(violations, ContractViolation{
				Rule:        "contract_not_yet_valid",
				Description: fmt.Sprintf("Contract not valid until %s", contract.Permissions.ValidFrom),
				Severity:    "critical",
			})
		}
	}

	maxConcurrent := contract.Permissions.MaxConcurrentSessions
	if maxConcurrent <= 0 {
		maxConcurrent = 1 // default
	}
	if activeSessions >= maxConcurrent {
		violations = append(violations, ContractViolation{
			Rule:        "max_concurrent_sessions",
			Description: fmt.Sprintf("Concurrent session limit reached (%d/%d)", activeSessions, maxConcurrent),
			Severity:    "error",
		})
	}

	if req.Attestation != nil && req.Attestation.EnclaveType != "" {
		allowed := false
		for _, t := range contract.AttestationRequirements.EnclaveTypes {
			if t == req.Attestation.EnclaveType {
				allowed = true
				break
			}
		}
		if !allowed {
			violations = append(violations, ContractViolation{
				Rule: "enclave_type",
				Description: fmt.Sprintf(
					"Enclave type '%s' not in allowed list %v",
					req.Attestation.EnclaveType,
					contract.AttestationRequirements.EnclaveTypes,
				),
				Severity: "critical",
			})
		}
	}

	if contract.Consumer.AgentHash != nil && req.Attestation != nil && req.Attestation.AgentHash != nil {
		if contract.Consumer.AgentHash.Value != req.Attestation.AgentHash.Value {
			violations = append(violations, ContractViolation{
				Rule: "agent_hash_mismatch",
				Description: fmt.Sprintf(
					"Agent hash %s does not match contract requirement %s",
					req.Attestation.AgentHash.Value,
					contract.Consumer.AgentHash.Value,
				),
				Severity: "critical",
			})
		}
	}

	if contract.Consumer.AgentID != "" && req.AgentID != "" {
		if contract.Consumer.AgentID != req.AgentID {
			violations = append(violations, ContractViolation{
				Rule:        "agent_id_mismatch",
				Description: fmt.Sprintf("Agent '%s' not permitted; contract requires '%s'", req.AgentID, contract.Consumer.AgentID),
				Severity:    "error",
			})
		}
	}

	return violations
}

// validateHeartbeat checks an incoming heartbeat against session and contract rules.
func validateHeartbeat(
	session *types.Session,
	contract *types.Contract,
	req *types.HeartbeatRequest,
) []ContractViolation {
	var violations []ContractViolation

	if session.Status != types.SessionActive {
		violations = append(violations, ContractViolation{
			Rule:        "session_not_active",
			Description: fmt.Sprintf("Session is '%s', heartbeat only accepted for active sessions", session.Status),
			Severity:    "error",
		})
		return violations
	}

	if session.ExpiresAt != "" {
		expiry, err := time.Parse(time.RFC3339, session.ExpiresAt)
		if err == nil && time.Now().UTC().After(expiry) {
			violations = append(violations, ContractViolation{
				Rule:        "session_expired",
				Description: "Session has expired",
				Severity:    "critical",
			})
		}
	}

	// Verify attestation freshness if required.
	if contract.AttestationRequirements.RuntimeVerification != nil {
		rv := contract.AttestationRequirements.RuntimeVerification
		freshness := contract.AttestationRequirements.AttestationFreshness
		if freshness <= 0 {
			freshness = 300 // default 5 minutes
		}

		if req.Attestation != nil && req.Attestation.Timestamp != "" {
			attTime, err := time.Parse(time.RFC3339, req.Attestation.Timestamp)
			if err == nil {
				age := time.Since(attTime).Seconds()
				if int(age) > freshness {
					violations = append(violations, ContractViolation{
						Rule: "attestation_stale",
						Description: fmt.Sprintf(
							"Attestation is %ds old, max freshness is %ds",
							int(age), freshness,
						),
						Severity: "error",
					})
				}
			}
		} else if rv.PeriodicHeartbeatSecs > 0 {
			violations = append(violations, ContractViolation{
				Rule:        "attestation_missing",
				Description: "Heartbeat must include attestation proof",
				Severity:    "warning",
			})
		}
	}

	return violations
}

// ResultValidation contains the outcome of result policy enforcement.
type ResultValidation struct {
	Valid    bool                `json:"valid"`
	Issues   []ContractViolation `json:"issues"`
	Warnings []ContractViolation `json:"warnings"`
}

// enforceResultPolicy validates a result against the contract's restrictions.
func enforceResultPolicy(contract *types.Contract, result *types.Result) *ResultValidation {
	rv := &ResultValidation{Valid: true}

	restrictions := contract.Restrictions

	if result.ContractID != contract.ContractID {
		rv.addIssue("contract_id_mismatch", "Result contract_id does not match session contract", "critical")
	}

	checkNetworkPolicy(rv, restrictions.NetworkPolicy, result.Attestation.Claims)

	checkResultScanning(rv, restrictions.ResultScanning, result.ResultScan)

	rawAllowed := false
	if restrictions.ResultPolicy.RawContentAllowed != nil {
		rawAllowed = *restrictions.ResultPolicy.RawContentAllowed
	}
	if result.PIIReport.RawContentIncluded && !rawAllowed {
		rv.addIssue("raw_content_violation", "Raw content included but not allowed by contract", "critical")
	}

	if result.PIIReport.ComplianceStatus == "violation_detected" {
		rv.addIssue("pii_compliance_violation", "PII compliance violation detected by agent", "critical")
	}

	if contract.AttestationRequirements.RuntimeVerification != nil {
		rtv := contract.AttestationRequirements.RuntimeVerification
		if rtv.EndOfSessionAttestation != nil && *rtv.EndOfSessionAttestation {
			if result.EndOfSessionAttestation == nil {
				rv.addWarning("eos_attestation_missing", "End-of-session attestation expected but not present")
			} else if !result.EndOfSessionAttestation.MeasurementMatchesStart {
				rv.addIssue("eos_measurement_mismatch",
					"End-of-session measurement does not match start -- possible tampering", "critical")
			}
		}
	}

	checkSubAgentPolicy(rv, contract, result.Attestation.Claims)

	if restrictions.ResultPolicy.NumericPrecisionPolicy != nil {
		checkNumericPrecision(rv, restrictions.ResultPolicy.NumericPrecisionPolicy, result.Extractions)
	}

	if restrictions.ResultPolicy.MaxResultSizeBytes > 0 {
		// This is typically enforced at the transport layer; we note it as a warning.
		rv.addWarning("max_result_size", fmt.Sprintf(
			"Max result size is %d bytes (transport-level enforcement)", restrictions.ResultPolicy.MaxResultSizeBytes))
	}

	return rv
}

func checkNetworkPolicy(rv *ResultValidation, policy types.NetworkPolicy, claims types.AttestationClaims) {
	if policy.Egress == "deny_all" && len(claims.NetworkDestinations) > 0 {
		rv.addIssue("unauthorized_network_egress",
			fmt.Sprintf("Network egress detected but policy is deny_all: %v", claims.NetworkDestinations),
			"critical")
		return
	}

	if policy.Egress == "allow_listed" {
		allowed := make(map[string]bool)
		for _, d := range policy.AllowedDestinations {
			key := fmt.Sprintf("%s:%d", d.Host, d.Port)
			allowed[key] = true
		}
		for _, dest := range claims.NetworkDestinations {
			if !allowed[dest] {
				rv.addIssue("unauthorized_network_destination",
					fmt.Sprintf("Unauthorized network destination: %s", dest), "critical")
			}
		}
	}
}

func checkResultScanning(rv *ResultValidation, scanConfig types.ResultScanning, scanReport types.ResultScanReport) {
	if scanConfig.Enabled && !scanReport.Performed {
		rv.addIssue("result_scanning_required", "Result scanning required but not performed", "critical")
		return
	}

	if !scanReport.Performed {
		return
	}

	if len(scanConfig.RequiredScanners) > 0 {
		actualScanners := make(map[string]bool)
		for _, raw := range scanReport.Verdicts {
			var v struct {
				ScannerType string `json:"scanner_type"`
			}
			if err := json.Unmarshal(raw, &v); err == nil && v.ScannerType != "" {
				actualScanners[v.ScannerType] = true
			}
		}
		for _, required := range scanConfig.RequiredScanners {
			if !actualScanners[required] {
				rv.addIssue("missing_required_scanner",
					fmt.Sprintf("Required scanner '%s' did not run", required), "error")
			}
		}
	}

	if scanReport.OverallPassed != nil && !*scanReport.OverallPassed {
		action := scanConfig.ScanFailureAction
		if action == "" {
			action = "block_result"
		}
		switch action {
		case "block_result":
			rv.addIssue("scan_failed_block", "Result scan failed and policy is block_result", "critical")
		case "flag_and_deliver":
			rv.addWarning("scan_failed_flagged", "Result scan failed but policy is flag_and_deliver")
		case "quarantine":
			rv.addWarning("scan_failed_quarantine", "Result scan failed; result quarantined for manual review")
		}
	}
}

func checkSubAgentPolicy(rv *ResultValidation, contract *types.Contract, claims types.AttestationClaims) {
	policy := contract.Consumer.SubAgentPolicy
	chain := claims.SubAgentChain

	if policy == nil || len(chain) == 0 {
		return
	}

	if policy.Allowed != nil && !*policy.Allowed && len(chain) > 0 {
		rv.addIssue("sub_agents_not_allowed",
			fmt.Sprintf("Sub-agents not allowed but chain has %d steps", len(chain)), "critical")
		return
	}

	if policy.MaxPipelineSteps > 0 && len(chain) > policy.MaxPipelineSteps {
		rv.addIssue("max_pipeline_steps_exceeded",
			fmt.Sprintf("Sub-agent chain has %d steps, max allowed is %d", len(chain), policy.MaxPipelineSteps),
			"error")
	}

	if policy.LLMSubAgentAllowed != nil && !*policy.LLMSubAgentAllowed {
		for _, step := range chain {
			if step.AgentType == "llm_freeform" {
				rv.addIssue("llm_sub_agent_not_allowed",
					fmt.Sprintf("LLM sub-agent at step %d not allowed by contract", step.StepIndex),
					"critical")
			}
		}
	}

	if len(policy.AllowedPurposes) > 0 {
		allowedPurposes := make(map[string]bool)
		for _, p := range policy.AllowedPurposes {
			allowedPurposes[p] = true
		}
		for _, step := range chain {
			if !allowedPurposes[step.Purpose] {
				rv.addIssue("sub_agent_purpose_not_allowed",
					fmt.Sprintf("Sub-agent purpose '%s' at step %d not in allowed list", step.Purpose, step.StepIndex),
					"error")
			}
		}
	}

	if policy.CrossEnclaveAllowed != nil && !*policy.CrossEnclaveAllowed {
		for _, step := range chain {
			if step.EnclaveShared != nil && !*step.EnclaveShared {
				rv.addIssue("cross_enclave_not_allowed",
					fmt.Sprintf("Cross-enclave sub-agent at step %d not allowed", step.StepIndex),
					"error")
			}
		}
	}
}

func checkNumericPrecision(
	rv *ResultValidation,
	policy *types.NumericPrecisionPolicy,
	extractions []types.DocumentExtraction,
) {
	maxDP := policy.MaxDecimalPlaces
	if maxDP == 0 && policy.MaxSignificantDigits == 0 {
		return // No numeric precision policy configured.
	}

	for i, raw := range extractions {
		// Decode the raw extraction JSON to access fields.
		var ext struct {
			Fields map[string]interface{} `json:"fields"`
		}
		if err := json.Unmarshal(raw, &ext); err != nil || ext.Fields == nil {
			continue
		}

		for key, val := range ext.Fields {
			f, ok := toFloat64(val)
			if !ok {
				continue
			}

			if maxDP > 0 {
				dp := decimalPlaces(f)
				if dp > maxDP {
					rv.addIssue("numeric_precision_exceeded",
						fmt.Sprintf("extraction[%d].fields.%s has %d decimal places (max %d)", i, key, dp, maxDP),
						"error")
				}
			}

			if policy.MaxSignificantDigits > 0 {
				sd := significantDigits(f)
				if sd > policy.MaxSignificantDigits {
					rv.addIssue("numeric_significant_digits_exceeded",
						fmt.Sprintf("extraction[%d].fields.%s has %d significant digits (max %d)",
							i, key, sd, policy.MaxSignificantDigits),
						"error")
				}
			}
		}
	}
}

// checkPrivacyBudget verifies that processing this session does not exceed the
// contract's privacy budget.
func checkPrivacyBudget(contract *types.Contract, currentConsumed float64) []ContractViolation {
	var violations []ContractViolation

	budget := contract.Restrictions.PrivacyBudget
	if budget == nil || budget.Epsilon == nil {
		return violations
	}

	// Simple epsilon check: each session consumes 1.0 epsilon by default.
	// In a real implementation, this would be based on the actual query sensitivity.
	sessionCost := 1.0
	if currentConsumed+sessionCost > *budget.Epsilon {
		violations = append(violations, ContractViolation{
			Rule: "privacy_budget_exceeded",
			Description: fmt.Sprintf(
				"Privacy budget would be exceeded: consumed=%.2f, cost=%.2f, limit=%.2f",
				currentConsumed, sessionCost, *budget.Epsilon,
			),
			Severity: "critical",
		})
	}

	return violations
}

func (rv *ResultValidation) addIssue(rule, description, severity string) {
	rv.Valid = false
	rv.Issues = append(rv.Issues, ContractViolation{
		Rule:        rule,
		Description: description,
		Severity:    severity,
	})
}

func (rv *ResultValidation) addWarning(rule, description string) {
	rv.Warnings = append(rv.Warnings, ContractViolation{
		Rule:        rule,
		Description: description,
		Severity:    "warning",
	})
}

// toFloat64 attempts to convert an interface{} value to float64.
func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	case string:
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

// decimalPlaces returns the number of decimal places in a float64.
func decimalPlaces(f float64) int {
	if f == math.Trunc(f) {
		return 0
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	parts := strings.Split(s, ".")
	if len(parts) != 2 {
		return 0
	}
	return len(parts[1])
}

// significantDigits returns an approximation of the number of significant digits.
func significantDigits(f float64) int {
	if f == 0 {
		return 1
	}
	s := strconv.FormatFloat(math.Abs(f), 'f', -1, 64)
	s = strings.TrimLeft(s, "0")
	s = strings.Replace(s, ".", "", 1)
	s = strings.TrimRight(s, "0")
	if s == "" {
		return 1
	}
	return len(s)
}
