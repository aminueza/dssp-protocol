// Package attestation implements enclave attestation verification for the DSSP gateway.
//
// It provides a pluggable Verifier interface with implementations for:
//   - Simulated:  Accepts any attestation (development/CI only)
//   - SGX DCAP:   Parses and verifies Intel SGX Data Center Attestation Primitives quotes
//   - Nitro:      Parses and verifies AWS Nitro Enclave attestation documents
//
// The verifier is called during session creation to validate that the agent is
// running inside a genuine enclave with the expected measurement.
package attestation

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/dssp-protocol/gateway/internal/types"
)

// Mode selects which attestation verification backend to use.
type Mode string

const (
	ModeSimulated Mode = "simulated" // Accept any attestation (dev/CI)
	ModeVerify    Mode = "verify"    // Parse and verify real attestation quotes
)

type VerificationResult struct {
	Verified           bool     `json:"verified"`
	EnclaveType        string   `json:"enclave_type"`
	Measurement        string   `json:"measurement"`
	MeasurementMatches bool     `json:"measurement_matches"`
	SignatureValid     bool     `json:"signature_valid"`
	CertChainValid     bool     `json:"cert_chain_valid"`
	FreshnessValid     bool     `json:"freshness_valid"`
	Details            []string `json:"details"`
	Errors             []string `json:"errors,omitempty"`
}

// Policy defines the attestation requirements extracted from a contract.
type Policy struct {
	AllowedEnclaveTypes  []string

	// Maps enclave type to expected measurement hash.
	// If empty, any measurement is accepted (but logged as a warning).
	ExpectedMeasurements map[string]string

	ExpectedAgentHash    *types.HashDigest

	// Zero means no freshness check.
	MaxFreshnessSeconds  int
}

func PolicyFromContract(c *types.Contract) Policy {
	p := Policy{
		AllowedEnclaveTypes:  c.AttestationRequirements.EnclaveTypes,
		MaxFreshnessSeconds:  c.AttestationRequirements.AttestationFreshness,
		ExpectedMeasurements: make(map[string]string),
	}

	if c.Consumer.AgentHash != nil {
		p.ExpectedAgentHash = c.Consumer.AgentHash
	}

	return p
}

type Verifier interface {
	Verify(att *types.SessionAttestation, policy Policy) *VerificationResult
	Mode() Mode
}

func New(mode Mode, logger *slog.Logger) Verifier {
	switch mode {
	case ModeVerify:
		return &RealVerifier{
			sgx:   &SGXVerifier{log: logger},
			nitro: &NitroVerifier{log: logger},
			log:   logger,
		}
	default:
		return &SimulatedVerifier{log: logger}
	}
}

// SimulatedVerifier accepts any attestation without cryptographic verification.
// For development and CI only.
type SimulatedVerifier struct {
	log *slog.Logger
}

func (v *SimulatedVerifier) Mode() Mode { return ModeSimulated }

func (v *SimulatedVerifier) Verify(att *types.SessionAttestation, policy Policy) *VerificationResult {
	result := &VerificationResult{
		Verified:           true,
		EnclaveType:        att.EnclaveType,
		Measurement:        att.Measurement,
		MeasurementMatches: true,
		SignatureValid:     true,
		CertChainValid:     true,
		FreshnessValid:     true,
		Details: []string{
			"SIMULATED: attestation accepted without cryptographic verification",
			"WARNING: this mode provides NO security guarantees",
		},
	}

	// Even in simulated mode, enforce the contract's allowed enclave type list.
	if len(policy.AllowedEnclaveTypes) > 0 {
		allowed := false
		for _, t := range policy.AllowedEnclaveTypes {
			if t == att.EnclaveType || (t == "sandbox" && att.EnclaveType == "sandbox") {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Verified = false
			result.Errors = append(result.Errors, fmt.Sprintf(
				"enclave type '%s' not in allowed list %v", att.EnclaveType, policy.AllowedEnclaveTypes))
		}
	}

	v.log.Warn("simulated attestation verification - no security guarantees",
		"enclave_type", att.EnclaveType,
		"measurement", truncate(att.Measurement, 16),
	)

	return result
}

// RealVerifier dispatches to the appropriate backend based on enclave type.
type RealVerifier struct {
	sgx   *SGXVerifier
	nitro *NitroVerifier
	log   *slog.Logger
}

func (v *RealVerifier) Mode() Mode { return ModeVerify }

func (v *RealVerifier) Verify(att *types.SessionAttestation, policy Policy) *VerificationResult {
	if len(policy.AllowedEnclaveTypes) > 0 {
		allowed := false
		for _, t := range policy.AllowedEnclaveTypes {
			if t == att.EnclaveType {
				allowed = true
				break
			}
		}
		if !allowed {
			return &VerificationResult{
				Verified:    false,
				EnclaveType: att.EnclaveType,
				Errors: []string{fmt.Sprintf(
					"enclave type '%s' not in allowed list %v",
					att.EnclaveType, policy.AllowedEnclaveTypes)},
			}
		}
	}

	switch att.EnclaveType {
	case "sgx", "sgx-simulated":
		return v.sgx.Verify(att, policy)
	case "nitro", "nitro-simulated":
		return v.nitro.Verify(att, policy)
	case "sandbox":
		return v.verifySandbox(att, policy)
	default:
		return &VerificationResult{
			Verified:    false,
			EnclaveType: att.EnclaveType,
			Errors:      []string{fmt.Sprintf("unsupported enclave type: %s", att.EnclaveType)},
		}
	}
}

func (v *RealVerifier) verifySandbox(att *types.SessionAttestation, policy Policy) *VerificationResult {
	result := &VerificationResult{
		EnclaveType:    "sandbox",
		Measurement:    att.Measurement,
		SignatureValid: false,
		CertChainValid: false,
		FreshnessValid: true,
		Details: []string{
			"sandbox enclave provides no hardware-backed security",
			"acceptable for development and testing only",
		},
	}

	// Sandbox must be explicitly listed in the contract's allowed types.
	allowed := false
	for _, t := range policy.AllowedEnclaveTypes {
		if t == "sandbox" {
			allowed = true
			break
		}
	}
	result.Verified = allowed
	result.MeasurementMatches = true

	if !allowed {
		result.Errors = append(result.Errors, "sandbox enclave not permitted by contract")
	}

	return result
}

func checkFreshness(att *types.SessionAttestation, maxFreshnessSecs int) (bool, string) {
	if maxFreshnessSecs <= 0 {
		return true, "freshness check skipped (no max configured)"
	}

	if att.Timestamp == "" {
		return false, "attestation timestamp missing"
	}

	attTime, err := time.Parse(time.RFC3339, att.Timestamp)
	if err != nil {
		return false, fmt.Sprintf("invalid attestation timestamp: %v", err)
	}

	age := time.Since(attTime)
	maxAge := time.Duration(maxFreshnessSecs) * time.Second

	if age > maxAge {
		return false, fmt.Sprintf("attestation is %s old, max freshness is %s",
			age.Round(time.Second), maxAge)
	}

	if age < -30*time.Second {
		return false, fmt.Sprintf("attestation timestamp is %s in the future", (-age).Round(time.Second))
	}

	return true, fmt.Sprintf("attestation age %s within %s window", age.Round(time.Second), maxAge)
}

func checkAgentHash(att *types.SessionAttestation, expected *types.HashDigest) (bool, string) {
	if expected == nil {
		return true, "agent hash check skipped (no expected hash in contract)"
	}

	if att.AgentHash == nil {
		return false, "agent hash missing from attestation but required by contract"
	}

	if att.AgentHash.Value != expected.Value {
		return false, fmt.Sprintf("agent hash mismatch: got %s, expected %s",
			truncate(att.AgentHash.Value, 16), truncate(expected.Value, 16))
	}

	if att.AgentHash.Algorithm != expected.Algorithm {
		return false, fmt.Sprintf("agent hash algorithm mismatch: got %s, expected %s",
			att.AgentHash.Algorithm, expected.Algorithm)
	}

	return true, "agent hash matches contract"
}

func decodeRawQuote(raw string) ([]byte, error) {
	if raw == "" {
		return nil, fmt.Errorf("no raw quote provided")
	}
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// Fallback: try URL-safe base64.
		data, err = base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("failed to decode raw quote: %w", err)
		}
	}
	return data, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
