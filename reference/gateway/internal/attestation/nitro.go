package attestation

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/dssp-protocol/gateway/internal/types"
)

// AWS Nitro Attestation document structure.
// The attestation document is a COSE_Sign1 structure (CBOR-encoded).
// For the reference implementation, we parse the JSON representation
// that the agent provides after decoding the COSE_Sign1 document.
//
// In production, this should use a CBOR/COSE library to parse the
// raw COSE_Sign1 bytes and verify the signature directly.

type NitroAttestationDoc struct {
	ModuleID    string            `json:"module_id"`
	Digest      string            `json:"digest"` // "SHA384"
	Timestamp   int64             `json:"timestamp"` // milliseconds since epoch
	PCRs        map[string]string `json:"pcrs"`
	Certificate string            `json:"certificate"` // base64 DER
	CABundle    []string          `json:"cabundle"`     // base64 DER certificates
	PublicKey   string            `json:"public_key,omitempty"`
	UserData    string            `json:"user_data,omitempty"`
	Nonce       string            `json:"nonce,omitempty"`
}

// SHA-256 fingerprint of the AWS Nitro Attestation Root CA.
// Source: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
const nitroRootCAFingerprint = "641a0321a3e244afe5388b35f24e18bc5ceb1a593adc119f8c8830b9e6018e14"

type NitroVerifier struct {
	log *slog.Logger

	// NitroRootCert is the AWS Nitro Attestation Root CA certificate.
	// If nil, certificate chain verification is skipped (with a warning).
	NitroRootCert *x509.Certificate
}

func (v *NitroVerifier) Verify(att *types.SessionAttestation, policy Policy) *VerificationResult {
	result := &VerificationResult{
		EnclaveType: att.EnclaveType,
		Measurement: att.Measurement,
	}

	freshnessOK, freshnessMsg := checkFreshness(att, policy.MaxFreshnessSeconds)
	result.FreshnessValid = freshnessOK
	result.Details = append(result.Details, freshnessMsg)
	if !freshnessOK {
		result.Errors = append(result.Errors, freshnessMsg)
	}

	hashOK, hashMsg := checkAgentHash(att, policy.ExpectedAgentHash)
	result.Details = append(result.Details, hashMsg)
	if !hashOK {
		result.Errors = append(result.Errors, hashMsg)
	}

	if att.RawQuote == "" {
		result.SignatureValid = false
		result.CertChainValid = false
		result.MeasurementMatches = v.checkMeasurement(att.Measurement, att.EnclaveType, policy)
		result.Verified = result.MeasurementMatches && freshnessOK && hashOK
		result.Details = append(result.Details,
			"no raw_quote provided - measurement accepted from claim without cryptographic proof",
			"WARNING: production deployments MUST provide the Nitro attestation document")
		return result
	}

	doc, err := v.parseAttestationDoc(att.RawQuote)
	if err != nil {
		result.Verified = false
		result.Errors = append(result.Errors,
			fmt.Sprintf("failed to parse Nitro attestation document: %v", err))
		return result
	}

	structErrors := v.validateDocStructure(doc, result)

	pcr0, hasPCR0 := doc.PCRs["PCR0"]
	if hasPCR0 {
		result.Measurement = pcr0
		result.Details = append(result.Details,
			fmt.Sprintf("PCR0 (enclave image): %s", truncate(pcr0, 16)))
	} else {
		result.Details = append(result.Details, "WARNING: PCR0 not found in attestation document")
	}

	for pcrName, pcrValue := range doc.PCRs {
		if pcrName != "PCR0" {
			result.Details = append(result.Details,
				fmt.Sprintf("%s: %s", pcrName, truncate(pcrValue, 16)))
		}
	}

	if att.Measurement != "" && hasPCR0 && att.Measurement != pcr0 {
		result.Details = append(result.Details,
			fmt.Sprintf("WARNING: claimed measurement %s differs from PCR0 %s",
				truncate(att.Measurement, 16), truncate(pcr0, 16)))
	}

	measurementToCheck := att.Measurement
	if hasPCR0 {
		measurementToCheck = pcr0
	}
	result.MeasurementMatches = v.checkMeasurement(measurementToCheck, att.EnclaveType, policy)
	if !result.MeasurementMatches {
		expected := policy.ExpectedMeasurements[att.EnclaveType]
		if expected != "" {
			result.Errors = append(result.Errors,
				fmt.Sprintf("PCR0 mismatch: got %s, expected %s",
					truncate(measurementToCheck, 16), truncate(expected, 16)))
		}
	}

	if doc.Timestamp > 0 {
		docTime := time.UnixMilli(doc.Timestamp)
		age := time.Since(docTime)
		result.Details = append(result.Details,
			fmt.Sprintf("attestation document timestamp: %s (age: %s)",
				docTime.UTC().Format(time.RFC3339), age.Round(time.Second)))

		if policy.MaxFreshnessSeconds > 0 {
			maxAge := time.Duration(policy.MaxFreshnessSeconds) * time.Second
			if age > maxAge {
				result.Errors = append(result.Errors,
					fmt.Sprintf("attestation document is %s old, max freshness is %s",
						age.Round(time.Second), maxAge))
				result.FreshnessValid = false
			}
		}
	}

	result.CertChainValid = v.verifyCertChain(doc, result)

	// Full COSE_Sign1 signature verification requires a CBOR/COSE library.
	// The reference implementation delegates to certificate chain validation.
	result.SignatureValid = result.CertChainValid
	if result.CertChainValid {
		result.Details = append(result.Details,
			"signature verification: delegated to certificate chain validation")
	} else {
		result.Details = append(result.Details,
			"NOTE: full COSE_Sign1 signature verification requires a CBOR/COSE library")
	}

	// Simulated Nitro has no real NSM, so relax crypto requirements.
	if att.EnclaveType == "nitro-simulated" {
		result.SignatureValid = true
		result.CertChainValid = true
		result.Verified = result.MeasurementMatches && freshnessOK && hashOK
		result.Details = append(result.Details,
			"nitro-simulated: crypto verification relaxed (no real NSM)")
		v.log.Info("Nitro attestation verification complete (simulated)",
			"verified", result.Verified,
			"measurement", truncate(measurementToCheck, 16),
		)
		return result
	}

	result.Verified = result.MeasurementMatches && freshnessOK && hashOK &&
		result.SignatureValid && result.CertChainValid && !structErrors

	v.log.Info("Nitro attestation verification complete",
		"verified", result.Verified,
		"pcr0", truncate(measurementToCheck, 16),
		"module_id", doc.ModuleID,
	)

	return result
}

func (v *NitroVerifier) parseAttestationDoc(rawQuote string) (*NitroAttestationDoc, error) {
	docBytes, err := base64.StdEncoding.DecodeString(rawQuote)
	if err != nil {
		docBytes, err = base64.URLEncoding.DecodeString(rawQuote)
		if err != nil {
			return nil, fmt.Errorf("failed to base64-decode attestation document: %w", err)
		}
	}

	// The reference agent sends a JSON-serialized attestation document.
	// In production, this would be a CBOR-encoded COSE_Sign1 structure
	// that should be parsed with a proper CBOR library.
	var doc NitroAttestationDoc
	if err := json.Unmarshal(docBytes, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse attestation document JSON: %w (note: production should use CBOR/COSE parsing)", err)
	}

	return &doc, nil
}

func (v *NitroVerifier) validateDocStructure(doc *NitroAttestationDoc, result *VerificationResult) bool {
	hasErrors := false

	if doc.ModuleID == "" {
		result.Errors = append(result.Errors, "attestation document missing module_id")
		hasErrors = true
	} else {
		result.Details = append(result.Details, fmt.Sprintf("module_id: %s", doc.ModuleID))
	}

	if doc.Digest != "SHA384" && doc.Digest != "" {
		result.Details = append(result.Details,
			fmt.Sprintf("WARNING: unexpected digest algorithm: %s (expected SHA384)", doc.Digest))
	}

	if len(doc.PCRs) == 0 {
		result.Errors = append(result.Errors, "attestation document contains no PCR values")
		hasErrors = true
	}

	if _, ok := doc.PCRs["PCR0"]; !ok {
		result.Errors = append(result.Errors, "PCR0 (enclave image hash) missing from attestation")
		hasErrors = true
	}

	if doc.Timestamp <= 0 {
		result.Details = append(result.Details, "WARNING: no timestamp in attestation document")
	}

	if doc.Certificate == "" {
		result.Details = append(result.Details, "WARNING: no certificate in attestation document")
	}

	return hasErrors
}

func (v *NitroVerifier) checkMeasurement(measurement, enclaveType string, policy Policy) bool {
	expected, ok := policy.ExpectedMeasurements[enclaveType]
	if !ok || expected == "" {
		v.log.Warn("no expected measurement configured for enclave type - accepting any",
			"enclave_type", enclaveType,
			"measurement", truncate(measurement, 16))
		return true
	}
	return measurement == expected
}

func (v *NitroVerifier) verifyCertChain(doc *NitroAttestationDoc, result *VerificationResult) bool {
	if doc.Certificate == "" && len(doc.CABundle) == 0 {
		result.Details = append(result.Details,
			"no certificate or CA bundle in attestation document")
		return false
	}

	var endEntityCert *x509.Certificate
	if doc.Certificate != "" {
		certDER, err := base64.StdEncoding.DecodeString(doc.Certificate)
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("failed to decode end-entity certificate: %v", err))
			return false
		}

		endEntityCert, err = x509.ParseCertificate(certDER)
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("failed to parse end-entity certificate: %v", err))
			// Not necessarily fatal for simulated certs.
		} else {
			result.Details = append(result.Details,
				fmt.Sprintf("end-entity cert subject: %s", endEntityCert.Subject.String()))
		}
	}

	intermediates := x509.NewCertPool()
	parsedCACount := 0
	for i, caB64 := range doc.CABundle {
		caDER, err := base64.StdEncoding.DecodeString(caB64)
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("cabundle[%d]: failed to decode: %v", i, err))
			continue
		}

		caCert, err := x509.ParseCertificate(caDER)
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("cabundle[%d]: failed to parse: %v", i, err))
			continue
		}

		intermediates.AddCert(caCert)
		parsedCACount++
	}

	result.Details = append(result.Details,
		fmt.Sprintf("parsed %d CA certificate(s) from bundle", parsedCACount))

	if endEntityCert != nil && v.NitroRootCert != nil {
		roots := x509.NewCertPool()
		roots.AddCert(v.NitroRootCert)

		_, err := endEntityCert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		})
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("certificate chain verification failed: %v", err))
			return false
		}

		result.Details = append(result.Details,
			"certificate chain verified against AWS Nitro Root CA")
		return true
	}

	if v.NitroRootCert == nil {
		result.Details = append(result.Details,
			"AWS Nitro Root CA not configured - certificate chain structure checked but not cryptographically verified",
			"configure DSSP_NITRO_ROOT_CA_PATH for full chain verification")
	}

	return endEntityCert != nil || parsedCACount > 0
}
