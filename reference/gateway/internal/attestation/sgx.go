package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"

	"github.com/dssp-protocol/gateway/internal/types"
)

// SGX DCAP Quote v3 structure offsets and sizes.
// Reference: Intel SGX DCAP Developer Guide, "Quote Format" section.
const (
	sgxQuoteMinSize    = 436 // header (48) + report body (384) + auth data length (4)
	sgxHeaderSize      = 48
	sgxReportBodySize  = 384

	// Header field offsets
	sgxHeaderVersion       = 0  // uint16
	sgxHeaderAttKeyType    = 2  // uint16
	sgxHeaderReserved      = 4  // uint32
	sgxHeaderQESVN         = 8  // uint16
	sgxHeaderPCESVN        = 10 // uint16
	sgxHeaderQEVendorID    = 12 // 16 bytes
	sgxHeaderUserData      = 28 // 20 bytes

	// Report body field offsets (relative to report body start at 48)
	sgxReportCPUSVN        = 0   // 16 bytes
	sgxReportMiscSelect    = 16  // uint32
	sgxReportReserved1     = 20  // 12 bytes
	sgxReportISVExtProdID  = 32  // 16 bytes
	sgxReportAttributes    = 48  // 16 bytes (flags u64 + xfrm u64)
	sgxReportMRENCLAVE     = 64  // 32 bytes
	sgxReportReserved2     = 96  // 32 bytes
	sgxReportMRSIGNER      = 128 // 32 bytes
	sgxReportReserved3     = 160 // 96 bytes
	sgxReportISVProdID     = 256 // uint16
	sgxReportISVSVN        = 258 // uint16
	sgxReportReserved4     = 260 // 60 bytes
	sgxReportReportData    = 320 // 64 bytes
)

// Intel's well-known QE Vendor ID for DCAP.
var intelQEVendorID = [16]byte{
	0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9,
	0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
}

// SGXQuote represents a parsed SGX DCAP v3 quote.
type SGXQuote struct {
	Version     uint16
	AttKeyType  uint16 // 2 = ECDSA-256-with-P-256, 3 = ECDSA-384-with-P-384
	QESVN       uint16
	PCESVN      uint16
	QEVendorID  [16]byte
	UserData    [20]byte

	CPUSVN       [16]byte
	MiscSelect   uint32
	Attributes   [16]byte // flags (8 bytes) + xfrm (8 bytes)
	MRENCLAVE    [32]byte
	MRSIGNER     [32]byte
	ISVProdID    uint16
	ISVSVN       uint16
	ReportData   [64]byte

	AuthDataSize uint32
	AuthData     []byte

	SignedData []byte // header + report body (for signature verification)
}

func ParseSGXQuote(data []byte) (*SGXQuote, error) {
	if len(data) < sgxQuoteMinSize {
		return nil, fmt.Errorf("SGX quote too short: %d bytes (minimum %d)", len(data), sgxQuoteMinSize)
	}

	q := &SGXQuote{}

	q.Version = binary.LittleEndian.Uint16(data[sgxHeaderVersion:])
	q.AttKeyType = binary.LittleEndian.Uint16(data[sgxHeaderAttKeyType:])
	q.QESVN = binary.LittleEndian.Uint16(data[sgxHeaderQESVN:])
	q.PCESVN = binary.LittleEndian.Uint16(data[sgxHeaderPCESVN:])
	copy(q.QEVendorID[:], data[sgxHeaderQEVendorID:sgxHeaderQEVendorID+16])
	copy(q.UserData[:], data[sgxHeaderUserData:sgxHeaderUserData+20])

	rb := data[sgxHeaderSize:]
	copy(q.CPUSVN[:], rb[sgxReportCPUSVN:sgxReportCPUSVN+16])
	q.MiscSelect = binary.LittleEndian.Uint32(rb[sgxReportMiscSelect:])
	copy(q.Attributes[:], rb[sgxReportAttributes:sgxReportAttributes+16])
	copy(q.MRENCLAVE[:], rb[sgxReportMRENCLAVE:sgxReportMRENCLAVE+32])
	copy(q.MRSIGNER[:], rb[sgxReportMRSIGNER:sgxReportMRSIGNER+32])
	q.ISVProdID = binary.LittleEndian.Uint16(rb[sgxReportISVProdID:])
	q.ISVSVN = binary.LittleEndian.Uint16(rb[sgxReportISVSVN:])
	copy(q.ReportData[:], rb[sgxReportReportData:sgxReportReportData+64])

	authOffset := sgxHeaderSize + sgxReportBodySize
	if len(data) >= authOffset+4 {
		q.AuthDataSize = binary.LittleEndian.Uint32(data[authOffset:])
		authStart := authOffset + 4
		authEnd := authStart + int(q.AuthDataSize)
		if authEnd <= len(data) {
			q.AuthData = data[authStart:authEnd]
		}
	}

	q.SignedData = data[:sgxHeaderSize+sgxReportBodySize]

	return q, nil
}

func (q *SGXQuote) MRENCLAVEHex() string {
	return hex.EncodeToString(q.MRENCLAVE[:])
}

func (q *SGXQuote) MRSIGNERHex() string {
	return hex.EncodeToString(q.MRSIGNER[:])
}

func (q *SGXQuote) IsIntelQE() bool {
	return q.QEVendorID == intelQEVendorID
}

type SGXVerifier struct {
	log *slog.Logger

	// IntelRootCert is the Intel SGX Root CA certificate for verifying the
	// PCK certificate chain. If nil, certificate chain verification is skipped
	// (with a warning logged).
	IntelRootCert *x509.Certificate
}

func (v *SGXVerifier) Verify(att *types.SessionAttestation, policy Policy) *VerificationResult {
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
		// No raw quote: accept the claimed measurement but mark
		// signature and cert chain as unverified.
		result.SignatureValid = false
		result.CertChainValid = false
		result.MeasurementMatches = v.checkMeasurement(att.Measurement, att.EnclaveType, policy)
		result.Verified = result.MeasurementMatches && freshnessOK && hashOK
		result.Details = append(result.Details,
			"no raw_quote provided - measurement accepted from claim without cryptographic proof",
			"WARNING: production deployments SHOULD require raw_quote for full verification")
		return result
	}

	quoteBytes, err := decodeRawQuote(att.RawQuote)
	if err != nil {
		result.Verified = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to decode SGX quote: %v", err))
		return result
	}

	quote, err := ParseSGXQuote(quoteBytes)
	if err != nil {
		result.Verified = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to parse SGX quote: %v", err))
		return result
	}

	structErrors := v.validateQuoteStructure(quote)
	result.Details = append(result.Details, structErrors.details...)
	if len(structErrors.errors) > 0 {
		result.Errors = append(result.Errors, structErrors.errors...)
	}

	quoteMRENCLAVE := quote.MRENCLAVEHex()
	result.Measurement = quoteMRENCLAVE
	result.Details = append(result.Details,
		fmt.Sprintf("MRENCLAVE from quote: %s", truncate(quoteMRENCLAVE, 16)),
		fmt.Sprintf("MRSIGNER from quote: %s", truncate(quote.MRSIGNERHex(), 16)),
		fmt.Sprintf("ISV ProdID: %d, ISV SVN: %d", quote.ISVProdID, quote.ISVSVN),
	)

	// The claimed measurement must agree with what the quote actually contains.
	if att.Measurement != "" && att.Measurement != quoteMRENCLAVE {
		result.Details = append(result.Details,
			fmt.Sprintf("WARNING: claimed measurement %s differs from quote MRENCLAVE %s",
				truncate(att.Measurement, 16), truncate(quoteMRENCLAVE, 16)))
		// Use the quote's measurement as the authoritative value.
	}

	result.MeasurementMatches = v.checkMeasurement(quoteMRENCLAVE, att.EnclaveType, policy)
	if !result.MeasurementMatches {
		expected := policy.ExpectedMeasurements[att.EnclaveType]
		if expected != "" {
			result.Errors = append(result.Errors,
				fmt.Sprintf("MRENCLAVE mismatch: got %s, expected %s",
					truncate(quoteMRENCLAVE, 16), truncate(expected, 16)))
		}
	}

	result.SignatureValid = v.verifyQuoteSignature(quote, result)
	result.CertChainValid = v.verifyCertChain(att.PlatformCertificateChain, result)

	// Cert chain verification is only required when the Intel Root CA is configured.
	certChainOK := result.CertChainValid || v.IntelRootCert == nil
	result.Verified = result.MeasurementMatches && freshnessOK && hashOK &&
		result.SignatureValid && certChainOK &&
		len(structErrors.errors) == 0

	// Simulated SGX (gramine-direct) has no hardware QE, so relax crypto.
	if att.EnclaveType == "sgx-simulated" {
		result.SignatureValid = true
		result.CertChainValid = true
		result.Verified = result.MeasurementMatches && freshnessOK && hashOK
		result.Details = append(result.Details,
			"sgx-simulated: crypto verification relaxed (no hardware QE)")
	}

	v.log.Info("SGX attestation verification complete",
		"verified", result.Verified,
		"mrenclave", truncate(quoteMRENCLAVE, 16),
		"mrsigner", truncate(quote.MRSIGNERHex(), 16),
		"version", quote.Version,
		"is_intel_qe", quote.IsIntelQE(),
	)

	return result
}

type structValidation struct {
	details []string
	errors  []string
}

func (v *SGXVerifier) validateQuoteStructure(q *SGXQuote) structValidation {
	sv := structValidation{}

	if q.Version != 3 {
		sv.errors = append(sv.errors, fmt.Sprintf("unsupported quote version %d (expected 3)", q.Version))
	} else {
		sv.details = append(sv.details, "quote version: 3 (DCAP)")
	}

	switch q.AttKeyType {
	case 2:
		sv.details = append(sv.details, "attestation key type: ECDSA-256-with-P-256")
	case 3:
		sv.details = append(sv.details, "attestation key type: ECDSA-384-with-P-384")
	default:
		sv.errors = append(sv.errors, fmt.Sprintf("unsupported attestation key type %d", q.AttKeyType))
	}

	if q.IsIntelQE() {
		sv.details = append(sv.details, "QE Vendor ID: Intel (genuine)")
	} else {
		sv.details = append(sv.details, "QE Vendor ID: non-Intel (simulated or third-party)")
	}

	allZero := true
	for _, b := range q.MRENCLAVE {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		sv.errors = append(sv.errors, "MRENCLAVE is all zeros (invalid)")
	}

	return sv
}

func (v *SGXVerifier) checkMeasurement(measurement, enclaveType string, policy Policy) bool {
	expected, ok := policy.ExpectedMeasurements[enclaveType]
	if !ok || expected == "" {
		// No specific measurement required. Accept any but log warning.
		v.log.Warn("no expected measurement configured for enclave type - accepting any",
			"enclave_type", enclaveType,
			"measurement", truncate(measurement, 16))
		return true
	}
	return measurement == expected
}

func (v *SGXVerifier) verifyQuoteSignature(q *SGXQuote, result *VerificationResult) bool {
	if len(q.AuthData) < 64 {
		result.Details = append(result.Details,
			"insufficient auth data for ECDSA signature verification")
		return false
	}

	if q.AttKeyType != 2 {
		result.Details = append(result.Details,
			fmt.Sprintf("signature verification not implemented for key type %d", q.AttKeyType))
		return false
	}

	// Auth data layout for ECDSA-256: signature (64B) || public key (64B) || QE data.
	if len(q.AuthData) < 128 {
		result.Details = append(result.Details,
			"auth data too short for ECDSA-256 signature + public key")
		return false
	}

	sigR := new(big.Int).SetBytes(q.AuthData[0:32])
	sigS := new(big.Int).SetBytes(q.AuthData[32:64])

	pubX := new(big.Int).SetBytes(q.AuthData[64:96])
	pubY := new(big.Int).SetBytes(q.AuthData[96:128])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     pubX,
		Y:     pubY,
	}

	if !pubKey.Curve.IsOnCurve(pubX, pubY) {
		result.Details = append(result.Details, "attestation public key is not on P-256 curve")
		return false
	}

	hash := sha256.Sum256(q.SignedData)
	valid := ecdsa.Verify(pubKey, hash[:], sigR, sigS)
	if valid {
		result.Details = append(result.Details,
			"ECDSA-256 signature verified over header + report body")
	} else {
		result.Details = append(result.Details,
			"ECDSA-256 signature verification FAILED")
	}

	return valid
}

func (v *SGXVerifier) verifyCertChain(chain []string, result *VerificationResult) bool {
	if len(chain) == 0 {
		result.Details = append(result.Details,
			"no platform certificate chain provided - skipping cert verification")
		return false
	}

	var certs []*x509.Certificate
	for i, certStr := range chain {
		block, _ := pem.Decode([]byte(certStr))
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				result.Details = append(result.Details,
					fmt.Sprintf("cert[%d]: failed to parse PEM certificate: %v", i, err))
				continue
			}
			certs = append(certs, cert)
			continue
		}

		// Fallback: try DER.
		cert, err := x509.ParseCertificate([]byte(certStr))
		if err != nil {
			result.Details = append(result.Details,
				fmt.Sprintf("cert[%d]: failed to parse certificate (not PEM or DER)", i))
			continue
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		result.Details = append(result.Details,
			"no valid certificates found in the chain")
		return false
	}

	result.Details = append(result.Details,
		fmt.Sprintf("parsed %d certificate(s) from chain", len(certs)))

	if v.IntelRootCert != nil {
		roots := x509.NewCertPool()
		roots.AddCert(v.IntelRootCert)

		intermediates := x509.NewCertPool()
		for _, cert := range certs[1:] {
			intermediates.AddCert(cert)
		}

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		}

		if len(certs) > 0 {
			_, err := certs[0].Verify(opts)
			if err != nil {
				result.Details = append(result.Details,
					fmt.Sprintf("certificate chain verification failed: %v", err))
				return false
			}
			result.Details = append(result.Details,
				"certificate chain verified against Intel Root CA")
			return true
		}
	}

	result.Details = append(result.Details,
		"Intel Root CA not configured - certificate chain structure checked but not cryptographically verified",
		"configure DSSP_INTEL_ROOT_CA_PATH for full chain verification")
	return true // Structural check passed; full crypto verification was skipped.
}
