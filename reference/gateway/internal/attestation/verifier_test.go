package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/dssp-protocol/gateway/internal/types"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// ── Helper: build a valid simulated SGX DCAP v3 quote ───────

func buildTestSGXQuote(t *testing.T, mrenclave [32]byte, signKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	// Header (48 bytes)
	header := make([]byte, sgxHeaderSize)
	binary.LittleEndian.PutUint16(header[sgxHeaderVersion:], 3)          // version 3
	binary.LittleEndian.PutUint16(header[sgxHeaderAttKeyType:], 2)       // ECDSA-256
	binary.LittleEndian.PutUint16(header[sgxHeaderQESVN:], 0x0300)       // QE SVN
	binary.LittleEndian.PutUint16(header[sgxHeaderPCESVN:], 0x0e00)      // PCE SVN
	copy(header[sgxHeaderQEVendorID:], intelQEVendorID[:])               // Intel QE

	// Report body (384 bytes)
	reportBody := make([]byte, sgxReportBodySize)
	copy(reportBody[sgxReportMRENCLAVE:], mrenclave[:])     // MRENCLAVE
	mrsigner := sha256.Sum256([]byte("test-signer"))
	copy(reportBody[sgxReportMRSIGNER:], mrsigner[:])       // MRSIGNER
	binary.LittleEndian.PutUint16(reportBody[sgxReportISVProdID:], 1)
	binary.LittleEndian.PutUint16(reportBody[sgxReportISVSVN:], 1)

	signedData := append(header, reportBody...)

	// Sign: ECDSA-256 over SHA-256(header || report_body)
	hash := sha256.Sum256(signedData)
	r, s, err := ecdsa.Sign(rand.Reader, signKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign quote: %v", err)
	}

	// Auth data: sig (64) + pubkey (64) = 128 bytes minimum
	sigBytes := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)

	pubKeyBytes := make([]byte, 64)
	xBytes := signKey.PublicKey.X.Bytes()
	yBytes := signKey.PublicKey.Y.Bytes()
	copy(pubKeyBytes[32-len(xBytes):32], xBytes)
	copy(pubKeyBytes[64-len(yBytes):64], yBytes)

	authData := append(sigBytes, pubKeyBytes...)

	// Auth data length (4 bytes)
	authLenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(authLenBytes, uint32(len(authData)))

	quote := append(signedData, authLenBytes...)
	quote = append(quote, authData...)

	return quote
}

func testMRENCLAVE() [32]byte {
	return sha256.Sum256([]byte("test-enclave-measurement"))
}

// ── SimulatedVerifier Tests ─────────────────────────────────

func TestSimulatedVerifier_AcceptsAnyAttestation(t *testing.T) {
	v := &SimulatedVerifier{log: testLogger}

	att := &types.SessionAttestation{
		EnclaveType: "sandbox",
		Measurement: "abc123",
		Timestamp:   types.NowUTC(),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sandbox", "sgx"},
	}

	result := v.Verify(att, policy)

	if !result.Verified {
		t.Errorf("simulated verifier should accept any attestation, got errors: %v", result.Errors)
	}
	if result.EnclaveType != "sandbox" {
		t.Errorf("expected enclave type 'sandbox', got '%s'", result.EnclaveType)
	}
}

func TestSimulatedVerifier_RejectsDisallowedEnclaveType(t *testing.T) {
	v := &SimulatedVerifier{log: testLogger}

	att := &types.SessionAttestation{
		EnclaveType: "nitro",
		Measurement: "abc123",
		Timestamp:   types.NowUTC(),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx"}, // nitro not allowed
	}

	result := v.Verify(att, policy)

	if result.Verified {
		t.Error("simulated verifier should reject disallowed enclave type")
	}
}

func TestSimulatedVerifier_Mode(t *testing.T) {
	v := &SimulatedVerifier{log: testLogger}
	if v.Mode() != ModeSimulated {
		t.Errorf("expected mode 'simulated', got '%s'", v.Mode())
	}
}

// ── RealVerifier Dispatch Tests ─────────────────────────────

func TestRealVerifier_DispatchesSGX(t *testing.T) {
	v := &RealVerifier{
		sgx:   &SGXVerifier{log: testLogger},
		nitro: &NitroVerifier{log: testLogger},
		log:   testLogger,
	}

	m := testMRENCLAVE()
	att := &types.SessionAttestation{
		EnclaveType: "sgx",
		Measurement: hex.EncodeToString(m[:]),
		Timestamp:   types.NowUTC(),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx"},
	}

	result := v.Verify(att, policy)

	// Should proceed (no raw_quote so measurement accepted from claim)
	if result.EnclaveType != "sgx" {
		t.Errorf("expected enclave type 'sgx', got '%s'", result.EnclaveType)
	}
}

func TestRealVerifier_DispatchesNitro(t *testing.T) {
	v := &RealVerifier{
		sgx:   &SGXVerifier{log: testLogger},
		nitro: &NitroVerifier{log: testLogger},
		log:   testLogger,
	}

	att := &types.SessionAttestation{
		EnclaveType: "nitro",
		Measurement: "some-pcr0-value",
		Timestamp:   types.NowUTC(),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"nitro"},
	}

	result := v.Verify(att, policy)

	if result.EnclaveType != "nitro" {
		t.Errorf("expected enclave type 'nitro', got '%s'", result.EnclaveType)
	}
}

func TestRealVerifier_RejectsUnsupportedEnclaveType(t *testing.T) {
	v := &RealVerifier{
		sgx:   &SGXVerifier{log: testLogger},
		nitro: &NitroVerifier{log: testLogger},
		log:   testLogger,
	}

	att := &types.SessionAttestation{
		EnclaveType: "unknown-tee",
		Measurement: "abc",
		Timestamp:   types.NowUTC(),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"unknown-tee"},
	}

	result := v.Verify(att, policy)

	if result.Verified {
		t.Error("should reject unsupported enclave type")
	}
}

func TestRealVerifier_RejectsDisallowedEnclaveType(t *testing.T) {
	v := &RealVerifier{
		sgx:   &SGXVerifier{log: testLogger},
		nitro: &NitroVerifier{log: testLogger},
		log:   testLogger,
	}

	att := &types.SessionAttestation{
		EnclaveType: "sgx",
		Measurement: "abc",
		Timestamp:   types.NowUTC(),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"nitro"}, // sgx not allowed
	}

	result := v.Verify(att, policy)

	if result.Verified {
		t.Error("should reject enclave type not in allowed list")
	}
}

func TestRealVerifier_SandboxOnlyIfAllowed(t *testing.T) {
	v := &RealVerifier{
		sgx:   &SGXVerifier{log: testLogger},
		nitro: &NitroVerifier{log: testLogger},
		log:   testLogger,
	}

	att := &types.SessionAttestation{
		EnclaveType: "sandbox",
		Measurement: "abc",
		Timestamp:   types.NowUTC(),
	}

	// Sandbox allowed
	policy1 := Policy{AllowedEnclaveTypes: []string{"sandbox"}}
	r1 := v.Verify(att, policy1)
	if !r1.Verified {
		t.Error("sandbox should be accepted when in allowed list")
	}

	// Sandbox not allowed
	policy2 := Policy{AllowedEnclaveTypes: []string{"sgx"}}
	r2 := v.Verify(att, policy2)
	if r2.Verified {
		t.Error("sandbox should be rejected when not in allowed list")
	}
}

// ── SGX Quote Parsing Tests ─────────────────────────────────

func TestParseSGXQuote_Valid(t *testing.T) {
	signKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	mrenclave := testMRENCLAVE()
	quoteBytes := buildTestSGXQuote(t, mrenclave, signKey)

	quote, err := ParseSGXQuote(quoteBytes)
	if err != nil {
		t.Fatalf("ParseSGXQuote failed: %v", err)
	}

	if quote.Version != 3 {
		t.Errorf("expected version 3, got %d", quote.Version)
	}
	if quote.AttKeyType != 2 {
		t.Errorf("expected att key type 2, got %d", quote.AttKeyType)
	}
	if !quote.IsIntelQE() {
		t.Error("expected Intel QE vendor ID")
	}
	if quote.MRENCLAVEHex() != hex.EncodeToString(mrenclave[:]) {
		t.Errorf("MRENCLAVE mismatch: got %s, expected %s",
			quote.MRENCLAVEHex(), hex.EncodeToString(mrenclave[:]))
	}
}

func TestParseSGXQuote_TooShort(t *testing.T) {
	_, err := ParseSGXQuote(make([]byte, 100))
	if err == nil {
		t.Error("expected error for short quote")
	}
}

func TestParseSGXQuote_AllZeroMRENCLAVE(t *testing.T) {
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	quoteBytes := buildTestSGXQuote(t, [32]byte{}, signKey)

	quote, err := ParseSGXQuote(quoteBytes)
	if err != nil {
		t.Fatalf("ParseSGXQuote failed: %v", err)
	}

	// Structural validation should catch all-zero MRENCLAVE
	v := &SGXVerifier{log: testLogger}
	sv := v.validateQuoteStructure(quote)
	hasAllZeroError := false
	for _, e := range sv.errors {
		if e == "MRENCLAVE is all zeros (invalid)" {
			hasAllZeroError = true
		}
	}
	if !hasAllZeroError {
		t.Error("expected all-zero MRENCLAVE error")
	}
}

// ── SGX Signature Verification Tests ────────────────────────

func TestSGXVerifier_SignatureVerification(t *testing.T) {
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mrenclave := testMRENCLAVE()
	quoteBytes := buildTestSGXQuote(t, mrenclave, signKey)

	att := &types.SessionAttestation{
		EnclaveType: "sgx",
		Measurement: hex.EncodeToString(mrenclave[:]),
		Timestamp:   types.NowUTC(),
		RawQuote:    base64.StdEncoding.EncodeToString(quoteBytes),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx"},
	}

	v := &SGXVerifier{log: testLogger}
	result := v.Verify(att, policy)

	if !result.SignatureValid {
		t.Errorf("signature should be valid, errors: %v, details: %v", result.Errors, result.Details)
	}
	if !result.Verified {
		t.Errorf("verification should pass, errors: %v", result.Errors)
	}
}

func TestSGXVerifier_TamperedQuote(t *testing.T) {
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mrenclave := testMRENCLAVE()
	quoteBytes := buildTestSGXQuote(t, mrenclave, signKey)

	// Tamper with the MRENCLAVE after signing
	quoteBytes[sgxHeaderSize+sgxReportMRENCLAVE] ^= 0xFF

	att := &types.SessionAttestation{
		EnclaveType: "sgx",
		Measurement: hex.EncodeToString(mrenclave[:]),
		Timestamp:   types.NowUTC(),
		RawQuote:    base64.StdEncoding.EncodeToString(quoteBytes),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx"},
	}

	v := &SGXVerifier{log: testLogger}
	result := v.Verify(att, policy)

	if result.SignatureValid {
		t.Error("tampered quote should fail signature verification")
	}
	if result.Verified {
		t.Error("tampered quote should not be verified")
	}
}

func TestSGXVerifier_MeasurementMismatch(t *testing.T) {
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mrenclave := testMRENCLAVE()
	quoteBytes := buildTestSGXQuote(t, mrenclave, signKey)

	att := &types.SessionAttestation{
		EnclaveType: "sgx",
		Measurement: hex.EncodeToString(mrenclave[:]),
		Timestamp:   types.NowUTC(),
		RawQuote:    base64.StdEncoding.EncodeToString(quoteBytes),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx"},
		ExpectedMeasurements: map[string]string{
			"sgx": "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}

	v := &SGXVerifier{log: testLogger}
	result := v.Verify(att, policy)

	if result.MeasurementMatches {
		t.Error("measurement should not match when expected differs")
	}
	if result.Verified {
		t.Error("should not verify when measurement doesn't match policy")
	}
}

func TestSGXVerifier_MeasurementMatch(t *testing.T) {
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mrenclave := testMRENCLAVE()
	quoteBytes := buildTestSGXQuote(t, mrenclave, signKey)

	att := &types.SessionAttestation{
		EnclaveType: "sgx",
		Measurement: hex.EncodeToString(mrenclave[:]),
		Timestamp:   types.NowUTC(),
		RawQuote:    base64.StdEncoding.EncodeToString(quoteBytes),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx"},
		ExpectedMeasurements: map[string]string{
			"sgx": hex.EncodeToString(mrenclave[:]),
		},
	}

	v := &SGXVerifier{log: testLogger}
	result := v.Verify(att, policy)

	if !result.MeasurementMatches {
		t.Error("measurement should match")
	}
	if !result.Verified {
		t.Errorf("should verify, errors: %v", result.Errors)
	}
}

func TestSGXVerifier_SimulatedModeRelaxesCrypto(t *testing.T) {
	att := &types.SessionAttestation{
		EnclaveType: "sgx-simulated",
		Measurement: "abc123",
		Timestamp:   types.NowUTC(),
		RawQuote:    base64.StdEncoding.EncodeToString(make([]byte, sgxQuoteMinSize)),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx-simulated"},
	}

	v := &SGXVerifier{log: testLogger}
	result := v.Verify(att, policy)

	if !result.Verified {
		t.Errorf("sgx-simulated should be verified with relaxed crypto, errors: %v", result.Errors)
	}
}

// ── Nitro Verification Tests ────────────────────────────────

func TestNitroVerifier_ValidDoc(t *testing.T) {
	pcr0 := hex.EncodeToString(sha256.New().Sum([]byte("test-enclave-image")))

	doc := NitroAttestationDoc{
		ModuleID:    "test-module",
		Digest:      "SHA384",
		Timestamp:   time.Now().UnixMilli(),
		PCRs:        map[string]string{"PCR0": pcr0, "PCR1": "kernel-hash", "PCR2": "app-hash"},
		Certificate: base64.StdEncoding.EncodeToString([]byte("test-cert")),
		CABundle:    []string{base64.StdEncoding.EncodeToString([]byte("test-root-ca"))},
	}
	docJSON, _ := json.Marshal(doc)
	rawQuote := base64.StdEncoding.EncodeToString(docJSON)

	att := &types.SessionAttestation{
		EnclaveType: "nitro",
		Measurement: pcr0,
		Timestamp:   types.NowUTC(),
		RawQuote:    rawQuote,
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"nitro"},
	}

	v := &NitroVerifier{log: testLogger}
	result := v.Verify(att, policy)

	if result.Measurement != pcr0 {
		t.Errorf("expected PCR0 '%s', got '%s'", pcr0, result.Measurement)
	}
}

func TestNitroVerifier_MissingPCR0(t *testing.T) {
	doc := NitroAttestationDoc{
		ModuleID:  "test-module",
		Digest:    "SHA384",
		Timestamp: time.Now().UnixMilli(),
		PCRs:      map[string]string{"PCR1": "kernel-hash"}, // no PCR0
	}
	docJSON, _ := json.Marshal(doc)
	rawQuote := base64.StdEncoding.EncodeToString(docJSON)

	att := &types.SessionAttestation{
		EnclaveType: "nitro",
		Measurement: "fallback",
		Timestamp:   types.NowUTC(),
		RawQuote:    rawQuote,
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"nitro"},
	}

	v := &NitroVerifier{log: testLogger}
	result := v.Verify(att, policy)

	hasError := false
	for _, e := range result.Errors {
		if e == "PCR0 (enclave image hash) missing from attestation" {
			hasError = true
		}
	}
	if !hasError {
		t.Error("expected error for missing PCR0")
	}
}

func TestNitroVerifier_SimulatedRelaxesCrypto(t *testing.T) {
	doc := NitroAttestationDoc{
		ModuleID:  "test-module",
		Digest:    "SHA384",
		Timestamp: time.Now().UnixMilli(),
		PCRs:      map[string]string{"PCR0": "test-pcr0"},
	}
	docJSON, _ := json.Marshal(doc)
	rawQuote := base64.StdEncoding.EncodeToString(docJSON)

	att := &types.SessionAttestation{
		EnclaveType: "nitro-simulated",
		Measurement: "test-pcr0",
		Timestamp:   types.NowUTC(),
		RawQuote:    rawQuote,
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"nitro-simulated"},
	}

	v := &NitroVerifier{log: testLogger}
	result := v.Verify(att, policy)

	if !result.Verified {
		t.Errorf("nitro-simulated should be verified, errors: %v", result.Errors)
	}
}

// ── Freshness Tests ─────────────────────────────────────────

func TestCheckFreshness_Valid(t *testing.T) {
	att := &types.SessionAttestation{
		Timestamp: types.NowUTC(),
	}
	ok, _ := checkFreshness(att, 300)
	if !ok {
		t.Error("fresh attestation should pass")
	}
}

func TestCheckFreshness_Stale(t *testing.T) {
	staleTime := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	att := &types.SessionAttestation{
		Timestamp: staleTime,
	}
	ok, _ := checkFreshness(att, 300) // 5 min max
	if ok {
		t.Error("stale attestation should fail")
	}
}

func TestCheckFreshness_Future(t *testing.T) {
	futureTime := time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	att := &types.SessionAttestation{
		Timestamp: futureTime,
	}
	ok, _ := checkFreshness(att, 300)
	if ok {
		t.Error("future attestation should fail")
	}
}

func TestCheckFreshness_NoMax(t *testing.T) {
	att := &types.SessionAttestation{
		Timestamp: types.NowUTC(),
	}
	ok, _ := checkFreshness(att, 0)
	if !ok {
		t.Error("no max freshness should always pass")
	}
}

func TestCheckFreshness_MissingTimestamp(t *testing.T) {
	att := &types.SessionAttestation{}
	ok, _ := checkFreshness(att, 300)
	if ok {
		t.Error("missing timestamp should fail")
	}
}

// ── Agent Hash Tests ────────────────────────────────────────

func TestCheckAgentHash_Matches(t *testing.T) {
	att := &types.SessionAttestation{
		AgentHash: &types.HashDigest{Algorithm: "sha-256", Value: "abc123"},
	}
	ok, _ := checkAgentHash(att, &types.HashDigest{Algorithm: "sha-256", Value: "abc123"})
	if !ok {
		t.Error("matching hash should pass")
	}
}

func TestCheckAgentHash_Mismatch(t *testing.T) {
	att := &types.SessionAttestation{
		AgentHash: &types.HashDigest{Algorithm: "sha-256", Value: "abc123"},
	}
	ok, _ := checkAgentHash(att, &types.HashDigest{Algorithm: "sha-256", Value: "def456"})
	if ok {
		t.Error("mismatched hash should fail")
	}
}

func TestCheckAgentHash_NoExpected(t *testing.T) {
	att := &types.SessionAttestation{
		AgentHash: &types.HashDigest{Algorithm: "sha-256", Value: "abc123"},
	}
	ok, _ := checkAgentHash(att, nil)
	if !ok {
		t.Error("no expected hash should pass")
	}
}

func TestCheckAgentHash_MissingFromAttestation(t *testing.T) {
	att := &types.SessionAttestation{}
	ok, _ := checkAgentHash(att, &types.HashDigest{Algorithm: "sha-256", Value: "abc123"})
	if ok {
		t.Error("missing agent hash should fail when expected")
	}
}

func TestCheckAgentHash_AlgorithmMismatch(t *testing.T) {
	att := &types.SessionAttestation{
		AgentHash: &types.HashDigest{Algorithm: "sha-384", Value: "abc123"},
	}
	ok, _ := checkAgentHash(att, &types.HashDigest{Algorithm: "sha-256", Value: "abc123"})
	if ok {
		t.Error("algorithm mismatch should fail")
	}
}

// ── PolicyFromContract Tests ────────────────────────────────

func TestPolicyFromContract(t *testing.T) {
	contract := &types.Contract{
		AttestationRequirements: types.AttestationRequirements{
			EnclaveTypes:         []string{"sgx", "nitro"},
			AttestationFreshness: 600,
		},
		Consumer: types.ContractConsumer{
			AgentHash: &types.HashDigest{Algorithm: "sha-256", Value: "expected-hash"},
		},
	}

	policy := PolicyFromContract(contract)

	if len(policy.AllowedEnclaveTypes) != 2 {
		t.Errorf("expected 2 allowed types, got %d", len(policy.AllowedEnclaveTypes))
	}
	if policy.MaxFreshnessSeconds != 600 {
		t.Errorf("expected 600s freshness, got %d", policy.MaxFreshnessSeconds)
	}
	if policy.ExpectedAgentHash == nil {
		t.Error("expected agent hash should not be nil")
	}
	if policy.ExpectedAgentHash.Value != "expected-hash" {
		t.Errorf("expected hash 'expected-hash', got '%s'", policy.ExpectedAgentHash.Value)
	}
}

// ── Factory Tests ───────────────────────────────────────────

func TestNew_Simulated(t *testing.T) {
	v := New(ModeSimulated, testLogger)
	if v.Mode() != ModeSimulated {
		t.Errorf("expected simulated mode, got %s", v.Mode())
	}
}

func TestNew_Verify(t *testing.T) {
	v := New(ModeVerify, testLogger)
	if v.Mode() != ModeVerify {
		t.Errorf("expected verify mode, got %s", v.Mode())
	}
}

// ── End-to-end: full SGX flow ───────────────────────────────

func TestEndToEnd_SGXQuoteVerification(t *testing.T) {
	// Generate a signing key
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mrenclave := testMRENCLAVE()
	quoteBytes := buildTestSGXQuote(t, mrenclave, signKey)
	mrenclaveHex := hex.EncodeToString(mrenclave[:])

	// Build attestation as the agent would
	att := &types.SessionAttestation{
		EnclaveType: "sgx",
		Measurement: mrenclaveHex,
		AgentHash:   &types.HashDigest{Algorithm: "sha-256", Value: "agent-binary-hash"},
		Timestamp:   types.NowUTC(),
		Signature:   "placeholder",
		RawQuote:    base64.StdEncoding.EncodeToString(quoteBytes),
	}

	// Build policy from a contract
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx"},
		ExpectedMeasurements: map[string]string{
			"sgx": mrenclaveHex,
		},
		ExpectedAgentHash: &types.HashDigest{Algorithm: "sha-256", Value: "agent-binary-hash"},
		MaxFreshnessSeconds: 300,
	}

	// Verify
	v := New(ModeVerify, testLogger)
	result := v.Verify(att, policy)

	if !result.Verified {
		t.Fatalf("end-to-end SGX verification failed: errors=%v details=%v", result.Errors, result.Details)
	}
	if !result.SignatureValid {
		t.Error("signature should be valid")
	}
	if !result.MeasurementMatches {
		t.Error("measurement should match")
	}
	if !result.FreshnessValid {
		t.Error("freshness should be valid")
	}
	if result.Measurement != mrenclaveHex {
		t.Errorf("measurement should be %s, got %s", mrenclaveHex, result.Measurement)
	}
}

// ── Edge cases ──────────────────────────────────────────────

func TestSGXVerifier_NoRawQuote(t *testing.T) {
	att := &types.SessionAttestation{
		EnclaveType: "sgx",
		Measurement: "claimed-measurement",
		Timestamp:   types.NowUTC(),
		// No RawQuote — measurement accepted from claim
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx"},
	}

	v := &SGXVerifier{log: testLogger}
	result := v.Verify(att, policy)

	// Should be verified (measurement accepted from claim) but crypto fields unverified
	if !result.Verified {
		t.Errorf("should accept claimed measurement without raw_quote, errors: %v", result.Errors)
	}
	if result.SignatureValid {
		t.Error("signature should not be valid without raw_quote")
	}
}

func TestSGXVerifier_InvalidBase64Quote(t *testing.T) {
	att := &types.SessionAttestation{
		EnclaveType: "sgx",
		Measurement: "abc",
		Timestamp:   types.NowUTC(),
		RawQuote:    "not-valid-base64!!@#$",
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx"},
	}

	v := &SGXVerifier{log: testLogger}
	result := v.Verify(att, policy)

	if result.Verified {
		t.Error("invalid base64 should fail verification")
	}
}

func TestNitroVerifier_InvalidJSON(t *testing.T) {
	att := &types.SessionAttestation{
		EnclaveType: "nitro",
		Measurement: "abc",
		Timestamp:   types.NowUTC(),
		RawQuote:    base64.StdEncoding.EncodeToString([]byte("not json")),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"nitro"},
	}

	v := &NitroVerifier{log: testLogger}
	result := v.Verify(att, policy)

	if result.Verified {
		t.Error("invalid JSON should fail verification")
	}
}

func TestDecodeRawQuote_StandardBase64(t *testing.T) {
	original := []byte("test data for encoding")
	encoded := base64.StdEncoding.EncodeToString(original)
	decoded, err := decodeRawQuote(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(decoded) != string(original) {
		t.Error("decoded data mismatch")
	}
}

func TestDecodeRawQuote_Empty(t *testing.T) {
	_, err := decodeRawQuote("")
	if err == nil {
		t.Error("empty quote should fail")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Error("short string should not be truncated")
	}
	if truncate("a-very-long-string-here", 5) != "a-ver..." {
		t.Errorf("got '%s'", truncate("a-very-long-string-here", 5))
	}
}

// ── Benchmark ───────────────────────────────────────────────

func BenchmarkSGXQuoteParsing(b *testing.B) {
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mrenclave := testMRENCLAVE()
	quoteBytes := buildTestSGXQuote(&testing.T{}, mrenclave, signKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseSGXQuote(quoteBytes)
	}
}

func BenchmarkSGXVerification(b *testing.B) {
	signKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mrenclave := testMRENCLAVE()
	quoteBytes := buildTestSGXQuote(&testing.T{}, mrenclave, signKey)

	att := &types.SessionAttestation{
		EnclaveType: "sgx",
		Measurement: hex.EncodeToString(mrenclave[:]),
		Timestamp:   types.NowUTC(),
		RawQuote:    base64.StdEncoding.EncodeToString(quoteBytes),
	}
	policy := Policy{
		AllowedEnclaveTypes: []string{"sgx"},
	}

	v := &SGXVerifier{log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.Verify(att, policy)
	}
}
