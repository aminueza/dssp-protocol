// Package types defines the core DSSP protocol types matching the JSON schemas.
// These types form the data model for the Document Sovereignty Protocol v0.1.
package types

import (
	"encoding/json"
	"time"
)

// DSPVersion is the protocol version constant.
const DSPVersion = "0.1"

const (
	SchemaManifest   = "https://dssp.dev/schema/manifest/v0.1"
	SchemaContract   = "https://dssp.dev/schema/contract/v0.1"
	SchemaResult     = "https://dssp.dev/schema/result/v0.1"
	SchemaAuditEvent = "https://dssp.dev/schema/audit/v0.1"
)

const (
	PrefixManifest = "mf"
	PrefixDocument = "doc"
	PrefixContract = "ct"
	PrefixSession  = "ps"
	PrefixResult   = "rs"
	PrefixEvent    = "ev"
	PrefixAgent    = "ag"
)

type HashDigest struct {
	Algorithm string `json:"algorithm"`           // sha-256, sha-384, sha-512, blake3
	Value     string `json:"value"`               // hex-encoded hash
}

// We serialize to RFC 3339 with Z suffix.
type Timestamp = string

type OwnerInfo struct {
	OrgID         string `json:"org_id"`
	Jurisdiction  string `json:"jurisdiction,omitempty"`
	DataResidency string `json:"data_residency,omitempty"`
}

type Manifest struct {
	Schema     string           `json:"$schema"`
	DSPVersion string           `json:"dssp_version"`
	ManifestID string           `json:"manifest_id"`
	Owner      OwnerInfo        `json:"owner"`
	CreatedAt  Timestamp        `json:"created_at"`
	ExpiresAt  Timestamp        `json:"expires_at,omitempty"`
	Scope      *ManifestScope   `json:"scope,omitempty"`
	Documents  []DocumentEntry  `json:"documents"`
	Summary    *ManifestSummary `json:"summary,omitempty"`
}

type ManifestScope struct {
	EngagementID string          `json:"engagement_id,omitempty"`
	Period       *ScopePeriod    `json:"period,omitempty"`
	Tags         []string        `json:"tags,omitempty"`
}

type ScopePeriod struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type StorageRef struct {
	Type     string `json:"type"`               // s3, azure-blob, gcs
	Bucket   string `json:"bucket"`
	Key      string `json:"key"`
	Endpoint string `json:"endpoint,omitempty"`
}

type DocumentEntry struct {
	DocumentID        string            `json:"document_id"`
	Classification    string            `json:"classification"`
	Sensitivity       string            `json:"sensitivity"`
	Format            string            `json:"format"`
	Hash              HashDigest        `json:"hash"`
	StorageRef        *StorageRef       `json:"storage_ref,omitempty"`
	MimeType          string            `json:"mime_type,omitempty"`
	PageCount         int               `json:"page_count,omitempty"`
	Language          string            `json:"language,omitempty"`
	SizeBytes         int64             `json:"size_bytes,omitempty"`
	CreatedAt         Timestamp         `json:"created_at,omitempty"`
	PIIFieldsDeclared []string          `json:"pii_fields_declared,omitempty"`
	AllowedOperations []string          `json:"allowed_operations,omitempty"`
	DeniedOperations  []string          `json:"denied_operations,omitempty"`
	Tags              []string          `json:"tags,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

type ManifestSummary struct {
	TotalDocuments   int            `json:"total_documents"`
	TotalSizeBytes   int64          `json:"total_size_bytes,omitempty"`
	Classifications  map[string]int `json:"classifications,omitempty"`
	SensitivityLevels map[string]int `json:"sensitivity_levels,omitempty"`
	Formats          map[string]int `json:"formats,omitempty"`
	Languages        map[string]int `json:"languages,omitempty"`
}

type Contract struct {
	Schema                string                 `json:"$schema"`
	DSPVersion            string                 `json:"dssp_version"`
	ContractID            string                 `json:"contract_id"`
	Version               int                    `json:"version"`
	Status                string                 `json:"status"` // active, suspended, revoked, expired
	Owner                 OwnerInfo              `json:"owner"`
	Consumer              ContractConsumer        `json:"consumer"`
	Permissions           ContractPermissions     `json:"permissions"`
	Restrictions          ContractRestrictions    `json:"restrictions"`
	AttestationRequirements AttestationRequirements `json:"attestation_requirements"`
	CreatedAt             Timestamp              `json:"created_at"`
	UpdatedAt             Timestamp              `json:"updated_at,omitempty"`
	RevokedAt             Timestamp              `json:"revoked_at,omitempty"`
	RevocationReason      string                 `json:"revocation_reason,omitempty"`
}

type ContractConsumer struct {
	OrgID                string      `json:"org_id"`
	AgentID              string      `json:"agent_id,omitempty"`
	AgentHash            *HashDigest `json:"agent_hash,omitempty"`
	AgentVersionsAllowed []string    `json:"agent_versions_allowed,omitempty"`
	AgentType            string      `json:"agent_type,omitempty"`
	SubAgentPolicy       *SubAgentPolicy `json:"sub_agent_policy,omitempty"`
}

type SubAgentPolicy struct {
	Allowed                 *bool       `json:"allowed,omitempty"`
	MaxPipelineSteps        int         `json:"max_pipeline_steps,omitempty"`
	AllowedPurposes         []string    `json:"allowed_purposes,omitempty"`
	RequireSubAgentHashes   *bool       `json:"require_sub_agent_hashes,omitempty"`
	ApprovedSubAgentHashes  []HashDigest `json:"approved_sub_agent_hashes,omitempty"`
	CrossEnclaveAllowed     *bool       `json:"cross_enclave_allowed,omitempty"`
	LLMSubAgentAllowed      *bool       `json:"llm_sub_agent_allowed,omitempty"`
}

type ContractPermissions struct {
	Operations            []string          `json:"operations"`
	DocumentFilter        *DocumentFilter   `json:"document_filter,omitempty"`
	MaxDocumentsPerSession int              `json:"max_documents_per_session,omitempty"`
	MaxConcurrentSessions  int              `json:"max_concurrent_sessions,omitempty"`
	MaxSessionDuration     int              `json:"max_session_duration_seconds,omitempty"`
	ValidFrom             Timestamp         `json:"valid_from,omitempty"`
	ValidUntil            Timestamp         `json:"valid_until,omitempty"`
}

type DocumentFilter struct {
	Classifications []string `json:"classifications,omitempty"`
	SensitivityMax  string   `json:"sensitivity_max,omitempty"`
	TagsRequired    []string `json:"tags_required,omitempty"`
	TagsAny         []string `json:"tags_any,omitempty"`
	DocumentIDs     []string `json:"document_ids,omitempty"`
}

type ContractRestrictions struct {
	NetworkPolicy          NetworkPolicy          `json:"network_policy"`
	StoragePolicy          string                 `json:"storage_policy"`
	ResultPolicy           ResultPolicy           `json:"result_policy"`
	ResultScanning         ResultScanning         `json:"result_scanning"`
	DocumentSanitization   *DocumentSanitization  `json:"document_sanitization,omitempty"`
	PrivacyBudget          *PrivacyBudget         `json:"privacy_budget,omitempty"`
	GatewayVisibility      *GatewayVisibility     `json:"gateway_visibility,omitempty"`
}

type NetworkPolicy struct {
	Egress              string               `json:"egress"` // deny_all, allow_listed
	AllowedDestinations []AllowedDestination `json:"allowed_destinations,omitempty"`
}

type AllowedDestination struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Purpose string `json:"purpose"`
}

type ResultPolicy struct {
	RawContentAllowed      *bool                    `json:"raw_content_allowed,omitempty"`
	MaxResultSizeBytes     int64                    `json:"max_result_size_bytes,omitempty"`
	PIIRedactionRules      map[string]string        `json:"pii_redaction_rules"`
	CustomRedactionPatterns []CustomRedactionPattern `json:"custom_redaction_patterns,omitempty"`
	FreeTextFieldsPolicy   string                   `json:"free_text_fields_policy,omitempty"`
	MaxStringFieldLength   int                      `json:"max_string_field_length,omitempty"`
	NumericPrecisionPolicy *NumericPrecisionPolicy  `json:"numeric_precision_policy,omitempty"`
}

type CustomRedactionPattern struct {
	Pattern     string `json:"pattern"`
	Method      string `json:"method"`
	Description string `json:"description"`
}

type NumericPrecisionPolicy struct {
	MaxDecimalPlaces          int  `json:"max_decimal_places,omitempty"`
	MaxSignificantDigits      int  `json:"max_significant_digits,omitempty"`
	EnforceStandardRounding   *bool `json:"enforce_standard_rounding,omitempty"`
	DetectEntropyAnomaly      *bool `json:"detect_entropy_anomaly,omitempty"`
	CurrencyFieldsIntegerCents *bool `json:"currency_fields_integer_cents,omitempty"`
}

type ResultScanning struct {
	Enabled            bool                 `json:"enabled"`
	RequiredScanners   []string             `json:"required_scanners,omitempty"`
	NERModelRequirements *NERModelRequirements `json:"ner_model_requirements,omitempty"`
	ScanFailureAction  string               `json:"scan_failure_action,omitempty"`
}

type NERModelRequirements struct {
	MinEntityTypes         []string     `json:"min_entity_types,omitempty"`
	MinConfidenceThreshold float64      `json:"min_confidence_threshold,omitempty"`
	ApprovedScannerHashes  []HashDigest `json:"approved_scanner_hashes,omitempty"`
	Languages              []string     `json:"languages,omitempty"`
}

type DocumentSanitization struct {
	Enabled                   bool        `json:"enabled"`
	StripHiddenText           *bool       `json:"strip_hidden_text,omitempty"`
	StripJavaScript           *bool       `json:"strip_javascript,omitempty"`
	StripEmbeddedFiles        *bool       `json:"strip_embedded_files,omitempty"`
	NormalizeUnicode          *bool       `json:"normalize_unicode,omitempty"`
	InjectionPatternDetection *bool       `json:"injection_pattern_detection,omitempty"`
	MaxTextLengthPerPage      int         `json:"max_text_length_per_page,omitempty"`
	SanitizerHash             *HashDigest `json:"sanitizer_hash,omitempty"`
}

type PrivacyBudget struct {
	Epsilon                    *float64 `json:"epsilon,omitempty"`
	Delta                      *float64 `json:"delta,omitempty"`
	KAnonymityMin              int      `json:"k_anonymity_min,omitempty"`
	MaxUniqueValuesPerField    int      `json:"max_unique_values_per_field,omitempty"`
	AggregationMinimumRecords  int      `json:"aggregation_minimum_records,omitempty"`
	BudgetWindow               string   `json:"budget_window,omitempty"`
	BudgetConsumed             float64  `json:"budget_consumed,omitempty"`
}

type GatewayVisibility struct {
	Manifests                  string `json:"manifests"`
	Results                    string `json:"results"`
	AuditEvents                string `json:"audit_events"`
	CrossEngagementCorrelation *bool  `json:"cross_engagement_correlation,omitempty"`
}

type AttestationRequirements struct {
	EnclaveTypes              []string             `json:"enclave_types"`
	MeasurementAuthorities    []string             `json:"measurement_authorities,omitempty"`
	MustInclude               []string             `json:"must_include"`
	AttestationFreshness      int                  `json:"attestation_freshness_seconds,omitempty"`
	RuntimeVerification       *RuntimeVerification `json:"runtime_verification,omitempty"`
}

type RuntimeVerification struct {
	EndOfSessionAttestation *bool              `json:"end_of_session_attestation,omitempty"`
	PeriodicHeartbeatSecs   int                `json:"periodic_heartbeat_seconds,omitempty"`
	SidecarVerifier         *SidecarVerifier   `json:"sidecar_verifier,omitempty"`
	MemorySnapshotOnExit    *bool              `json:"memory_snapshot_on_exit,omitempty"`
}

type SidecarVerifier struct {
	Required     *bool       `json:"required,omitempty"`
	VerifierHash *HashDigest `json:"verifier_hash,omitempty"`
	Monitors     []string    `json:"monitors,omitempty"`
}

// Session states.
const (
	SessionCreated    = "created"
	SessionActive     = "active"
	SessionCompleted  = "completed"
	SessionFailed     = "failed"
	SessionTerminated = "terminated"
)

type Session struct {
	SessionID    string            `json:"session_id"`
	ContractID   string            `json:"contract_id"`
	ManifestID   string            `json:"manifest_id"`
	Status       string            `json:"status"`
	EnclaveType  string            `json:"enclave_type,omitempty"`
	AgentOrgID   string            `json:"agent_org_id,omitempty"`
	AgentID      string            `json:"agent_id,omitempty"`
	Token        *ScopedToken      `json:"token,omitempty"`
	StartedAt    Timestamp         `json:"started_at"`
	CompletedAt  Timestamp         `json:"completed_at,omitempty"`
	LastHeartbeat Timestamp        `json:"last_heartbeat,omitempty"`
	ExpiresAt    Timestamp         `json:"expires_at,omitempty"`
	ResultID     string            `json:"result_id,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type ScopedToken struct {
	Token     string       `json:"token"`
	ExpiresAt Timestamp    `json:"expires_at"`
	Scope     TokenScope   `json:"scope"`
}

type TokenScope struct {
	DocumentIDs []string `json:"document_ids"`
	Operations  []string `json:"operations"`
}

type Result struct {
	Schema                   string                 `json:"$schema"`
	DSPVersion               string                 `json:"dssp_version"`
	ResultID                 string                 `json:"result_id"`
	ContractID               string                 `json:"contract_id"`
	SessionID                string                 `json:"session_id"`
	ProducedAt               Timestamp              `json:"produced_at"`
	Attestation              ResultAttestation       `json:"attestation"`
	Extractions              []DocumentExtraction    `json:"extractions"`
	PIIReport                PIIHandlingReport       `json:"pii_report"`
	ResultScan               ResultScanReport        `json:"result_scan"`
	EndOfSessionAttestation  *EndOfSessionAttestation `json:"end_of_session_attestation,omitempty"`
	Errors                   []ProcessingError       `json:"errors,omitempty"`
}

type ResultAttestation struct {
	EnclaveType             string          `json:"enclave_type"`
	Measurement             string          `json:"measurement"`
	AgentHash               HashDigest      `json:"agent_hash"`
	Timestamp               Timestamp       `json:"timestamp"`
	SignedBy                string          `json:"signed_by,omitempty"`
	Signature               string          `json:"signature"`
	PlatformCertificateChain []string       `json:"platform_certificate_chain,omitempty"`
	Claims                  AttestationClaims `json:"claims"`
}

type AttestationClaims struct {
	DocumentsProcessed  int                 `json:"documents_processed"`
	ProcessingDurationMs int                `json:"processing_duration_ms"`
	MemoryPeakBytes     int64              `json:"memory_peak_bytes,omitempty"`
	NetworkEgressBytes  int64              `json:"network_egress_bytes,omitempty"`
	NetworkDestinations []string           `json:"network_destinations,omitempty"`
	InputDocumentHashes []HashDigest       `json:"input_document_hashes,omitempty"`
	OutputResultHash    *HashDigest        `json:"output_result_hash,omitempty"`
	SubAgentChain       []SubAgentAttestation `json:"sub_agent_chain,omitempty"`
}

type SubAgentAttestation struct {
	StepIndex            int         `json:"step_index"`
	AgentType            string      `json:"agent_type"`
	AgentID              string      `json:"agent_id,omitempty"`
	AgentHash            HashDigest  `json:"agent_hash"`
	AgentVersion         string      `json:"agent_version,omitempty"`
	Purpose              string      `json:"purpose"`
	InputType            string      `json:"input_type,omitempty"`
	OutputType           string      `json:"output_type,omitempty"`
	EnclaveShared        *bool       `json:"enclave_shared,omitempty"`
	SeparateAttestation  *json.RawMessage `json:"separate_attestation,omitempty"`
	ProcessingDurationMs int         `json:"processing_duration_ms,omitempty"`
}

// Uses json.RawMessage for maximum flexibility — agents may use varied schemas.
type DocumentExtraction = json.RawMessage

type ExtractedTable struct {
	TableID           string           `json:"table_id,omitempty"`
	Name              string           `json:"name,omitempty"`
	Headers           []string         `json:"headers,omitempty"`
	Columns           []TableColumn    `json:"columns,omitempty"`
	ColumnDefinitions []TableColumn    `json:"column_definitions,omitempty"`
	RowCount          int              `json:"row_count"`
	Rows              json.RawMessage  `json:"rows,omitempty"`
	Checksum          *HashDigest      `json:"checksum,omitempty"`
}

type TableColumn struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	PIIField   string `json:"pii_field,omitempty"`
	PIIBearing *bool  `json:"pii_bearing,omitempty"`
}

type ClassificationResult struct {
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
}

type ExtractionValidation struct {
	Passed bool              `json:"passed"`
	Checks []ValidationCheck `json:"checks,omitempty"`
}

type ValidationCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

type PIIHandlingReport struct {
	FieldsEncountered       []string          `json:"fields_encountered"`
	FieldsRedacted          []string          `json:"fields_redacted"`
	RedactionMethodsApplied json.RawMessage `json:"redaction_methods_applied,omitempty"`
	RedactionMethodsUsed    json.RawMessage `json:"redaction_methods_used,omitempty"`
	FieldsAllowedByContract []string          `json:"fields_allowed_by_contract,omitempty"`
	RawContentIncluded      bool              `json:"raw_content_included"`
	ComplianceStatus        string            `json:"compliance_status"` // compliant, violation_detected, unknown
	Violations              []PIIViolation    `json:"violations,omitempty"`
}

type PIIViolation struct {
	Field       string `json:"field"`
	Description string `json:"description"`
	Severity    string `json:"severity,omitempty"`
}

// Verdicts use json.RawMessage for flexibility — agents may use varied verdict schemas.
type ResultScanReport struct {
	Performed            bool              `json:"performed"`
	Verdicts             []json.RawMessage `json:"verdicts,omitempty"`
	OverallPassed        *bool             `json:"overall_passed,omitempty"`
	OverallVerdict       string            `json:"overall_verdict,omitempty"`
	TotalFindings        int               `json:"total_findings,omitempty"`
	FieldsModifiedByScan int               `json:"fields_modified_by_scan,omitempty"`
	ScanDurationMs       int               `json:"scan_duration_ms,omitempty"`
}

type ResultScanVerdict struct {
	ScannerType    string      `json:"scanner_type"`
	ScannerID      string      `json:"scanner_id,omitempty"`
	ScannerVersion string      `json:"scanner_version"`
	ScannerHash    *HashDigest `json:"scanner_hash,omitempty"`
	Passed         bool        `json:"passed"`
	Findings       []ScanFinding `json:"findings,omitempty"`
	Statistics     *ScanStatistics `json:"statistics,omitempty"`
	Timestamp      Timestamp   `json:"timestamp"`
}

type ScanFinding struct {
	FieldPath         string      `json:"field_path"`
	EntityType        string      `json:"entity_type"`
	Confidence        float64     `json:"confidence,omitempty"`
	ActionTaken       string      `json:"action_taken"`
	OriginalValueHash *HashDigest `json:"original_value_hash,omitempty"`
}

type ScanStatistics struct {
	FieldsScanned             int `json:"fields_scanned,omitempty"`
	EntitiesDetected          int `json:"entities_detected,omitempty"`
	EntitiesRedacted          int `json:"entities_redacted,omitempty"`
	EntitiesAllowed           int `json:"entities_allowed,omitempty"`
	FalsePositiveOverrideCount int `json:"false_positive_override_count,omitempty"`
}

type EndOfSessionAttestation struct {
	EnclaveType           string    `json:"enclave_type"`
	Measurement           string    `json:"measurement"`
	MeasurementMatchesStart bool    `json:"measurement_matches_start"`
	Timestamp             Timestamp `json:"timestamp"`
	Signature             string    `json:"signature,omitempty"`
}

type ProcessingError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	DocumentID string `json:"document_id,omitempty"`
}

type AuditEvent struct {
	Schema             string             `json:"$schema"`
	DSPVersion         string             `json:"dssp_version"`
	EventID            string             `json:"event_id"`
	PreviousEventHash  *HashDigest        `json:"previous_event_hash,omitempty"`
	EventHash          HashDigest         `json:"event_hash"`
	SequenceNumber     int64              `json:"sequence_number"`
	Timestamp          Timestamp          `json:"timestamp"`
	EventType          string             `json:"event_type"`
	Actor              AuditActor         `json:"actor"`
	Subject            *AuditSubject      `json:"subject,omitempty"`
	Action             map[string]interface{} `json:"action"`
	Outcome            AuditOutcome       `json:"outcome"`
	ViolationDetails   *ViolationDetails  `json:"violation_details,omitempty"`
	GatewayReceivedAt  Timestamp          `json:"gateway_received_at,omitempty"`
}

type AuditActor struct {
	Type    string `json:"type"` // owner, agent, consumer, gateway, system
	OrgID   string `json:"org_id,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	UserID  string `json:"user_id,omitempty"`
}

type AuditSubject struct {
	Type           string       `json:"type,omitempty"`
	ManifestID     string       `json:"manifest_id,omitempty"`
	ContractID     string       `json:"contract_id,omitempty"`
	SessionID      string       `json:"session_id,omitempty"`
	ResultID       string       `json:"result_id,omitempty"`
	DocumentIDs    []string     `json:"document_ids,omitempty"`
	DocumentHashes []HashDigest `json:"document_hashes,omitempty"`
}

type AuditOutcome struct {
	Status          string `json:"status"` // success, failure, partial, denied
	ErrorCode       string `json:"error_code,omitempty"`
	ErrorMessage    string `json:"error_message,omitempty"`
	PIIExposure     string `json:"pii_exposure,omitempty"`
	DocumentsTouched int   `json:"documents_touched,omitempty"`
	DataEgressBytes int64  `json:"data_egress_bytes,omitempty"`
	DurationMs      int    `json:"duration_ms,omitempty"`
}

type ViolationDetails struct {
	ViolationType   string                 `json:"violation_type,omitempty"`
	Severity        string                 `json:"severity,omitempty"`
	Description     string                 `json:"description,omitempty"`
	Evidence        map[string]interface{} `json:"evidence,omitempty"`
	AutoActionTaken string                 `json:"auto_action_taken,omitempty"`
}

type DSPError struct {
	Error      string `json:"error"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	Details    string `json:"details,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	Timestamp  string `json:"timestamp"`
}

type CreateSessionRequest struct {
	ContractID  string           `json:"contract_id"`
	ManifestID  string           `json:"manifest_id"`
	Attestation *SessionAttestation `json:"attestation,omitempty"`
	AgentOrgID  string           `json:"agent_org_id,omitempty"`
	AgentID     string           `json:"agent_id,omitempty"`
}

type SessionAttestation struct {
	EnclaveType              string      `json:"enclave_type"`
	Measurement              string      `json:"measurement,omitempty"`
	AgentHash                *HashDigest `json:"agent_hash,omitempty"`
	Timestamp                Timestamp   `json:"timestamp,omitempty"`
	Signature                string      `json:"signature,omitempty"`
	RawQuote                 string      `json:"raw_quote,omitempty"`                  // Base64 raw hardware quote (SGX DCAP, Nitro COSE_Sign1)
	PlatformCertificateChain []string    `json:"platform_certificate_chain,omitempty"` // Certificate chain for verification
}

type CreateSessionResponse struct {
	SessionID string       `json:"session_id"`
	Token     *ScopedToken `json:"token"`
	Manifest  *Manifest    `json:"manifest,omitempty"`
	ExpiresAt Timestamp    `json:"expires_at"`
}

type HeartbeatRequest struct {
	Attestation *SessionAttestation `json:"attestation,omitempty"`
	Status      string             `json:"status,omitempty"`
	Metrics     map[string]interface{} `json:"metrics,omitempty"`
}

type HeartbeatResponse struct {
	Acknowledged bool      `json:"acknowledged"`
	NextDeadline Timestamp `json:"next_deadline,omitempty"`
}

type CompleteSessionRequest struct {
	ResultID string `json:"result_id,omitempty"`
	Status   string `json:"status,omitempty"` // completed, failed
	Reason   string `json:"reason,omitempty"`
}

type GrantAccessRequest struct {
	SessionID          string              `json:"session_id"`
	DocumentIDs        []string            `json:"document_ids"`
	Operations         []string            `json:"operations"`
	TTLSeconds         int                 `json:"ttl_seconds"`
	EnclaveAttestation *SessionAttestation `json:"enclave_attestation,omitempty"`
}

type GrantAccessResponse struct {
	Token         *ScopedToken      `json:"token"`
	PresignedURLs map[string]string `json:"presigned_urls,omitempty"`
}

type ContractUpdateRequest struct {
	Status           string    `json:"status,omitempty"`
	RevocationReason string    `json:"revocation_reason,omitempty"`
	Version          *int      `json:"version,omitempty"`
}

type DSPConfiguration struct {
	DSPVersion            string    `json:"dssp_version"`
	GatewayID             string    `json:"gateway_id"`
	Endpoints             Endpoints `json:"endpoints"`
	SupportedEnclaveTypes []string  `json:"supported_enclave_types"`
	StorageAdapters       []string  `json:"storage_adapters"`
	AttestationMode       string    `json:"attestation_mode"` // simulated, verify
	Features              []string  `json:"features"`
}

type Endpoints struct {
	Manifests string `json:"manifests"`
	Contracts string `json:"contracts"`
	Sessions  string `json:"sessions"`
	Audit     string `json:"audit"`
	Storage   string `json:"storage"`
}

func NowUTC() Timestamp {
	return time.Now().UTC().Format(time.RFC3339)
}

func FutureUTC(d time.Duration) Timestamp {
	return time.Now().UTC().Add(d).Format(time.RFC3339)
}
