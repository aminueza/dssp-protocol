# Changelog

All notable changes to the DSSP specification are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Specification versions follow [Semantic Versioning](https://semver.org/).

## [0.1.3] - 2026-02-27

### Added
- Multi-model composition: sub-agent chain attestation
- Numeric precision policy to prevent steganographic exfiltration
- Sub-agent policy in contract consumer section

## [0.1.2] - 2026-02-26

### Added
- AI agent type declarations (structured, ml_structured, llm_freeform)
- Result scanning requirements (regex, NER, statistical)
- Privacy budget controls (k-anonymity, differential privacy)
- Document sanitization policy for prompt injection defense
- Sidecar verifier specification
- End-of-session attestation

### Changed
- Enclave type "none" restricted to public sensitivity only
- Gateway operates in split-knowledge mode (metadata only)

## [0.1.1] - 2026-02-25

### Added
- Reference implementation (Go gateway, Python agent)
- Conformance test suite (Core, Attested, Sovereign levels)
- PII scanner (regex, NER, statistical backends)
- Test vectors for canonical JSON, Merkle chain, hash computation

## [0.1.0] - 2026-02-24

### Added
- Initial specification draft
- Document Manifest schema
- Processing Contract schema
- Result Envelope schema
- Audit Event schema
- Storage Binding schema
- Common definitions schema
- OpenAPI 3.1 definition
- Bank statement extraction example
