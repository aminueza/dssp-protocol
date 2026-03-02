# DSSP Conformance Test Suite

Behavioral conformance tests for the Document Sovereignty Protocol & Privacy.

## Running Tests

```bash
# Install dependencies
pip install -e .

# Run all tests
pytest

# Run by conformance level
pytest -m core          # DSSP Core tests
pytest -m attested      # DSSP Attested tests
pytest -m ai_safe       # DSSP AI-Safe tests
pytest -m sovereign     # DSSP Sovereign tests

# Run with coverage
pytest --cov=tests -v

# Run against a live gateway
DSSP_GATEWAY_URL=http://localhost:8080 pytest
```

## Test Levels

| Level | Tests | Description |
|-------|-------|-------------|
| DSSP Core | Schema validation, PII safety, contract enforcement, audit chain integrity | Basic protocol compliance |
| DSSP Attested | Attestation verification, end-of-session attestation, heartbeat validation | Hardware attestation requirements |
| DSSP AI-Safe | Agent type scanning, privacy budget, sub-agent chain validation, numeric precision | AI/LLM-specific safety controls |
| DSSP Sovereign | Data residency, gateway visibility, cross-engagement correlation | Full data sovereignty |
