# DSP Conformance Test Suite

Behavioral conformance tests for the Document Sovereignty Protocol.

## Running Tests

```bash
# Install dependencies
pip install -e .

# Run all tests
pytest

# Run by conformance level
pytest -m core          # DSP Core tests
pytest -m attested      # DSP Attested tests
pytest -m ai_safe       # DSP AI-Safe tests
pytest -m sovereign     # DSP Sovereign tests

# Run with coverage
pytest --cov=tests -v

# Run against a live gateway
DSP_GATEWAY_URL=http://localhost:8080 pytest
```

## Test Levels

| Level | Tests | Description |
|-------|-------|-------------|
| DSP Core | Schema validation, PII safety, contract enforcement, audit chain integrity | Basic protocol compliance |
| DSP Attested | Attestation verification, end-of-session attestation, heartbeat validation | Hardware attestation requirements |
| DSP AI-Safe | Agent type scanning, privacy budget, sub-agent chain validation, numeric precision | AI/LLM-specific safety controls |
| DSP Sovereign | Data residency, gateway visibility, cross-engagement correlation | Full data sovereignty |
