# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the DSSP specification, schemas, or reference implementation, please report it responsibly.

**Do not open a public issue.**

Report via [GitHub Security Advisories](https://github.com/aminueza/dssp-protocol/security/advisories/new).

Include:

- Description of the vulnerability
- Steps to reproduce
- Which component is affected (spec, schemas, gateway, agent, scanner, sidecar)
- Potential impact

## Response Timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix or mitigation:** within 30 days for critical issues

## Scope

This policy covers:

- The DSSP specification (`spec/`)
- JSON Schemas (`schemas/`)
- OpenAPI definition (`spec/dssp-api-v0.1.yaml`)
- Reference gateway (`reference/gateway/`)
- Reference agent (`reference/agent/`)
- Scanner (`reference/scanner/`)
- Sidecar verifier (`reference/sidecar/`)
- Conformance test suite (`reference/conformance/`)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
