# Contributing to DSP

Thank you for your interest in the Document Sovereignty Protocol.

## Before You Start

1. Read the [specification](spec/dsp-v0.1.md) to understand what DSP does.
2. Read the [governance model](GOVERNANCE.md) to understand how changes are reviewed.
3. Check existing [issues](https://github.com/aminueza/dssp-protocol/issues) to avoid duplicate work.

## Types of Contributions

### Specification changes

Changes to the protocol specification (`spec/`), JSON schemas (`schemas/`), or OpenAPI definition (`spec/dsp-api-v0.1.yaml`) follow the RFC process described in [GOVERNANCE.md](GOVERNANCE.md).

1. Open an issue describing the change, motivation, and impact.
2. Wait for initial feedback before writing a pull request.
3. Submit a PR against the `main` branch.
4. Allow the review period (14 days for non-breaking, 30 days for breaking changes).

### Reference implementation

Changes to the reference gateway, agent, scanner, sidecar, or test vectors (`reference/`).

1. Open an issue or find an existing one.
2. Fork the repository and create a branch from `main`.
3. Write tests for new functionality.
4. Submit a PR.

### Documentation and examples

Fixes to documentation, new examples, or improved explanations.

- Small fixes (typos, broken links): submit a PR directly.
- New sections or structural changes: open an issue first.

### Conformance tests

New test cases for the conformance suite (`reference/conformance/`).

- Each test must reference a specific section of the specification.
- Tests must pass against the reference implementation.

## Development Setup

### Prerequisites

- Go 1.22+ (gateway)
- Python 3.12+ (agent, scanner, sidecar, validator)
- Docker and Docker Compose (integration tests)

### Running the reference stack

```bash
cd reference
docker compose up --build
```

### Running conformance tests

```bash
cd reference/conformance
pip install -e ".[test]"
pytest -v
```

### Running the schema validator

```bash
cd reference/validator
pip install -r requirements.txt
python validate.py ../examples/bank-statement-extraction/
```

## Pull Request Guidelines

- One logical change per PR. Don't mix specification changes with implementation changes.
- Write a clear title: `spec: add field X to contract schema` or `gateway: fix session timeout handling`.
- Reference the issue number: `Resolves #42`.
- Keep PRs small. Large PRs take longer to review and are more likely to be rejected.
- All CI checks must pass before merge.

## Commit Messages

Use conventional commits:

```
type(scope): description

spec(contract): add sub-agent chain declaration
gateway(handler): fix numeric precision enforcement
schemas(result): add pii_bearing flag to column definitions
docs(readme): fix quick start instructions
test(conformance): add attested level test cases
```

Types: `spec`, `schemas`, `gateway`, `agent`, `scanner`, `sidecar`, `docs`, `test`, `ci`, `chore`.

## Code Style

### Go (gateway)

- `gofmt` formatting (enforced by CI)
- Follow standard Go project layout
- Use `slog` for structured logging

### Python (agent, scanner, sidecar)

- Format with `black`
- Lint with `ruff`
- Type hints on all public functions

### JSON Schemas

- Follow JSON Schema 2020-12
- Use `$defs` for shared definitions in `common.schema.json`
- Include `description` on every property

## Reporting Issues

Use the issue templates:

- **Bug report**: something doesn't work as specified
- **Feature request**: a new capability for the protocol
- **RFC**: a proposed specification change

Include enough detail to reproduce the problem or understand the proposal.

## Code of Conduct

All participants must follow the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 license.

