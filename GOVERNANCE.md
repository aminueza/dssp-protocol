# DSP Governance

## How the Specification Evolves

### RFC Process

Changes to the DSP specification follow an RFC (Request for Comments) process:

1. **Proposal** — Open a GitHub issue describing the change, motivation, and impact.
2. **Draft** — Submit a pull request with the proposed specification changes.
3. **Review** — Minimum 14-day review period. At least 2 Technical Committee members must review.
4. **Vote** — Technical Committee votes. Requires majority approval.
5. **Merge** — Approved changes are merged and a new spec version is published.

### Breaking Changes

Changes that modify existing schema fields, remove features, or alter protocol behavior
require:

- 30-day review period (instead of 14)
- Unanimous Technical Committee approval
- Major version increment
- Migration guide published alongside the change

### Technical Committee

The Technical Committee (TC) is responsible for:

- Reviewing and approving specification changes
- Maintaining the conformance test suite
- Resolving disputes about protocol interpretation
- Publishing new specification versions

**Composition:** 3-5 members from different organizations.  
**Term:** 12 months, renewable.  
**Selection:** Nominated by contributors, confirmed by existing TC.

### Conformance Program

Implementations that wish to claim "DSP-compliant" must:

1. Pass the published conformance test suite for the claimed conformance level.
2. Submit test results to the DSP GitHub repository.
3. Re-certify when a new minor or major version is published.

### Code of Conduct

All participants in DSP development must follow the
[Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Licensing

- Specification: Apache 2.0
- Reference implementations: Apache 2.0
- Conformance tests: Apache 2.0

Commercial implementations may use any license, provided they comply with the
conformance requirements.

