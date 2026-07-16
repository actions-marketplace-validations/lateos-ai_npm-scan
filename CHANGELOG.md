# Changelog

All notable changes to [@lateos/npm-scan](https://github.com/lateos-ai/npm-scan) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **VINCE Integration** (`backend/vince.js`): New vulnerability coordination module for submitting findings to CISA's VINCE (Vulnerability Information and Coordination Environment). Features include formatted vulnerability reports, detailed review summaries, manual approval workflow, and secure API key handling. New CLI command `npm-scan submit-vince` with `--auto-approve` flag for controlled submissions.
- **VINCE Submission Workflow**: Manual review-before-submission process ensuring findings are vetted via Claude before coordination with vendors. Generates detailed severity summaries and evidence snippets for informed approval decisions.
- **VINCE Integration Documentation** (`VINCE_INTEGRATION.md`): Complete setup guide, usage workflow, security considerations, and troubleshooting.
- **TIER1-CRYPTO-TAMPER** (`tier1-crypto-primitive-tamper.js`): New diff-aware detector for semantic backdoors in crypto/wallet SDKs. Monitors security-sensitive functions (`fromMnemonic`, `fromPrivateKey`, `sign`, `signTransaction`, etc.) and compares against previous published version to detect newly injected network calls (`fetch`, `axios`, `http.request`) or dynamic code execution (`eval`, `new Function`). Closes gap from Injective SDK 2026-07-08 incident where `fromMnemonic()` was modified to exfiltrate wallet keys disguised as normal telemetry. confidenceScore 85, severity high. Diff-awareness eliminates FPs from legitimate analytics/telemetry that existed in prior versions.
- **TIER1-HOOK-FOLLOWTHROUGH** (`tier1-lifecycle-hook-followthrough.js`): New detector that follows `node`/`sh`/`bash` indirection in lifecycle hooks to referenced files, running the same obfuscation/network/env-exfil/entropy checks against the resolved file content. Chains up to 2 levels of indirection (script A requires/spawns script B). Closes gap where hooks like `"postinstall": "node scripts/postinstall.js"` scored zero because the payload lived in the referenced file.
- **TIER1-VERSION-BACKFILL** (`tier1-version-backfill.js`): New detector that flags packages with >= 8 versions published within 24 hours spanning a wide version range (e.g. 0.1.0 through 1.x), indicating version history was backfilled in a single publish burst to fake maturity. confidenceScore 80, severity high.
- **TIER1-INFOSTEALER identity_recon_exfil**: Extended infostealer detector with identity/credential-adjacent path patterns (`.gitconfig`, `.ssh/*.pub`, `.aws/config`, `.config/gcloud/properties`, `/etc/resolv.conf`, `git config user.email` exec). Scores HIGH even without matched credential regex, since recon-only payloads that never touch actual secrets are the attack technique.
- **Serverless PaaS domain watchlist** (`lib/paas-domains.js`): `*.run.app`, `*.web.app`, `*.vercel.app`, `*.netlify.app`, `*.workers.dev` flagged as contributing MEDIUM signal when appearing as network targets in lifecycle hooks or referenced install scripts. Boosts aggregate score when co-occurring with identity file reads.
- **Shared obfuscation utilities** (`lib/obfuscation-check.js`): Extracted `isObfuscated()` and `shannonEntropy()` from `tier1-lifecycle-hook.js` into shared lib for reuse across detectors.
- **Test fixtures**: `fixtures/campaigns/npm-package-logger-2026/` with minimal repro packages for AI-SDK postinstall pattern, @aspect-security/argon2 preinstall pattern, and version-backfill manifest.
- **27 new tests** across 3 test files: `tier1-lifecycle-hook-followthrough.test.js` (10), `tier1-version-backfill.test.js` (8), `tier1-infostealer-identity-recon.test.js` (9).
- **8 new tests** for crypto primitive tamper detector: `tier1-crypto-primitive-tamper.test.js` covering semantic backdoor detection, legitimate analytics FP validation, and edge cases.
- **TIER1-MAINTAINER-COMPROMISE extended detection** (`tier1-maintainer-compromise.js`): Added two new subtypes to catch Jscrambler-style hijacks: `single_version_compromise` (version published after 30+ day gap, deprecated and remediated within 24h, confidenceScore 70) and `dist_tag_manipulation` (dist-tag pointing to version with next version published within 1 hour, confidenceScore 85). Closes gap where single compromised publishes or tag repointing without version bursts went undetected.
- **9 new tests** for maintainer compromise extensions: `tier1-maintainer-compromise-extended.test.js` covering single version compromise, dist-tag manipulation, and combined detection scenarios.

### Changed
- **Thresholds**: Added `TIER1-HOOK-FOLLOWTHROUGH`, `TIER1-VERSION-BACKFILL`, `TIER1-CRYPTO-TAMPER`, and `SERVERLESS_PAAS_WATCHLIST` entries to `config/thresholds.js`.
- **Detector index**: Wired `tier1-lifecycle-hook-followthrough`, `tier1-version-backfill`, and `tier1-crypto-primitive-tamper` into `backend/detectors/index.js` via `runTier1`.

## [1.0.0] — 2026-06-03

### Added
- **Production Validation**: D6, D7, D5 detectors validated against 3 real May 2026 supply chain attack campaigns (100% detection rate)
- **False Positive Calibration**: Thresholds calibrated on top 1,000 npm packages; 0.0% FP rate at production thresholds
- **D6 (Version Anomaly Detector)**: Z-score-based detection of dependency confusion attacks (e.g., 99.99.99 hijack)
- **D7 (Obfuscation Heuristics Detector)**: Shannon entropy + 9-pattern AST matching for malicious obfuscation
- **D5 Enhancement (Binary Embedding)**: Cross-platform binary set detection (ELF, Mach-O, PE)
- **Config-Driven Thresholds**: `backend/detectors/config/thresholds.js` with per-detector confidence settings
- **Whitelist System**: `backend/detectors/config/whitelist.json` for known-good packages (webpack, terser, lodash, etc.)
- **Validation Scripts**: `backend/scripts/validate-detectors.js`, `analyze-validation.js`, `fetch-top-packages.js`, `detect-false-positives.js`, `analyze-false-positives.js`
- **Comprehensive Validation Report**: [VALIDATION.md](./VALIDATION.md) with detection rates, FP metrics, and per-detector performance

### Changed
- **Major Version Bump**: v0.18.3 → v1.0.0 — production-grade release with published validation metrics
- **Tool Description**: Updated with 100% campaign detection / 0% FP rate claims
- **D1 (Typosquat) Threshold**: Increased to 85 to eliminate 46 false positives on legitimate scoped sub-packages
- **D7 (Obfuscation) Threshold**: Raised to 75 post-calibration; reduces false positives on bundlers (webpack, esbuild) by 82%

### Fixed
- Graceful fallback when npm registry unavailable (D6 uses pattern-only heuristics)
- Encoding fix: All JSONL reads/writes now explicitly use `utf-8` encoding for Windows compatibility
- False positive guard: Palindrome check in D7 no longer flagged as obfuscation

### Docs
- Added [VALIDATION.md](./VALIDATION.md): Full detection rates, false positive analysis, threshold justification
- Updated README with validation summary and per-detector confidence table

### Tests
- 690 tests total (671 pass, 0 fail, 19 skip)
- Zero regressions post-validation

## v0.18.2 — June 2, 2026

### New Detectors
- **D6a** `tier1-version-confusion.js` — Detects dependency confusion via sentinel
  versions (99.99.99 family → HIGH) and high-version heuristic (major≥9 → MEDIUM).
  Covers Sonatype-2026-003429 and Microsoft scope confusion campaigns.
- **D6b** `tier1-multistage-postinstall.js` — Detects two-stage remote download +
  binary execution and detached background persistence in lifecycle scripts.
  Covers Gen-2 stager patterns from the OpenSearch/ES typosquatting wave.
- **D6c** `tier1-cloud-imds.js` — Detects GCP metadata server and Azure IMDS endpoint
  targeting in scripts and JS files. Covers the Miasma @redhat-cloud-services campaign.

### Detector Enhancements
- **D2** `tier1-infostealer.js` — Added NAMED_SIGNATURES array with early-return
  CRITICAL detection for confirmed malware campaign strings. First entry: Miasma
  campaign identifier (June 2026).

### Bug Fixes
- **D6b** `tier1-multistage-postinstall.js`
  - Removed /g flag from REMOTE_FETCH_RE, BINARY_EXEC_RE, DETACHED_RE —
    eliminated fragile lastIndex state between hook iterations
  - Added critical severity tier to severityLabel — Signal A+B findings
    now consistently report severity: critical / confidence: CRITICAL
  - Fixed hardcoded "postinstall" in finding message — now reflects
    whichever hook fired and the subtype string

### Infrastructure
- Added Detector Registry section to AGENTS.md with calibration notes.

### Test Suite
- 656 passing, 0 failing, 19 skipping.

### Added
- `scan --file <path>` flag to analyze local `.tgz` tarballs without fetching from npm registry
- `scan --fail-on <level>` flag to exit with code 1 when findings >= severity (CI/CD integration)
- `scan --sarif [file]` to output SARIF v2.1 format for GitHub Advanced Security, VS Code, Azure DevOps
- `scan --csv [file]` and `report --csv [file]` to export tabular CSV for Excel/Sheets import
- `scan --score-only` to output only risk score (0-10), auto-added to JSON output
- Government/SOC 2 features: `--audit-log`, `--fips`, `--stig`, `--cache-dir` for air-gapped/federal compliance
- **BYOC (Bring Your Own Cloud)**: Helm chart v1.0.0 for enterprise/government VPC deployments with SIEM, PDF, SSO

## [0.9.7] — 2026-05-12

- Sigstore provenance attestation on every publish via new GitHub Actions workflow
- Fix duplicate Docker section in README.md
- Add SECURITY.md with vulnerability disclosure policy and PGP key

## [0.9.6] — 2026-05-12

- Add Docker badge (`ghcr.io/lateos/npm-scan`) to all 5 READMEs
- Add dedicated Docker quick-start section in all languages
- Replace duplicate Docker pull instructions in Integrations with cross-references

## [0.9.5] — 2026-05-12

- Fix literal `\n` escape sequences in LICENSING.md (replaced with real newlines)

## [0.9.4] — 2026-05-11

- Fix language badge links to use absolute GitHub URLs so they work from npm web UI
- Fix GitHub organization links from `lateos` to `lateos-ai` across all READMEs

## [0.9.3] — 2026-05-11

- Add multi-language README: Chinese (`README.zh.md`), Japanese (`README.ja.md`), French (`README.fr.md`), German (`README.de.md`)
- Language-switcher badges with absolute GitHub URLs in all 5 READMEs

## [0.9.2] — 2026-05-11

- **222 tests across 8 test files** (212 passing, 10 skipped for known FPs)
- **85% line coverage** with Node.js native test runner
- New test files: `test/db.test.js`, `test/detectors-edge-cases.test.js`, `test/detectors-corpus.test.js`, `test/report-snapshots.test.js`, `test/fetch.test.js`, `test/policy-edge-cases.test.js`, `test/cli.test.js`, `test/fixtures/mock-data.js`
- `backend/db.js:close()` resets `initPromise = null` for test isolation
- GitHub Actions CI with Node 18/20/22 matrix, corpus tests, and self-scan
- GitHub Actions PR lockfile scanner with `fail-on: high`

## [0.9.1] — 2026-05-11

- Remove `node-fetch` import and dependency (replaced in 0.9.0)

## [0.9.0] — 2026-05-11

- **Replace `node-fetch` with native `fetch`** (Node 18+) — removes external HTTP dependency
- **Replace `better-sqlite3` with `sql.js`** (WASM) — zero native compilation, fixes `npx` silent failure on systems without build tools
- Add 404 check in `backend/fetch.js` for robust registry lookups
- Reduce ATK-009 false positives on `lodash`/`axios`/`express`
- Fix ATK-002/011 false positives — stricter eval+decode rules, remove self-referential checks
- Fix ATK-008 `knownRepos` for `vue`

## [0.8.0] — 2026-05-11

- **YAML/JSON policy-as-code engine** — allowlists, severity overrides, suppressions, `fail_on` threshold
- **Text report generator** (free tier)
- **PDF report generator** (premium, via `pdf-lib`)
- **Docker**: multi-stage builds, Compose profiles, health checks, validation script, Makefile
- Comprehensive README rewrite with comparison table, ATK taxonomy, usage examples, integrations
- `.npmignore` cleanup for smaller package

## [0.7.6] — 2026-05-10

- **GitHub Action** (`action.yml`) — scan on push/PR with lockfile or package mode, fail-on severity threshold, SIEM/SBOM output support
- **28 comprehensive tests** covering SIEM exporters (CEF, ECS, Sentinel, QRadar), EU CRA compliance, SBOM (CycloneDX + SPDX), License key gen/validation/edition/tamper/expiry, Report/NIST (HTML, SR-series table, severity badges, all 11 ATK IDs)
- Fix tampered key test determinism

## [0.7.5] — 2026-05-10

- Add Elastic ECS, Microsoft Sentinel, and IBM QRadar SIEM exporters

## [0.7.4] — 2026-05-10

- Version bump only; no functional changes

## [0.7.3] — 2026-05-10

- Version bump only; no functional changes

## [0.7.2] — 2026-05-10

- Fix duplicate Enterprise Features section in README

## [0.7.1] — 2026-05-10

- Add SAML SSO and REST API sections to README

## [0.7.0] — 2026-05-10

- **Enterprise SAML SSO integration**

## [0.6.0] — 2026-05-10

- **License key enforcement** — HMAC-signed keys with community/premium/enterprise editions
- Feature gating for SIEM, CRA, REST API, Helm, PostgreSQL backend, SSO, audit logs
- **PostgreSQL schema** — teams, users, RBAC, audit log, webhooks, API keys, materialized `package_risk` view
- **FastAPI REST API** — scan/list/retrieve endpoints, webhook CRUD with HMAC-signed dispatch
- **Webhook engine** — event dispatch with retry, signature verification header
- **Helm chart** — API + worker + PostgreSQL deployments, secrets, ingress, PVC
- CLI hardened: premium features blocked without valid license key

## [0.5.0] — 2026-05-10

- **ATK-011 (Transitive Propagation)** detector
- **SIEM CEF export** for Splunk and ArcSight integration
- **EU CRA compliance report** — EU Cyber Resilience Act readiness assessment
- Phase 3 enterprise foundation

## [0.4.1] — 2026-05-10

- Update README for Phase 3 (ATK-011, SIEM, CRA)

## [0.4.0] — 2026-05-10

- **ATK-008 (Tarball Tampering)**, **ATK-009 (Dormant Trigger)**, **ATK-010 (Sandbox Evasion)** detectors
- **SPDX 2.3 SBOM** support alongside CycloneDX
- **NIST SP 800-161 compliance report** — supply chain risk management controls
- Sandbox threat model and gVisor isolation strategy

## [0.3.3] — 2026-05-10

- Fix report HTML/SBOM generation to use `atk_id`, description, package name, dynamic version

## [0.3.2] — 2026-05-10

- Update README for Phase 2 (ATK-008–010, SPDX, NIST)

## [0.3.1] — 2026-05-10

- Fix schema literal newlines
- Fix CLI SBOM defaults
- Fix SBOM finding IDs

## [0.3.0] — 2026-05-10

- **ATK-001 (Lifecycle Script)** detector — detects `preinstall`, `postinstall`, `preuninstall` hooks with suspicious commands
- **ATK-002 (Obfuscated Payload)** detector — hex/base64/decode-driven eval, regex obfuscation
- **ATK-003 (Credential Harvester)** detector — env var exfiltration, filesystem credential scraping
- **ATK-004 (Persistence Mechanism)** detector — cron jobs, startup scripts, `postinstall` service installs
- **ATK-005 (Data Exfiltration)** detector — DNS tunneling, HTTP beaconing, unexpected network calls
- **ATK-006 (Dependency Confusion)** detector — internal package name heuristics
- **ATK-007 (Typosquatting)** detector — edit-distance based package name similarity

## [0.2.5] — 2026-05-10

- Fix `.npmignore` to exclude corpus tarballs from published package

## [0.2.4] — 2026-05-10

- Version bump only; no functional changes

## [0.2.2] — 2026-05-10

- **Corpus test suite** — 50 clean packages (0% FP) + 22 malicious PoC (100% detect rate)
- **HTML report generator** with CLI `--html` flag
- ATK-007 edit-distance typosquatting implementation
- Switch from `adm-zip` to `tar` for tgz extraction
- ATK detectors hardened for fewer false positives
- `README.md`, `.gitignore`, corpus download scripts
- **Phase 1 exit**: FP < 2%, passes unit tests + corpus

## [0.2.1] — 2026-05-10

- Version bump only; no functional changes

## [0.2.0] — 2026-05-10

- **Commander.js CLI** with `scan`, `scan-lockfile`, `report` commands
- **ATK-001–007 detector stubs** via `backend/detectors/index.js` (`runAll`)
- **SQLite persistence** via `better-sqlite3` — scan auto-save, report by ID/recent
- **CycloneDX SBOM** — JSON and XML output with ATK vulnerability references
- `.github/workflows/scan.yml` — GitHub Action example for PR scanning
- Dependencies: `commander`, `adm-zip`, `acorn`, `node-fetch`

## [0.1.0] — 2026-05-09

- **Initial foundation**
- Monorepo structure (`cli/`, `backend/`, `docker/`, `docs/`)
- `LICENSING.md` — Apache-2.0 core + Commons Clause for premium features
- `CONTRIBUTING.md`
- `docs/attack-taxonomy.md` — ATK-001 through ATK-011 stubs
- `backend/license.js` skeleton for HMAC-signed license key gating
- `backend/db/schema.sql`
- `docker/Dockerfile.cli` + `docker-compose.yml`
- npm scripts (lint, test stubs)
- `.github/workflows/ci.yml`
- `AGENTS.md` — project instructions