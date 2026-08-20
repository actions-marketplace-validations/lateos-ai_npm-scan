# AGENTS.md

## Project
ESM Node.js CLI monorepo for @lateos/npm-scan supply chain scanner.

## Repos
- **GitHub (oss):** `origin` → `https://github.com/lateos-ai/npm-scan.git` — public npm package `@lateos/npm-scan`
- **Premium:** `/Users/leochong/Projects/npm-scan-premium` — private premium feature repo (license-gated features: SIEM, PDF, SSO, etc.)

## Verification
Run `npm test` (243 tests), `npm run test:coverage` (85%+), `npm run lint`, `npm run build`.

## Architecture
- `cli/`: Commander.js entrypoints
- `backend/`: Core logic, detectors (ATK-001 to ATK-011), db/schema.sql
- `backend/detectors/`: 11 ATK detectors + tier-1 suite (D1–D6c, D24–D25) + campaign detectors + index.js routing
- `backend/siem/`: SIEM exporters (CEF, ECS, Sentinel, QRadar)
- `backend/license.js`: HMAC-signed license key generation/validation
- `backend/db.js`: SQLite via sql.js (WASM, no native deps)
- `backend/fetch.js`: npm registry fetch + tarball extraction
- `backend/report.js`: HTML + text report generation
- `backend/cra.js`: EU CRA compliance report
- `backend/sbom.js`: CycloneDX + SPDX SBOM
- `backend/pdf.js`: PDF report generation (premium)
- `backend/policy.js`: YAML/JSON policy-as-code engine
- `test/`: 270 tests across 13 files (db, detectors-edge-cases, detectors-corpus, report, policy, cli, fetch, tier1-bun-runtime-swap, tier1-split-dynamic-payload, tier1-lifecycle-hook-followthrough, tier1-version-backfill, tier1-infostealer-identity-recon)
- `test/fixtures/`: Shared mock data for test suites
- `tests/corpus/`: 33 malicious + 50 clean tarballs for integration testing
- `deploy/helm/`: Kubernetes Helm chart (enterprise)
- `docker/`: Multi-arch Docker images (cli, pipeline)

## Detector Registry

### Tier 1 Detectors

| ID | File | Finding ID | Campaign Coverage |
|---|---|---|---|
| D1 | `tier1-typosquat.js` | `TIER1-TYPOSQUAT` | Typosquatting, edit-distance spoofing |
| D2 | `tier1-infostealer.js` | `TIER1-INFOSTEALER` | AI-generated infostealers, GitHub PAT harvesting, named malware signatures, identity/credential-adjacent path recon |
| D3 | `tier1-lifecycle-hook.js` | `TIER1-LIFECYCLE-HOOK` | Obfuscated install scripts, env exfiltration |
| D3b | `tier1-lifecycle-hook-followthrough.js` | `TIER1-HOOK-FOLLOWTHROUGH` | Hook indirection to referenced files (node/sh/bash), 2-level chain followthrough |
| D4 | `tier1-binary-embed.js` | `TIER1-BINARY-EMBED` | Bun runtime abuse, IMDSv2/ECS credential targeting |
| D5 | `tier1-metadata-spoof.js` | `TIER1-METADATA-SPOOF` | Namespace spoofing, cloned repo URLs, Yandex alias pattern |
| D6a | `tier1-version-confusion.js` | `TIER1-VERSION-CONFUSION` | Sentinel versions (99.99.99 family), high-version heuristic (major≥9) |
| D6b | `tier1-multistage-postinstall.js` | `TIER1-MULTISTAGE-POSTINSTALL` | Two-stage download+exec, detached background persistence |
| D6c | `tier1-cloud-imds.js` | `TIER1-CLOUD-IMDS` | GCP metadata server, Azure IMDS endpoint targeting |
| D6d | `tier1-version-backfill.js` | `TIER1-VERSION-BACKFILL` | Version history backfill in single publish burst to fake maturity |
| D24 | `tier1-bun-runtime-swap.js` | `D24-BUN-RUNTIME-SWAP` | Bun runtime swap (spawn, API usage, process.argv), bun downloader, credential combo, node-to-bun evasion (Miasma/Hades campaign) |
| D25 | `tier1-split-dynamic-payload.js` | `D25-SPLIT-DYNAMIC-PAYLOAD` | Split/dynamic payload assembly, sys.path manipulation, eval+fetch chains, buffer assembly, multifile traversal (Miasma/Hades campaign) |
| D28 | `tier1-ai-slop-dropper.js` | `D28-AI-SLOP-DROPPER` | README-directed `require()`/`import` entry with no lifecycle hooks, hex/base64 string-array obfuscation + decoder, per-literal entropy, `process.platform`/`arch` fingerprinting scope-coupled to network calls, DNS TXT out-of-band stage-2 resolution ("AI Slop"/WEL1DROPPER 800-package campaign) |

### Calibration Notes

- **D6a heuristic** (`major >= 9 && minor >= 5 && patch >= 5`, `major !== 1`): known FP risk area. Tune confidence thresholds once production scan telemetry is available.
- **D2 named signatures**: zero-FP string literals for confirmed malware campaigns. Safe to add new entries without score recalibration.
- **D24/D25 pattern weights**: calibrated against Miasma/Hades campaign artifacts. Tune `bun_api_usage` and `buffer_assembly` weights once broader scan telemetry is available, as these patterns may appear in legitimate Bun-based tooling.
- **D3b hook followthrough**: Only fires on `node <path>` / `sh <path>` / `bash <path>` hooks with no inline eval/URL/exec. Chains up to 2 levels. Reuses `lib/obfuscation-check.js` for entropy/obfuscation scoring.
- **D6d version backfill**: Requires >= 8 versions, < 24h spread, wide version range (major span >= 1 or >= 4 unique minors). Calibrated against npm-package-logger-2026 campaign.
- **Serverless PaaS watchlist** (`*.run.app`, `*.web.app`, `*.vercel.app`, `*.netlify.app`, `*.workers.dev`): MEDIUM contributing signal (+15 confidence boost), not standalone critical. Hooks into D2 infostealer and D3b hook-followthrough.
- **D28 anchor signals**: a finding requires one of `dns_payload_assembly`, `dns_txt_oob`, or `encoded_string_array`. Everything else (fingerprint/network coupling, entropy, README lure, PaaS host, bare fingerprint) only modulates severity. This gate is load-bearing: without it Next.js flags critical (its dev server couples `process.platform` with network code) and prettier flags critical (HTML attribute tables at 4.76 bits + arrays of camelCase identifiers). Both are clean at the current calibration.
- **D28 entropy calibration** (measured on the clean corpus, reputable bail defeated): the campaign write-up's suggested 4.5-bit threshold is too low — 1,050 clean literals of >= 64 chars exceed it. `entropy_threshold` is 5.0 at `min_literal_length` 64; random base64 payloads score 5.0–5.4. Separately, a base64 *shape* test matches ordinary identifiers (`doExpressions`, `RegExpLiteral`), so encoded literals must also clear `base64_min_entropy` (4.5) — of 12,708 base64-shaped clean literals only 43 do.
- **D28 DNS safelist**: `dns_txt_oob` is suppressed for packages matching `network_utility_safelist`/`network_utility_keywords` (DNS, SPF, DKIM, ACME, mail tooling). `dns_payload_assembly` is never suppressed — decoding TXT records into an execution sink is not legitimate even for a mail utility.
- **D28 performance**: a regex prefilter runs before any parsing, so only ~1.3% of corpus JS files reach acorn. Worst case (reputable bail defeated across the whole corpus) is ~1.15 s against a ~30 s full-pipeline pass, i.e. 3.8%; with normal exemptions the delta is inside run-to-run noise. Files over `max_file_bytes` (512 KB) are skipped, as are non-`.js`/`.mjs`/`.cjs` files (TypeScript sources fail to parse and are dropped silently). Slowest single package in the corpus is Next.js at ~484 ms (3,721 files) against `runTier1`'s 800 ms timeout — headroom is real but not large, so re-measure before adding another AST walk. If new signals are added, keep the prefilter markers in sync with the AST thresholds — a mismatch silently disables the signal.

## Publishing
- Bump version: `npm version patch && git push origin main --tags`
- GitHub Actions auto-publishes via `.github/workflows/publish.yml` with Sigstore provenance attestation (on tag push `v*.*.*`)
- Requires `NPM_TOKEN` secret in GitHub repo (granular access token with read-and-publish scope for `@lateos/npm-scan`)
- Manual fallback: `npm publish --access public` (no provenance when publishing locally)
- Remote: `backup` → `/Volumes/Untitled/npm-scan.git` (FAT32 thumb drive)

## Conventions
- ESM modules, Node.js native test runner
- No native deps (sql.js WASM instead of better-sqlite3)
- Node >= 18 required
- License-gated premium: all code public, HMAC-signed `license.js` gates premium features
- Follow project-plan.md phases/ATK taxonomy
- Security vulns reported via GitHub Private Vulnerability Reporting (see `SECURITY.md`)
