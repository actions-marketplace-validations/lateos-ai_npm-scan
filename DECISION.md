# DECISION.md

Log of standing architectural and product decisions, with rationale, so they aren't re-litigated or accidentally reversed. Append new entries at the top; don't delete old ones (mark superseded instead).

## Licensing model: Apache-2.0 core + Commons Clause premium
**Decision:** Open-core model — static analysis engine, ATK-001–007 detectors, CLI, lockfile scanner, SBOM (CycloneDX), GitHub Action, Docker images, and basic HTML report are Apache-2.0. Dynamic sandbox, advanced compliance reports, SIEM connectors, reachability analysis, team dashboard, SSO, audit logs, and API/webhooks are premium (Apache-2.0 + Commons Clause), gated by a runtime-validated license key.
**Why:** Commons Clause is lighter-weight than BSL and avoids the community friction HashiCorp/Elasticsearch hit with BSL transitions. The boundary ("you may not sell this software as a service") is unambiguous. BSL is a fallback only if legal counsel recommends it.
**Source:** `docs/project-plan.md` §3, `LICENSING.md`

## SQLite via sql.js (WASM), not better-sqlite3
**Decision:** Use `sql.js` for local SQLite storage instead of `better-sqlite3` or other native bindings.
**Why:** No native deps — keeps the CLI installable everywhere (including restrictive CI/sandbox environments) without a compiler toolchain or platform-specific binaries.
**Source:** `AGENTS.md` Conventions

## Premium features ship as public code, gated by license key
**Decision:** All code (including premium features) stays in the public repo; `backend/license.js` uses HMAC-signed keys to gate premium functionality at runtime rather than splitting into a closed-source repo for the gated logic itself.
**Why:** Keeps a single codebase, simplifies review/audit, and matches the Commons Clause licensing boundary (the restriction is on commercial SaaS resale, not code visibility). Premium *packaging* (e.g. PDF, SSO) still lives in a separate private repo (`npm-scan-premium`) per `AGENTS.md`.
**Source:** `AGENTS.md` Conventions

## ATK taxonomy is the detection moat — versioned and governed
**Decision:** Publish and maintain a versioned Attack Taxonomy (`docs/attack-taxonomy.md`) that every detector maps to. New ATK entries require a PR with proof-of-concept sample, detection rule, false-positive analysis, and NIST 800-161 control mapping.
**Why:** Anchors detector development and marketing claims to something rigorous and auditable, rather than ad hoc pattern-matching; differentiates from CVE-only tools (npm audit, Snyk).
**Source:** `docs/project-plan.md` §2

## ESM-only, Node >= 18
**Decision:** Package is `"type": "module"`, targets Node.js >= 18, uses the native Node test runner (`node --test`) rather than Jest/Mocha.
**Why:** Simpler toolchain, no transpilation step, no extra test-runner dependency.
**Source:** `package.json`, `AGENTS.md` Conventions
