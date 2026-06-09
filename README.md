# npm-scan

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![License](https://img.shields.io/badge/license-MIT%20OR%20BLA-blue?style=flat-square)](LICENSING.md) [![Tests](https://img.shields.io/badge/tests-830%2B%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)

**Supply chain threat detection that catches what npm audit, Snyk, and Socket miss.**

Detects obfuscated payloads, credential stealers, kernel rootkits, eBPF hooks, memory extraction, GitHub spoofing, and AI-targeted attacks.

---

## Why npm-scan?

**Traditional tools are outdated.** npm audit checks CVE databases. Snyk scans dependency versions. Neither catches behavioral patterns.

**The 2026 wave of attacks:**
- eBPF kernel rootkits (invisible to monitoring)
- Memory-level credential extraction (OIDC tokens)
- Self-defending code (anti-debugging, anti-tampering)
- GitHub author spoofing ("claude@users.noreply.github.com")
- AI platform targeting (Claude, OpenAI, Cursor, Mistral keys)
- Worm-like propagation (auto-republish with stolen tokens)

npm-scan detects all of these. **95%+ confidence on real campaigns.**

---

## What It Detects

| Category | Examples | Detection |
|----------|----------|-----------|
| **Credential Theft** | Env var harvesting, token exfiltration | 98% |
| **Kernel Attacks** | eBPF rootkits, privilege escalation | 95% |
| **Code Evasion** | Obfuscation, self-defending code, anti-debug | 95% |
| **Memory Extraction** | OIDC token access, AI key targeting | 95% |
| **GitHub Attacks** | Author spoofing, force-push hijacking | 99% |
| **Worm Propagation** | Auto-republish via stolen credentials | 95% |

---

## Quick Start

```bash
# Install
npm install -g @lateos/npm-scan

# Scan a package with known vulnerabilities
npm-scan axios

# Scan your lockfile
npm-scan scan-lockfile

# Export findings to JSON
npm-scan express --json > findings.json
```

---

## Key Features

- ✅ **23 detectors (D1–D25)** covering supply chain attack vectors
- ✅ **Real campaign validation** (IronWorm, Miasma, Dependency Confusion)
- ✅ **Runs locally** — no telemetry, no cloud dependency
- ✅ **Fast** — <30 seconds per CI/CD run
- ✅ **Policy-as-code** — YAML allowlists, severity overrides
- ✅ **SBOM + SARIF** — CycloneDX, SPDX, GitHub Security
- ✅ **GitHub Action** — One-liner CI/CD integration
- ✅ **Docker** — Multi-arch images

**Learn more:** [lateos.ai/npm-scan](https://lateos.ai/npm-scan)

---

## GitHub Action

```yaml
- uses: lateos-ai/npm-scan@v1
  with:
    scan-type: lockfile
    fail-on: critical
```

See [GitHub Action docs](#) for full configuration.

---

## Licensing

**Free (MIT):** Solo founders, non-profits, students, open-source projects.
**Paid (BLA):** Companies with employees.

See [LICENSING.md](LICENSING.md) for details.

**Enterprise?** [Get a commercial license](https://lateos.ai/npm-scan/licensing) — flexible pricing, volume discounts available.

---

## More

- [Full documentation](https://github.com/lateos-ai/npm-scan)
- [Attack taxonomy (ATK series)](https://github.com/lateos-ai/npm-scan/blob/main/DETECTORS.md)
- [Campaign validation data](https://github.com/lateos-ai/npm-scan/blob/main/VALIDATION.md)

---

**Scan your first package:**

```bash
npx @lateos/npm-scan scan axios
```
