# Supply Chain Detection Gap Analysis & Architectural Plan — 2026

> **Audit Date:** July 2026
> **Scope:** Static analysis engine, AST rule sets, behavioral signature detectors, CLI pipeline vs. four sophisticated emerging attack vectors.

---

## 1. Native C++ Build Hook Exploitation (`binding.gyp`)

### Vulnerability Breakdown

**Current coverage:** D14 (`backend/detectors/tier1-build-config-abuse.js:1-264`) provides regex-based static analysis for `binding.gyp` content and C/C++ source files. Critical gaps remain:

| Gap | Details | Code Location |
|-----|---------|---------------|
| **No GYP semantic parsing** | `binding.gyp` uses a Python-like DSL with `<!()` shell execution syntax and conditional `'conditions'` blocks. Current regex `<!?\(.*\)` at L87 uses greedy `.*` and misses multi-line/nested shell commands inside conditionals. | `tier1-build-config-abuse.js:87` |
| **No Makefile / CMakeLists.txt / configure analysis** | Attackers embed `$(shell ...)` in Makefiles or `execute_process()` in CMake. Only `.gyp`, `.cc/.cpp/.c` are analyzed. | No coverage |
| **No preprocessor macro injection detection** | `#define` directives in headers can inject compilation-time code execution via `node-gyp rebuild`. Not checked. | No coverage |
| **Static legitimate-addon allowlist** | Only 9 packages (`node-sass`, `sqlite3`, `bcrypt`, etc.) bypass D14. Fragile and stale. | `thresholds.js:188-198` |
| **All files read as UTF-8** | Binary `.o`, `.a`, `.so` files are read as text and garbled; no magic-byte detection or ELF/COFF parsing. | `fetch.js:161-164` |
| **No shell compilation execution cross-reference** | `node-gyp rebuild` is detected via `package.json` scripts, but direct `node-gyp` invocation from lifecycle hooks is not cross-referenced with `binding.gyp` malicious content. | No linkage |
| **No `.gyp` vs `.gypi` include following** | `binding.gyp` can include `common.gypi`; included files are not analyzed recursively. | No linkage |

### Architecture Proposal

**GypAstParser — lightweight structural parser:**

```js
// backend/detectors/lib/gyp-parser.js
// No dependencies, ~100 lines, no Python eval

export function parseGyp(content) {
  const AST = { targets: [], conditions: [], variables: {}, includes: [], shellExecs: [] };
  // 1. Tokenize: extract 'targets', 'conditions', 'sources', 'variables', 'libraries'
  // 2. Extract all <!(shell_command) invocations with proper nesting awareness
  // 3. Resolve 'conditions' blocks for Python expressions (keyword-based search, no eval)
  // 4. Follow .gypi includes recursively (max depth: 2)
  return AST;
}
```

**New patterns to add to `binding.gyp` analysis:**

```js
// Compilation macro injection
/-D\s*['"]?[A-Z_]+=(system|exec|shell|popen)/g,
// Include path manipulation
/-I\s*\.\.\/\.\.\/(?:tmp|var|dev|private)/g,
// LD_PRELOAD equivalent in gyp linker settings
/linker:\s*(?:ldflags|libraries|link_settings).*['"](?:-lcurl|libcurl|-lssl)/g,
// Makefile shell exec
/\$\(shell\s+[^)]+\)/g,
// CMake execute_process
/\bexecute_process\s*\([^)]*COMMAND\b/g,
```

**NativeBuildCrossReference step (add to D14):** When lifecycle hook scripts contain `node-gyp rebuild` AND `binding.gyp` contains malicious patterns → escalate to critical severity (execution confirmation).

### Performance Impact Estimate

| Component | Cost | Trigger |
|-----------|------|---------|
| Gyp AST parser | ~0.5–2ms per package | Only when `binding.gyp` exists (<5% of npm) |
| C/C++ source extended regexes | +0.5ms per `.cc/.cpp/.c` file | Per source file found |
| Makefile/CMakeLists analysis | +1ms per additional build file | Per build file found |
| **Total (packages with native code)** | **+2–5ms** | |
| **Total (pure JS packages)** | **+0ms** | |

---

## 2. Ultra-Fast Wormable Self-Propagation Loops

### Vulnerability Breakdown

**Current state:** The scanner is purely static analysis with no runtime execution isolation or blocking.

| Gap | Details | Code Location |
|-----|---------|---------------|
| **No execution isolation** | Scanner runs in the main Node.js process. No sandbox, no VM, no container. | Entire pipeline |
| **No latency measurement** | Zero timing instrumentation in the scan pipeline. No way to measure detection-to-alert latency. | No `console.time`/`performance.now` anywhere |
| **No real-time blocking** | `--fail-on` exits the *scanner* process. Malicious code never executes because scanner never runs package code. | `cli.js:190-205` |
| **No credential canary/trap** | No honeytoken detection to alert if `.npmrc` or `.env` is accessed at install time. | No coverage |
| **D10 is retrospective only** | `tier1-self-propagation.js` analyzes registry metadata for publish bursts — after the package has already propagated to the registry. | `tier1-self-propagation.js:1-115` |
| **Sandbox doc exists, no implementation** | `docs/sandbox-threat-model.md` describes gVisor/Firecracker architecture but no implementation exists in the codebase. | No code |

**Scan execution timeline:**

```
[fetch tarball + extract] → ~200–5000ms
[run 45 detectors sequentially] → ~500–5000ms  (800ms timeout per tier-1 detector)
[post-process: score, output, policy] → ~10–50ms
───────────────────────────────────────────────
Total per package: ~700ms–10s (static analysis only)
```

Key insight: Since we never execute the package, there is no "detection-to-block" latency problem for static analysis. The gap is we cannot detect worm behavior that only manifests at runtime (credential scraping followed by immediate publish of poisoned downstream updates).

### Architecture Proposal

**Phase 1 — Proactive Static Detection of Worm-Capable Structure:**

```js
// Proposed: D10 Enhancement / new tier1-worm-propagation.js
// Static detection of patterns enabling instant self-propagation:

patterns: {
  npmrc_exfil: /(process\.env\.NPM_TOKEN|fs\.readFileSync.*\.npmrc|npm\s+(whoami|publish|token))/g,
  github_ssh_exfil: /(fs\.readFileSync.*\.ssh|fs\.readFileSync.*id_rsa|gh\s+auth)/g,
  cloud_cred_exfil: /(~\/\.aws\/credentials|~\/\.config\/gcloud|AZURE_CLIENT_ID)/g,
  self_publish: /\b(npm\s+publish|npm\s+version|npm\s+dist-tag)\b/g,
  immediate_exfil_no_delay: /(?:fetch|axios|request)\([^)]+\);?\s*(?:\n|$)/g,  // top-level await exfil
}
```

**Phase 2 — Sandbox Execution (Premium/Gated):** Implement the gVisor design from `sandbox-threat-model.md`:
- Gate behind `isFeatureEnabled('sandbox', licenseKey)` in `license.js`
- Execute package in isolated container with egress monitoring
- Capture credential access attempts via filesystem diff
- **Highest-effort item; recommend implementing in Q3 2026**

**Detection-to-alert latency target:**

| Mode | Latency | Use Case |
|------|---------|----------|
| Static detection | Sub-second | CI/CD pre-install gate |
| Dynamic (sandbox) | ~30s per package | Premium deep scan, air-gapped |


### Performance Impact Estimate

| Component | Cost | Notes |
|-----------|------|-------|
| Phase 1 (static worm regexes) | +1–2ms | 5 regexes on JS source |
| Phase 2 (sandbox) | +30s per package | Premium only, opt-in via `--sandbox` |
| Credential canary deployment | 0ms scanner impact | OS-level, outside scanner |

---

## 3. LLM/AI Agent Configuration Poisoning (`.cursorrules` / `CLAUDE.md`)

### Vulnerability Breakdown

**Current coverage:** Existing traction is minimal — trapdoor D5 detects zero-width characters only; D22 targets code files for API keys, not config files for prompt injection.

| Gap | Details | Code Location |
|-----|---------|---------------|
| **Zero-width char detection only** | Trapdoor D5 checks Unicode zero-width (U+200B–U+200D, U+FEFF) — no prompt injection content analysis. | `trapdoor/d5-ai-poisoning.js:1-37` |
| **No content semantic analysis** | No NLP/heuristic analysis of text content for manipulation patterns. | N/A |
| **D22 targets code, not config files** | `tier1-ai-token-targeting.js` only scans `.js/.mjs/.cjs/.ts` files (`isCodeFile()` L8–13). Ignores `.md`, `.json`, `.txt` config files. | `tier1-ai-token-targeting.js:8-12` |
| **No prompt injection pattern detection** | "Ignore previous instructions", system prompt overrides, manipulation directives unchecked. | N/A |
| **No hidden formatting detection** | Homoglyph characters, HTML comment injection, RTL override (U+202E), Markdown image exfiltration not checked. | D5 covers basic zero-width only |
| **No agent command injection detection** | No detection of inline shell execution instructions: `` `cmd` `` in markdown, `<!-- run: ... -->` HTML comments, `<execute>` tags. | N/A |

**Status of non-code document handling:** The scanner already reads ALL files into `allFiles` (`fetch.js:161-164`). Documents `.md`, `.json`, `.txt` are available to detectors. The gap is purely in detector logic — the data plane is ready.

### Architecture Proposal

```js
// Proposed: PromptInjectionDetector
// backend/detectors/lib/prompt-injection.js

const LLM_CONTEXT_FILES = [
  '.cursorrules',
  'CLAUDE.md',
  '.claude.md',
  '.cursor/rules/*.mdc',
  'AGENTS.md',
  '.github/copilot-instructions.md',
  '.windsurfrules',
];

const INJECTION_PATTERNS = {
  instruction_override: [
    /ignore\s+(all\s+)?(previous|above|prior)\s+instructions/i,
    /disregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions|directives|rules)/i,
    /do\s+not\s+(follow|obey|adhere\s+to)\s+(the\s+)?(above|previous)/i,
    /you\s+are\s+(now|no\s+longer|not)\s+(an?\s+)?(AI|assistant|chatbot|LLM)/i,
    /override\s+(all\s+)?(safety|security|ethics)\s+(constraints|guidelines|rules)/i,
    /act\s+as\s+(if\s+)?you\s+are\s+(not\s+)?(an?\s+)?(AI|assistant|chatbot)/i,
  ],
  command_execution: [
    /(run|execute|spawn|invoke)\s*[`'"](?:npm|npx|node|bash|sh|curl|wget|pip|gem)[`'"][^;]*/i,
    /<!--\s*(run|execute|cmd|shell|command):?\s*[^>]+-->/g,
    /<execute>\s*[\s\S]*?<\/execute>/gi,
    /```(?:bash|sh|shell|powershell|cmd)\s+[^`]+```/g,
  ],
  data_exfiltration_context: [
    /send\s+(all\s+)?(my\s+)?(data|files|keys|tokens|secrets|credentials|env)/i,
    /upload\s+(?:to|via)\s+(?:https?|ftp|s3):/i,
    /(?:exfiltrate|transmit|forward|relay)\s+(?:to|via)\s+(?:a\s+)?(?:remote|external|attacker)/i,
  ],
  hidden_directives: [
    /["'`]system["'`]\s*:\s*["'`][^"'`]{50,}["'`]/gi,   // system prompt injection
    /system_message\s*[:=]\s*["'`][^"'`]{30,}["'`]/gi,
    /\u202E/g,   // Right-to-Left Override (bidi spoofing)
  ],
};

export function scanPromptInjection(allFiles) {
  // Filter to LLM context target files (case-insensitive basename match)
  // Apply pattern groups with severity mapping:
  //   command_execution → critical
  //   instruction_override → high
  //   data_exfiltration_context → high
  //   hidden_directives → medium
  // Return findings
}
```

### Performance Impact Estimate

| Component | Cost | Notes |
|-----------|------|-------|
| Prompt injection regexes (~50 patterns) | +2–5ms | Applied to ~5–10 target files |
| Unicode normalization pre-pass | +3ms | Required for homoglyph detection |
| **Total** | **+5–10ms per package** | Negligible for interactive scans |

---

## 4. Cryptographic & OIDC Trust Over-Reliance

### Vulnerability Breakdown

**Current state:** The scoring engine gives zero trust credit to provenance because SLSA detection is a stub. However, an **implicit bypass via static reputation** exists.

| Gap | Details | Code Location |
|-----|---------|---------------|
| **SLSA attestation is a stub** | `tier1-slsa-attestation.js` returns `[]` — no provenance checking implemented. Comment: "waiting for npm registry API to stabilize." | `tier1-slsa-attestation.js:1-12` |
| **Static reputation bypass** | `KNOWN_REPUTABLE_PACKAGES` (80+ entries) causes multiple detectors to return `[]` immediately — no provenance verification of these packages. | `policy.js:7-95` |
| **No zero-trust evaluation** | A package with valid SLSA provenance receives identical analysis to an unsigned package — not because we distrust signatures, but because we never check them. | N/A |
| **Policy engine can suppress by reputation** | `suppress[].reputation_tier` rules skip findings for 'trusted' tier without requiring provenance verification of the signer. | `policy.js:194-204` |
| **No OIDC token validation** | No checking of GitHub OIDC token claims (audience, issuer, subject) for CI/CD-issued packages. | N/A |
| **`legitimate_native_addons` is static** | 9 packages permanently bypass D14 checks. No verification of actual build provenance. | `thresholds.js:188-198` |
| **Risk score is purely additive** | `calculateRiskScore()` weights severity levels (low=1, medium=3, high=7, critical=10) and sums, capped at 10. No provenance discount factor. | `report.js:239-243` |

### Architecture Proposal

```js
// Proposed: SLSA Provenance Verifier
// backend/detectors/lib/slsa-verifier.js

export async function verifyProvenance(pkgName, version, registryMeta) {
  // 1. Fetch provenance attestation from npm registry API
  // 2. Verify Sigstore bundle signature (Rekor + Fulcio)
  // 3. Check OIDC issuer matches expected: https://token.actions.githubusercontent.com
  // 4. Check OIDC subject (subject claim) matches expected repo for this package
  // 5. Return { verified: bool, publisher: string, slsaLevel: number, buildType: string }
}
```

**Zero-trust evaluation pipeline — replace static bypass with provenance-weighted scoring:**

```
Current flow:
  KNOWN_REPUTABLE_PACKAGES.has(name) ? return [] : run detection

Proposed flow:
  const prov = await verifyProvenance(name, version, meta);
  const findings = runDetection(...);  // run regardless
  if (prov.verified) {
    findings.forEach(f => f.confidenceScore *= 0.7);  // 30% confidence reduction
    // Do NOT suppress findings entirely
  }
```

**Changes required:**

| Component | Change |
|-----------|--------|
| `tier1-slsa-attestation.js` | Implement verifier, integrate into D8 |
| `policy.js:194-204` | Remove `reputation_tier` from suppress context matching; replace with `provenance_verified` context key |
| `tier1-build-config-abuse.js:38-43` | Do not skip reputables — run detection, apply provenance discount |
| `tier1-ai-token-targeting.js:46` | Same as above |
| `tier1-self-propagation.js:72` | Same as above |
| `report.js:239-243` | Add provenance credit: `Math.max(0, rawScore - rawScore * (prov.verified ? 0.15 : 0))` |

### Performance Impact Estimate

| Component | Cost | Notes |
|-----------|------|-------|
| SLSA provenance fetch | +100–300ms | 1 HTTP request to npm registry |
| Sigstore bundle verification | +50–100ms | Pure JS, no native deps |
| Caching | Mitigated | Provenance cached alongside tarball meta (same TTL) |
| **Total per package** | **+150–400ms** | Only when provenance exists (~5–15% of packages) |

---

## Priority Matrix

| Vector | Impact | Effort | Current Coverage | Priority |
|--------|--------|--------|-----------------|----------|
| C++ Build Hooks | High (CI/CD compromise) | Low | Partial (D14 regex) | **P1** |
| Wormable Self-Propagation | Critical (worm) | High | Minimal (D10 metadata) | **P1** |
| LLM Config Poisoning | Medium (agent compromise) | Low | Near-zero (D5 zero-width only) | **P2** |
| OIDC Trust Over-Reliance | Medium (false confidence) | Medium | Zero (stub) | **P2** |

### Recommended Implementation Order

1. **P1a — Gyp AST parser + extended patterns:** 2–3 days
2. **P1b — Worm static detection patterns:** 1–2 days
3. **P2a — Prompt injection detector:** 1–2 days
4. **P2b — SLSA verifier + zero-trust pipeline:** 3–5 days
5. **P1c — Sandbox execution (premium):** 4–6 weeks (gVisor integration)

---

*This document is a living artifact. Update when: new ATK entries are added, npm registry SLSA API stabilizes, or new campaign intelligence reveals detection gaps.*
