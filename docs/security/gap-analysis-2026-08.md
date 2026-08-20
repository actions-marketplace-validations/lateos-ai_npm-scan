# Supply Chain Detection Gap Analysis — August 2026

> **Audit date:** 2026-08-12
> **Scope:** Coverage of npm supply chain attack classes that post-date the July 2026 audit ([gap-analysis-2026.md](gap-analysis-2026.md)), plus verification that the July remediations actually work end-to-end.
> **Method:** Static review of `backend/detectors/`, `backend/lockfile.js`, `backend/report.js`, plus live execution of the SLSA path against the real npm registry.

---

## Executive summary

Two distinct problems:

1. **The July 2026 SLSA/provenance remediation does not work.** It was shipped, wired into the pipeline, and is reachable — but it misreads the npm registry response shape, so it never verifies anything. Every provenance-bearing package is reported as having *no* provenance, and the entire provenance-discount pathway is unreachable dead code. This is verified, not theoretical (§1).
2. **The scanner's model of "install-time execution" is still `package.json` scripts only.** The 2025–2026 attack wave moved to *other* files that execute on install or on developer-tool startup — pnpm/yarn/bun install hooks, MCP server configs, agent hook configs. The data plane already reads these files; no detector looks at them (§5, §6).

Priority matrix in §9.

---

## Part A — Confirmed defects in existing coverage

### 1. SLSA provenance verification is non-functional (P0)

`lib/slsa-verifier.js:15` reads:

```js
const attestations = dist.attestations || registryMeta.attestations || [];
if (!attestations.length) { result.error = 'no_attestations'; return result; }
```

`dist.attestations` in the npm packument is an **object**, not an array:

```json
{
  "url": "https://registry.npmjs.org/-/npm/v1/attestations/sigstore@3.0.0",
  "provenance": { "predicateType": "https://slsa.dev/provenance/v1" }
}
```

`.length` is `undefined` → falsy → the function short-circuits to `no_attestations` for **every package**, including SLSA L3 ones. Verified live:

```
$ node -e "...scan({name:'sigstore',version:'3.0.0'}, [], meta, [])"
[{ "id": "TIER1-SLSA-ATTESTATION", "sev": "medium",
   "msg": "Package sigstore@3.0.0 has no SLSA provenance attestation" }]
verifyProvenance: {"verified":false,"slsaLevel":0,"error":"no_attestations"}
```

`sigstore@3.0.0` is built with GitHub Actions SLSA provenance. The scanner says it has none.

**Two consequences:**

| Consequence | Impact |
|---|---|
| **False positive on every scan** | `TIER1-SLSA-ATTESTATION` medium (weight 3 in `calculateRiskScore`) fires unconditionally on any package with registry metadata. Every scan carries a permanent +3 raw risk floor and one unactionable medium finding. |
| **Provenance discount is dead code** | `verified` can never become `true`, so `applyProvenanceDiscount()` (`slsa-verifier.js:67`) and the risk-score provenance credit (`report.js:243-253`) never execute. The July audit's headline deliverable — provenance-weighted zero-trust scoring — is inert. |

**Fix:** the attestation *document* must be fetched from `dist.attestations.url`; the packument only carries a pointer and `predicateType`. This is a second HTTP request, not a field read.

### 2. Even when fixed, "verification" is not cryptographic (P0)

Independent of the shape bug, the design of `verifyProvenance()` is unsound as a *trust* signal:

- **No signature verification.** No Sigstore bundle validation, no Rekor inclusion proof, no Fulcio cert chain check. `grep -i "sigstore|rekor|fulcio|signature"` on `slsa-verifier.js` returns nothing.
- **`verified: true` is set by a string comparison** (`slsa-verifier.js:31-37`): if any `att.subject[].name` equals the package name, the package is "verified". An attacker who can author an attestation document — or a MITM/compromised mirror serving one — gets a 30% confidence discount on all their findings.
- **No OIDC claim validation.** The July plan (§4) explicitly specified checking issuer `https://token.actions.githubusercontent.com` and matching the subject claim to the expected repo. Neither is implemented. `publisher` is read from `runDetails.builder.id` and never validated against anything.
- **`dist.signatures` is never checked.** npm's registry-level ECDSA signature over `package@version` + integrity is present in the packument (confirmed live) and completely unused.

This inverts the intended security property: provenance currently can only ever *reduce* suspicion, never establish trust, and the reduction is attacker-influenceable once the shape bug is fixed. **Fixing §1 without fixing §2 makes the scanner less safe, not more.**

### 3. Lockfile `resolved` URLs are parsed and then discarded (P1)

`backend/lockfile.js` parses `resolved` for all three lockfile formats (npm `:52`, yarn `:134-144`, pnpm `:239`). Nothing consumes it:

```
$ rg "\.resolved" backend/ --glob '!*.test.js'
backend/lockfile.js:52:   resolved: pkg.resolved || '',
# (only other hits are Intl.resolvedOptions in a geo-killswitch detector)
```

A lockfile entry resolving to `http://attacker.internal/pkg.tgz`, a `git+ssh://` URL, or an unexpected registry host passes without comment. This is the cheapest high-value detector available — the field is already in the parsed structure.

**Related:** no `integrity` presence check either. Entries with `resolved` but no `integrity` (permitted by the format, and a known tampering foothold) are not flagged.

### 4. ATK-006 "dependency confusion" is a keyword stub (P1)

The entire detector (`atk-006-depconf.js`):

```js
const squat = Object.keys(deps).filter((d) => /squat|confus|typo/i.test(d.toLowerCase()));
```

It flags dependencies whose *names literally contain the words* "squat", "confus", or "typo". It does not model dependency confusion at all — no scope analysis, no internal-vs-public namespace check, no registry-existence comparison. ATK-006 is marked "Phase 1" (complete) in `docs/attack-taxonomy.md` and is claimed in `package.json`'s description ("Detects 100% of 3 real May 2026 supply chain campaigns (dependency confusion, …)").

Real coverage for this campaign class appears to come from `tier1-version-confusion.js` / `tier1-version-anomaly.js`. The ATK-006 entry should either be implemented or explicitly re-pointed at the tier-1 detectors, because the taxonomy is the documented moat and this entry does not hold up to inspection.

---

## Part B — Uncovered newer attack classes

### 5. Install-time execution outside `package.json` scripts (P1)

Every lifecycle detector (D3, D3b, D6b, ATK-001) keys off `package.json` `scripts`. The package-manager ecosystem has several *other* files that execute code at install time, none of which are examined:

| Surface | Mechanism | Coverage |
|---|---|---|
| `.pnpmfile.cjs` | `hooks.readPackage()` runs arbitrary Node on every install; can rewrite any dependency's manifest in-memory | **None** |
| `.yarnrc.yml` `plugins:` | Yarn Berry loads plugin JS from a path or URL at command time | **None** |
| `bunfig.toml` `[install.lifecycle]` / `trustedDependencies` | Re-enables blocked install scripts for named packages | **None** |
| `package.json` `overrides` / `resolutions` | Silently substitutes a transitive dep's *source* across the tree | Parsed by `policy.js`, not analyzed as an attack surface |

`grep -il ".pnpmfile|yarnrc|bunfig|trustedDependencies" backend/detectors/` → no hits.

Note the asymmetry this creates: `tier1-bun-runtime-swap.js` (D24) detects Bun *runtime* abuse but not `bunfig.toml`, which is the configuration file that authorizes it.

### 6. Agent / MCP configuration poisoning — executable config (P1)

The July audit added `lib/prompt-injection.js`, which is good work, but its target list is prose-only:

```js
.cursorrules, CLAUDE.md, .claude.md, AGENTS.md,
.github/copilot-instructions.md, .windsurfrules, .cursor/rules/*.mdc
```

These are files an agent *reads*. The higher-severity 2026 vector is config an agent **executes**:

| Surface | Why it matters | Coverage |
|---|---|---|
| `.mcp.json` / `mcpServers` blocks | Declares an MCP server as `command` + `args` — arbitrary process spawn on agent startup | **None** |
| `.vscode/mcp.json`, `.cursor/mcp.json` | Same, editor-scoped | **None** |
| `.claude/settings.json` `hooks` | Shell commands run on tool-use / session events | **None** |
| `.vscode/tasks.json` `runOptions.runOn: folderOpen` | Command execution on folder open | **None** |
| `.devcontainer/devcontainer.json` `postCreateCommand` | Command execution on container create | **None** |

`grep -i ".mcp.json|mcpServers"` across `backend/` → no hits. This is a clean miss, and it is the class most likely to produce a real incident in the next two quarters: it requires no `postinstall`, survives `--ignore-scripts`, and executes with full developer privileges.

**Severity note:** an injected *instruction* is `high` (needs an agent to comply). An injected *server command* is `critical` (unconditional execution). They should not share a detector or a severity band.

### 7. Manifest confusion (P2)

The npm registry serves dependency metadata from the **registry manifest**, which is submitted at publish time and is not required to match the `package.json` inside the published **tarball**. An attacker can declare benign deps to the registry (what audit tools and `npm ls` see) while the tarball installs different ones.

No coverage: `grep -i "manifest.confusion|manifestConfusion"` → no hits.

The scanner is unusually well-positioned here — `fetch.js` already holds both `registryMeta` and the extracted tarball `pkgJson` in the same scope and passes both to every detector. The comparison is a few lines: diff `dependencies`, `scripts`, `bin`, and `version` between `registryMeta.versions[v]` and the tarball manifest. Any mismatch is high-confidence malicious; there is no legitimate reason for them to diverge.

### 8. CI workflow poisoning shipped inside packages (P2)

Packages can ship `.github/workflows/*.yml`. A consumer who vendors or forks the package inherits them. `pull_request_target` + untrusted checkout is the canonical privilege-escalation pattern, and `workflow_run` triggers inherit write-scoped tokens.

No coverage: `grep -i ".github/workflows|pull_request_target|workflow_run"` across `backend/` → no hits. `allFiles` already includes these files (`fetch.js:161` walks with `ext = ''`).

### 9. Starjacking / reputation spoofing (P3)

`tier1-metadata-spoof.js` (D5) covers cloned repo URLs and namespace spoofing. It does not cover starjacking — pointing `repository` at a *legitimate, popular, unrelated* repo to inherit its social proof in registry UIs and reputation heuristics. Distinct from D5's cloned-repo case because the target repo is genuine and unmodified. Low impact on detection accuracy, but it directly undermines any reputation-tier logic in `policy.js`.

---

## Priority matrix

| # | Gap | Class | Impact | Effort | Priority |
|---|---|---|---|---|---|
| 1 | SLSA attestation shape bug | Defect | FP on every scan + dead provenance pipeline | ~1 day | **P0** |
| 2 | Non-cryptographic provenance "verification" | Defect | Attacker-influenceable trust discount | 3–5 days | **P0** |
| 5 | pnpm/yarn/bun install hooks | Uncovered | Install-time RCE, bypasses all lifecycle detectors | 2–3 days | **P1** |
| 6 | MCP / agent hook config execution | Uncovered | Dev-machine RCE, survives `--ignore-scripts` | 2–3 days | **P1** |
| 3 | Lockfile `resolved` host validation | Defect | Off-registry fetch undetected | ~0.5 day | **P1** |
| 4 | ATK-006 stub vs. taxonomy claim | Defect | Documented coverage not real | 1–2 days | **P1** |
| 7 | Manifest confusion | Uncovered | Registry metadata ≠ shipped code | ~1 day | **P2** |
| 8 | Shipped CI workflow poisoning | Uncovered | Downstream CI compromise | 1–2 days | **P2** |
| 9 | Starjacking | Uncovered | Reputation-heuristic bypass | ~1 day | **P3** |

### Recommended order

1. **§1 + §2 together, as one change.** Do not ship the shape fix alone — it activates a trust discount that has no cryptographic basis. If §2 can't be done now, the safer interim action is to make `verified` permanently `false` *explicitly* and drop the unconditional `no_attestations` finding to `low`/informational, so the scan stops carrying a phantom +3 risk floor.
2. **§3 + §7** — both are near-free, operate on data already parsed and in scope, and are high-confidence/low-FP.
3. **§5 + §6** — the actual new attack surface. Suggest a single new detector module (`tier1-install-config-abuse.js`) for §5 and extending `lib/prompt-injection.js` with a separate `critical`-band executable-config path for §6.
4. **§4, §8, §9** as taxonomy/coverage hygiene.

---

## Calibration notes for new detectors

- **§5 pnpmfile:** presence of `.pnpmfile.cjs` alone is not suspicious (legitimate monorepo use is common). Score on *content* — `readPackage` mutating `scripts`, or any network/`child_process` reference — reusing `lib/obfuscation-check.js`.
- **§6 MCP configs:** `command: "node"` / `"npx"` pointing inside the package is normal for a package that legitimately *is* an MCP server. Escalate on: absolute paths outside the package, shell interpreters (`sh`/`bash`/`powershell`), inline `-c` payloads, or network fetch in `args`. Cross-reference `pkgJson.keywords` for `mcp` to suppress the legitimate case.
- **§7 manifest confusion:** exclude `version` normalization differences and registry-injected fields (`_id`, `dist`, `_npmUser`, `gitHead`) before diffing, or every package will fire.
- **§3 resolved host:** allowlist must cover `registry.npmjs.org`, `registry.yarnpkg.com`, and configured private registries — this needs to be policy-configurable (`policy.js`) or it will be unusable in enterprise environments, which are the paying users.

---

*Companion to [gap-analysis-2026.md](gap-analysis-2026.md) (July 2026). Update when new campaign intelligence lands or when the P0 items are remediated.*
