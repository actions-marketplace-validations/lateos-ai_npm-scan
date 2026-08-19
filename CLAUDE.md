# CLAUDE.md

Instructions for Claude Code when working in this repo. See [AGENTS.md](AGENTS.md) for full architecture, detector registry, and conventions — this file only adds Claude-Code-specific notes and a quick reference.

## Quick reference
- ESM Node.js CLI monorepo for `@lateos/npm-scan`, a supply chain vulnerability scanner.
- Entry points: `cli/cli.js` (bin `npm-scan`), `backend/index.js` (main).
- Verify changes with `npm test`, `npm run lint`, `npm run format:check` (or `npm run validate` to run all three).
- Detectors live in `backend/detectors/` (ATK-001–011 + tier-1 D1–D25 + campaign detectors), routed through `backend/detectors/index.js`.
- No native deps — `sql.js` (WASM) is used instead of `better-sqlite3` deliberately; keep it that way.
- Node >= 18 required.

## Working in this repo
- Read [AGENTS.md](AGENTS.md) before making non-trivial changes — it has the full detector table, calibration notes, and publishing steps.
- Follow `docs/project-plan.md` and `docs/attack-taxonomy.md` for the ATK taxonomy when adding or modifying detectors.
- New detectors need: proof-of-concept fixture (see `fixtures/campaigns/`), detection rule, false-positive analysis, and tests (`test/`).
- Premium features are license-gated via `backend/license.js` (HMAC-signed) but the code stays public — see `LICENSING.md`.
- Don't touch licensing boundaries (`LICENSING.md`) or the Commons Clause model without explicit user confirmation — see [DECISION.md](DECISION.md).
- Check [STATUS.md](STATUS.md) for current in-progress work before starting something that might overlap.
