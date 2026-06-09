# npm-scan

[![English](https://img.shields.io/badge/lang-en-blue?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.md)
[![中文](https://img.shields.io/badge/lang-zh--CN-red?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.zh.md)
[![日本語](https://img.shields.io/badge/lang-ja-purple?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.ja.md)
[![Français](https://img.shields.io/badge/lang-fr-orange?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.fr.md)
[![Deutsch](https://img.shields.io/badge/lang-de-green?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.de.md)

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![npm downloads/week](https://img.shields.io/npm/dw/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![License](https://img.shields.io/badge/license-MIT%20OR%20BLA-blue?style=flat-square)](LICENSING.md) [![Tests](https://img.shields.io/badge/tests-830%2B%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)

**Erkennung von Lieferkettenbedrohungen, die npm audit, Snyk und Socket übersehen.**

Erkennt obfuskierte Payloads, Credential-Stealer, Kernel-Rootkits, eBPF-Hooks, Speicherextraktion, GitHub-Spoofing und KI-gesteuerte Angriffe.

---

## Warum npm-scan?

**Traditionelle Werkzeuge sind veraltet.** npm audit prüft CVE-Datenbanken. Snyk scannt Abhängigkeitsversionen. Keines erfasst Verhaltensmuster.

**Die Angriffswelle 2026:**
- eBPF-Kernel-Rootkits (für Überwachung unsichtbar)
- Speicherbasierte Credential-Extraktion (OIDC-Tokens)
- Selbstverteidigender Code (Anti-Debugging, Anti-Manipulation)
- GitHub-Autoren-Spoofing ("claude@users.noreply.github.com")
- KI-Plattform-Targeting (Claude, OpenAI, Cursor, Mistral-Schlüssel)
- Wurmartige Verbreitung (automatische Neuveröffentlichung mit gestohlenen Tokens)

npm-scan erkennt all dies. **95%+ Konfidenz bei realen Kampagnen.**

---

## Was wird erkannt?

| Kategorie | Beispiele | Erkennungsrate |
|-----------|-----------|----------------|
| **Credential-Diebstahl** | Umgebungsvariablen, Token-Exfiltration | 98% |
| **Kernel-Angriffe** | eBPF-Rootkits, Privilegieneskalation | 95% |
| **Code-Verschleierung** | Obfuskation, Selbstverteidigung, Anti-Debug | 95% |
| **Speicherextraktion** | OIDC-Token-Zugriff, KI-Schlüssel-Targeting | 95% |
| **GitHub-Angriffe** | Autoren-Spoofing, Force-Push-Entführung | 99% |
| **Wurmverbreitung** | Auto-Republish via gestohlener Credentials | 95% |

---

## Schnellstart

```bash
npm install -g @lateos/npm-scan
npm-scan axios
npm-scan scan-lockfile
npm-scan express --json > findings.json
```

---

## Hauptfunktionen

- ✅ **23 Detektoren (D1–D25)** für Lieferketten-Angriffsvektoren
- ✅ **Validierung an echten Kampagnen** (IronWorm, Miasma, Dependency Confusion)
- ✅ **Lokale Ausführung** — keine Telemetrie, keine Cloud-Abhängigkeit
- ✅ **Schnell** — <30 Sekunden pro CI/CD-Durchlauf
- ✅ **Policy-as-Code** — YAML-Whitelists, Schweregrad-Überschreibungen
- ✅ **SBOM + SARIF** — CycloneDX, SPDX, GitHub Security
- ✅ **GitHub Action** — Einzeilige CI/CD-Integration
- ✅ **Docker** — Multi-Arch-Images

---

## GitHub Action

```yaml
- uses: lateos-ai/npm-scan@v1
  with:
    scan-type: lockfile
    fail-on: critical
```

---

## Lizenzierung

**Kostenlos (MIT):** Einzelgründer, Non-Profits, Studenten, Open-Source-Projekte.
**Bezahlt (BLA):** Unternehmen mit Angestellten.

Siehe [LICENSING.md](LICENSING.md) für Details.

**Enterprise?** [Kommerzielle Lizenz erhalten](https://lateos.ai/npm-scan/licensing)

---

## Mehr

- [Vollständige Dokumentation](https://github.com/lateos-ai/npm-scan)
- [Angriffstaxonomie (ATK-Serie)](https://github.com/lateos-ai/npm-scan/blob/main/DETECTORS.md)
- [Kampagnen-Validierungsdaten](https://github.com/lateos-ai/npm-scan/blob/main/VALIDATION.md)

---

**Scannen Sie Ihr erstes Paket jetzt:**

```bash
npx @lateos/npm-scan scan axios
```
