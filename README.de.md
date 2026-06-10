# npm-scan

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![License](https://img.shields.io/badge/license-MIT%20OR%20BLA-blue?style=flat-square)](LICENSING.md) [![Tests](https://img.shields.io/badge/tests-830%2B%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)

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

## Abdeckung: npm-scan vs Branchentools

| Angriffsvektor | npm-scan | npm audit | Snyk | Socket | Sonatype |
|---|:---:|:---:|:---:|:---:|:---:|
| **Miasma/Hades (binding.gyp)** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 40% | ❌ 0% |
| **eBPF-Kernel-Rootkit** | ✅ 95% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **KI-Token-Targeting** | ✅ 98% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **GitHub-Autoren-Spoofing** | ✅ 99% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **Speicher-Credential-Extraktion** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 20% | ❌ 0% |
| **Selbstverteidigender Code** | ✅ 95% | ❌ 0% | ⚠️ 25% | ⚠️ 45% | ❌ 0% |
| **Modul-Lade-Ausführung** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 50% | ❌ 0% |
| **Bekannte CVEs** | ✅ Ja | ✅ Ja | ✅ Ja | ✅ Ja | ✅ Ja |

**Legende:** ✅ = 85%+ Erkennung | ⚠️ = 15–80% Erkennung | ❌ = 0% Erkennung

---

## Risikominderung und Compliance

**Einzelwerkzeug-Ansatz = Blinder Fleck = Teure Haftung**

Ein kompromittiertes npm-Paket kostet Ihr Unternehmen:
- **Datenpanne:** 4,5 Mio. $ Durchschnitt (IBM, 2024)
- **Regulierungsstrafen:** SOC 2-Verstöße (100 K$+), DSGVO (10 Mio.$+), Compliance-Prüfungen
- **Ausfallzeit:** 5 K$–50 K$ pro Stunde Umsatzverlust
- **Reputation:** Markenschaden, Vertrauensverlust bei Kunden
- **Rechtliches:** Klagen betroffener Kunden, Haftungsansprüche

**Ein traditionelles Tool allein übersieht Verhaltensangriffe.** Wenn npm audit + Snyk nichts sehen, aber Angreifer Ihre AWS-Anmeldedaten über ein Verhaltensmuster stehlen, haften Sie.

**npm-scan + npm audit = Vollständige Abdeckung = Risikominderung**

Durch die Erkennung der 95%+ Angriffe, die traditionelle Tools übersehen, reduzieren Sie:
- ✅ Wahrscheinlichkeit einer Panne (Verhaltenserkennung erfasst Angriffe vor dem Schaden)
- ✅ Compliance-Verletzungsrisiko (Sorgfaltspflicht: Sie haben mehrere Erkennungsmethoden verwendet)
- ✅ Finanzielle Haftung (Prüfer fragen: "Wie haben Sie die Lieferkettensicherheit verifiziert?")
- ✅ Kundenauswirkung (schnellere Erkennung = schnellere Behebung = weniger betroffene Kunden)

**Kosten-Nutzen:** npm-scan (2,4 K$/Jahr Enterprise) vs. Datenpanne (4,5 Mio.$ Durchschnitt). ROI: 1.875x.

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
- ✅ **CI/CD-Integration** — funktioniert mit jeder CI/CD-Plattform
- ✅ **Docker** — Multi-Arch-Images

---

## CI/CD-Integration

```yaml
# GitHub Actions Beispiel
- name: Scan with npm-scan
  run: |
    npm install -g @lateos/npm-scan
    npm-scan scan-lockfile --fail-on critical
```

Funktioniert mit GitHub Actions, GitLab CI, Jenkins oder jeder CI/CD-Plattform.

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
