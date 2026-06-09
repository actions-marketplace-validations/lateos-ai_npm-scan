# npm-scan

[![English](https://img.shields.io/badge/lang-en-blue?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.md)
[![中文](https://img.shields.io/badge/lang-zh--CN-red?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.zh.md)
[![日本語](https://img.shields.io/badge/lang-ja-purple?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.ja.md)
[![Français](https://img.shields.io/badge/lang-fr-orange?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.fr.md)
[![Deutsch](https://img.shields.io/badge/lang-de-green?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.de.md)

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![npm downloads/week](https://img.shields.io/npm/dw/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![License](https://img.shields.io/badge/license-MIT%20OR%20BLA-blue?style=flat-square)](LICENSING.md) [![Tests](https://img.shields.io/badge/tests-830%2B%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)

**Détection des menaces sur la chaîne d'approvisionnement que npm audit, Snyk et Socket ne voient pas.**

Détecte les charges utiles obfusquées, les voleurs d'identifiants, les rootkits noyau, les hooks eBPF, l'extraction mémoire, l'usurpation GitHub et les attaques ciblant l'IA.

---

## Pourquoi npm-scan ?

**Les outils traditionnels sont obsolètes.** npm audit vérifie les bases CVE. Snyk analyse les versions de dépendances. Aucun ne détecte les schémas comportementaux.

**La vague d'attaques de 2026 :**
- Rootkits noyau eBPF (invisibles pour la surveillance)
- Extraction mémoire de credentials (jetons OIDC)
- Code auto-défensif (anti-débogage, anti-altération)
- Usurpation d'auteur GitHub ("claude@users.noreply.github.com")
- Ciblage de plateformes IA (Clés Claude, OpenAI, Cursor, Mistral)
- Propagation de type ver (republié automatiquement avec jetons volés)

npm-scan détecte tout cela. **95%+ de confiance sur des campagnes réelles.**

---

## Ce qui est détecté

| Catégorie | Exemples | Détection |
|-----------|----------|-----------|
| **Vol d'identifiants** | Collecte de variables d'env, exfiltration de jetons | 98% |
| **Attaques noyau** | Rootkits eBPF, escalade de privilèges | 95% |
| **Évitement de code** | Obfuscation, code auto-défensif, anti-débogage | 95% |
| **Extraction mémoire** | Accès aux jetons OIDC, ciblage de clés IA | 95% |
| **Attaques GitHub** | Usurpation d'auteur, détournement force-push | 99% |
| **Propagation de ver** | Republié via des identifiants volés | 95% |

---

## Démarrage rapide

```bash
npm install -g @lateos/npm-scan
npm-scan axios
npm-scan scan-lockfile
npm-scan express --json > findings.json
```

---

## Fonctionnalités clés

- ✅ **23 détecteurs (D1–D25)** couvrant les vecteurs d'attaque de la chaîne d'approvisionnement
- ✅ **Validation sur des campagnes réelles** (IronWorm, Miasma, Dependency Confusion)
- ✅ **Exécution locale** — aucune télémétrie, aucune dépendance cloud
- ✅ **Rapide** — <30 secondes par exécution CI/CD
- ✅ **Politique en tant que code** — listes blanches YAML, surcharges de sévérité
- ✅ **SBOM + SARIF** — CycloneDX, SPDX, GitHub Security
- ✅ **GitHub Action** — Intégration CI/CD en une ligne
- ✅ **Docker** — Images multi-architecture

---

## GitHub Action

```yaml
- uses: lateos-ai/npm-scan@v1
  with:
    scan-type: lockfile
    fail-on: critical
```

---

## Licence

**Gratuit (MIT) :** Fondateurs individuels, ONG, étudiants, projets open-source.
**Payant (BLA) :** Entreprises avec employés.

Voir [LICENSING.md](LICENSING.md) pour les détails.

**Enterprise ?** [Obtenir une licence commerciale](https://lateos.ai/npm-scan/licensing)

---

## Plus

- [Documentation complète](https://github.com/lateos-ai/npm-scan)
- [Taxonomie des attaques (série ATK)](https://github.com/lateos-ai/npm-scan/blob/main/DETECTORS.md)
- [Données de validation des campagnes](https://github.com/lateos-ai/npm-scan/blob/main/VALIDATION.md)

---

**Scannez votre premier paquet dès maintenant :**

```bash
npx @lateos/npm-scan scan axios
```
