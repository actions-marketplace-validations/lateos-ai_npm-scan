# @lateos/npm-scan

[![English](https://img.shields.io/badge/lang-en-blue?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.md)
[![中文](https://img.shields.io/badge/lang-zh--CN-red?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.zh.md)
[![日本語](https://img.shields.io/badge/lang-ja-purple?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.ja.md)
[![Français](https://img.shields.io/badge/lang-fr-orange?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.fr.md)
[![Deutsch](https://img.shields.io/badge/lang-de-green?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.de.md)

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%2B%20Commons%20Clause-blue?style=flat-square)](LICENSING.md)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square)](package.json)
[![Tests](https://img.shields.io/badge/tests-459%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)
[![Coverage](https://img.shields.io/badge/coverage-85%25-yellowgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)
[![Docker](https://img.shields.io/badge/docker-lateos%2Fnpm--scan-2496ED?style=flat-square&logo=docker)](https://hub.docker.com/r/lateos/npm-scan)
[![Sigstore](https://img.shields.io/static/v1?label=Sigstore&message=Provenance&color=green&style=flat-square&logo=sigstore)](https://github.com/lateos-ai/npm-scan/actions/workflows/publish.yml)

**Sécurité moderne de la chaîne d'approvisionnement pour l'écosystème npm.**  
Analyse statique + comportementale qui détecte ce que npm audit, Snyk et Socket manquent — charges utiles obfusquées, voleurs d'identifiants, déclencheurs conditionnels, contournement de sandbox et propagation de type ver.

---

## 📌 Le problème

La vague d'attaques sur la chaîne d'approvisionnement npm de 2025-2026 a prouvé que les outils traditionnels ne suffisent plus.

Les attaquants ont dépassé le simple typosquatting. Ils livrent désormais des **hooks de pré-installation obfusqués**, des **voleurs d'identifiants cachés derrière la détection d'environnement**, des **portes dérobées dormantes avec activation temporelle**, et une **propagation transitive de type ver** qui se répand via les dépendances peer.

La **campagne Megalodon** (2026) a à elle seule compromis plus de 5 500 dépôts via de fausses PR GitHub, l'injection de workflows malveillants et l'exfiltration d'identifiants cloud - le tout coordonné par un seul acteur automatisant l'ensemble de la chaîne de destruction. **@lateos/npm-scan** détecte désormais les artefacts de cette campagne dès la première utilisation.

La **campagne de ver Mini Shai-Hulud** (mai 2026) a frappé l'écosystème npm en trois vagues - détournement CI/CD TanStack (84 artefacts en 6 minutes), compromission du mainteneur AntV/atool (600+ versions malveillantes dans 300+ packages), et empoisonnement de l'extension VS Code Nx Console (CVE-2026-48027) - toutes utilisant l'obfuscation ctf-scramble-v2, la persistance démonisée avec vérifications d'environnement CI, des killswitches géographiques ciblant les régions sanctionnées, et des canaux C2 GitHub dead-drop pour la récupération de jetons. **@lateos/npm-scan** détecte désormais les 10 signaux Mini Shai-Hulud répartis sur deux suites de détection.

Un vecteur d'attaque croissant est **l'usurpation d'organisation HuggingFace** - des packages qui se font passer pour des dépôts de modèles HF légitimes pour tromper les utilisateurs.

La **campagne TrapDoor** (mai 2026) couvre npm, PyPI et Crates.io - 34 packages malveillants, 384+ versions attribuées à un seul éditeur.

La **compromission node-ipc** (14 mai 2026) a utilisé un domaine de maintenance expiré pour détourner l'un des packages les plus dépendus de npm.

La **campagne de typosquattage massif (vpmdhaj)** (mai 2026) a utilisé le compte mainteneur npm `vpmdhaj` pour publier 14 packages typosquattés en 4 heures - ciblant les environnements AWS/CI/CD avec des stagers de pré-installation, un abus du runtime Bun, et l'exfiltration d'identifiants cloud. **@lateos/npm-scan** détecte désormais les 3 signaux de la campagne de typosquattage.

La **campagne d'empoisonnement du registre Axios** (mai 2026) a compromis les métadonnées du package axios pour publier `axios@1.14.1` et `axios@0.30.4` avec des dépendances injectées contenant des RAT multiplateformes. **@lateos/npm-scan** détecte désormais les 3 signaux d'empoisonnement Axios.

**npm audit** vérifie les CVE connus. **Snyk** recherche les vulnérabilités. **Socket** analyse le comportement des paquets. Aucun d'eux n'a été conçu pour la génération d'attaques apparue en 2025.

**@lateos/npm-scan** a été conçu pour ce moment.

---

## 🔬 Pourquoi @lateos/npm-scan ?

| Capacité | npm audit | Snyk | Socket | **@lateos/npm-scan** |
|---|---|---|---|---|---|
| Correspondance CVE connus | ✅ | ✅ | ❌ | ✅ |
| Analyse statique | ❌ | ✅ | ✅ | ✅ |
| Détection de charges utiles obfusquées | ❌ | ❌ | ❌ | ✅ |
| Analyse heuristique au niveau AST | ❌ | ❌ | ❌ | ✅ |
| Bac à sable comportemental runtime | ❌ | ❌ | ✅ | ✅ |
| Détection de déclencheurs conditionnels (ATK-009) | ❌ | ❌ | ❌ | ✅ |
| Détection de contournement de sandbox (ATK-010) | ❌ | ❌ | ❌ | ✅ |
| Propagation transitive de ver (ATK-011) | ❌ | ❌ | ❌ | ✅ |
| Détection de campagne (Megalodon CI/CD) | ❌ | ❌ | ❌ | ✅ |
| Détection de campagne de ver (Mini Shai-Hulud Vagues 1-3) | ❌ | ❌ | ❌ | ✅ |
| Détection d'usurpation HF (dépôt de modèles + clone README) | ❌ | ❌ | ❌ | ✅ |
| Analyse d'extension VS Code (--vsix) | ❌ | ❌ | ❌ | ✅ |
| Détection de vulnérabilité Python (CVE-2026-48710 BadHost) | ❌ | ❌ | ❌ | ✅ |
| Détection d'attaque multi-écosystème (TrapDoor) | ❌ | ❌ | ❌ | ✅ |
| Détection de détournement de domaine expiré (node-ipc) | ❌ | ❌ | ❌ | ✅ |
| Détection d'obfuscation de malware (ctf-scramble-v2) | ❌ | ❌ | ❌ | ✅ |
| Campagne de typosquattage massif (mainteneur vpmdhaj) | ❌ | ❌ | ❌ | ✅ |
| Détection d'empoisonnement de registre (versions axios) | ❌ | ❌ | ❌ | ✅ |
| Taxonomie d'attaques (série ATK) | ❌ | ❌ | ❌ | ✅ |
| Sortie SBOM (CycloneDX + SPDX) | ❌ | ✅ | ❌ | ✅ |
| Rapport de conformité NIST 800-161 | ❌ | ❌ | ❌ | ✅ |
| Rapport de conformité EU CRA | ❌ | ❌ | ❌ | ✅ |
| Export SIEM (CEF / ECS / Sentinel / QRadar) | ❌ | ❌ | ❌ | ✅ |
| Exécution entièrement locale - aucune télémétrie | ✅ | ❌ | ❌ | ✅ |
| Politique en tant que code (listes blanches YAML) | ❌ | ❌ | ❌ | ✅ |

> **La vie privée d'abord.** Toute l'analyse s'effectue sur votre machine. Aucun code ne quitte votre environnement. Aucune télémétrie. Aucune dépendance au cloud.

---

## ✨ Fonctionnalités clés

| Icône | Fonctionnalité | Description |
|------|---------|-------------|
| 🕵️ | **Analyse statique heuristique** | L'inspection au niveau AST détecte l'obfuscation, les chaînes eval, le sondage d'environnement et les scripts de cycle de vie suspects que les outils basés sur les regex manquent |
| 🧠 | **Détection comportementale** | Identifie les déclencheurs conditionnels (temporels, conscients du CI), le contournement de sandbox et les modèles d'activation dormante |
| 🧬 | **Taxonomie d'attaques ATK** | 11 types d'attaques classifiés avec correspondances NIST 800-161 - versionnés, documentés et PR-ables |
| 🪱 | **Détection de campagne de ver** | Mini Shai-Hulud - 10 sous-vérifications réparties sur deux suites détectant les bursts de publication, les compromissions de pairs, les anomalies d'attestation SLSA, la dérive d'éditeur, la correspondance IOC, l'exfiltration de jetons, l'obfuscation ctf-scramble-v2, la persistance démonisée, les killswitches géographiques et les canaux C2 GitHub |
| 🧩 | **Analyse d'extension VSIX** | `npm-scan scan --vsix` - détecte les attaques de la chaîne d'approvisionnement du Marketplace VS Code |
| 🐍 | **Détection de vulnérabilité Python** | CVE-2026-48710 (BadHost) - injection d'en-tête Host Starlette |
| 🪤 | **Détection d'attaque multi-écosystème** | TrapDoor - 9 sous-vérifications |
| 📡 | **Détection de détournement de domaine expiré** | node-ipc - 11 sous-vérifications |
| ☣️ | **Détection d'obfuscation de malware** | ctf-scramble-v2 - analyse des distributions à la recherche de motifs d'obfuscation de malware connus, arrêt immédiat avec condition d'arrêt de sévérité CRITIQUE |
| 🎭 | **Détection de campagne de typosquattage massif** | Liste noire du mainteneur vpmdhaj avec condition d'arrêt, détection de typosquattage basée sur Levenshtein, identification de stager de pré-installation, motifs d'exfiltration d'identifiants AWS ECS/Vault/GitHub |
| ☠️ | **Détection d'empoisonnement de registre** | Liste noire des versions Axios (1.14.1/0.30.4) avec condition d'arrêt, découverte de dépendance leurre (plain-crypto-js), détection de RAT multiplateforme |
| 🔏 | **Piste d'audit de provenance** | Cadre Aureus-Elicitor v1.7 - manifests de détection signés HMAC-SHA256, pistes d'audit vérifiées par hachage de contenu, URLs de provenance de règle, attribution de source de campagne |
| 📦 | **Génération SBOM** | CycloneDX 1.5 et SPDX 2.3 avec résultats intégrés comme vulnérabilités |
| 🧾 | **Rapports de conformité** | Matrice de traçabilité NIST SP 800-161 + cartographie EU Cyber Resilience Act (gratuit) |
| 🔌 | **Export SIEM** | Formats Splunk CEF, Elastic ECS, Microsoft Sentinel, IBM QRadar (premium) |
| 📜 | **Politique en tant que code** | Moteur de politique YAML/JSON avec listes blanches, surcharges de sévérité, suppressions et seuils d'échec |
| 🐳 | **Docker + GitHub Action** | Images multi-arch, pipeline Compose en une commande, action de scan PR |
| 🛡️ | **Zéro télémétrie** | Aucune donnée ne quitte votre machine. Pas de cloud. Pas de rappels. |
| 💾 | **Historique de scan local** | Persistance basée sur SQLite, zéro dépendance externe |

---

## ⚡ Démarrage rapide

```bash
# Installation globale
npm install -g @lateos/npm-scan

# Scanner un seul paquet
npm-scan scan lodash

# Scanner votre fichier de verrouillage
npm-scan scan-lockfile

# Voir les derniers scans
npm-scan report
```

**Pas d'installation ? Pas de problème :**

```bash
npx @lateos/npm-scan scan commander
```

---

## 🐳 Exécutez @lateos/npm-scan partout avec Docker — zéro installation

```bash
# Tirez et exécutez un scan unique — pas de Node.js ni npm requis
docker run --rm lateos/npm-scan:cli scan lodash

# Pipeline complet avec stockage persistant et Compose
docker compose --profile pipeline up -d
```

Pas de Node.js. Pas de `npm install`. Pas de paquets globaux. Fonctionne sur tout système avec Docker — serveurs CI, environnements air-gap, clusters Kubernetes. Images multi-arch pour `linux/amd64` et `linux/arm64`.

---

## 🛡️ Prêt pour le Gouvernement et SOC 2

| Fonctionnalité | Contrôles SOC 2 | NIST 800-161 | Alignement STIG/FedRAMP |
|----------------|-------|--------------|--------------|
| Journaux d'audit (--audit-log) | CC6.8 | AU-2 | ✓ |
| Crypto FIPS (--fips) | CC6.1 | SC-13 | ✓ |
| Rapport STIG (--stig) | CC7.3 | RA-5 | ✓ |
| Cache hors ligne (--cache-dir) | A1.2 | SC-8 | ✓ |
| Provenance Sigstore | CC6.2 | SI-7 | ✓ |
| SBOM (SPDX/CycloneDX) | CC7.4 | SA-10 | ✓ |

```bash
# Scan conforme en environnement hermétique
npm-scan scan-lockfile --cache-dir /offline/cache --audit-log /var/log/npm-scan.audit --fips
npm-scan report --stig
```

---

## 📖 Exemples d'utilisation

### Scanner un seul paquet

```bash
# Sortie JSON par défaut avec tous les résultats
npm-scan scan axios

# Générer un SBOM en même temps que le scan
npm-scan scan express --sbom             # CycloneDX JSON
npm-scan scan express --sbom xml         # CycloneDX XML
npm-scan scan express --sbom spdx        # SPDX 2.3

# Appliquer une politique YAML
npm-scan scan some-package --policy .npm-scan.yml

# Scanner un fichier tarball local (pas de téléchargement depuis le registre)
npm-scan scan --file path/to/malicious-package.tgz
```

### Scanner un fichier de verrouillage

```bash
# Scanner les dépendances du projet actuel
npm-scan scan-lockfile

# Scanner un fichier de verrouillage spécifique
npm-scan scan-lockfile -f ./path/to/package-lock.json

# Échouer en CI/CD sur les découvertes de severity haute ou critique (code de sortie 1)
npm-scan scan-lockfile --fail-on high

# Échouer sur toute découverte (low et au-delà)
npm-scan scan-lockfile --fail-on low

# Générer une sortie SARIF v2.1 pour GitHub Advanced Security / VS Code
npm-scan scan-lockfile --sarif results.sarif

# Afficher uniquement le score de risque (0-10) pour les tableaux de bord/seuils
npm-scan scan-lockfile --score-only
```

### Générer des rapports

```bash
# Lister tous les scans récents
npm-scan report

# Voir un scan spécifique
npm-scan report -i 42

# Générer un rapport HTML (gratuit) avec tous les résultats + tableau NIST
npm-scan report -i 42 --html

# Afficher le tableau de conformité NIST 800-161
npm-scan report -i 42 --nist

# Afficher le tableau de conformité EU CRA
npm-scan report --cra

# Export CSV pour Excel / Sheets (prêt pour audit)
npm-scan report --csv risks.csv
npm-scan scan lodash --csv          # CSV vers stdout

# Rapport texte (gratuit)
npm-scan report --text

# Rapport PDF (premium)
npm-scan report --pdf --license-key <key>

# Export SIEM (premium)
npm-scan report --siem cef        # Splunk CEF
npm-scan report --siem ecs        # Elastic ECS
npm-scan report --siem sentinel   # Microsoft Sentinel
npm-scan report --siem qradar     # IBM QRadar

# Combiner tous les scans en un seul rapport
npm-scan report --html            # tous les scans
npm-scan report --pdf             # tous les scans (premium)
```

---

## 🧬 Capacités de détection (Taxonomie ATK)

| ID | Classe d'attaque | Méthode de détection | Sévérité | NIST 800-161 |
|---|---|---|---|---|
| **ATK-001** | Scripts de cycle de vie malveillants (`preinstall`, `postinstall`, `install`) | Statique | 🔴 élevée | SR-3.1 |
| **ATK-002** | Livraison de charge utile obfusquée (hex, base64, chaînes eval) | Statique | 🟠 moyenne | SR-4.2 |
| **ATK-003** | Vol d'identifiants (variables d'env, .npmrc, clés SSH) | Statique + Dynamique | 🔴 élevée | SR-5.3 |
| **ATK-004** | Persistance via les répertoires d'éditeur/config (.vscode, .claude, .cursor) | Statique | 🔴 élevée | SR-6.4 |
| **ATK-005** | Exfiltration réseau (API GitHub, tunneling DNS, HTTP C2) | Statique + Dynamique | ⚫ critique | SR-7.5 |
| **ATK-006** | Confusion de dépendances / accaparement d'espace de noms | Statique (fichier de verrouillage) | 🟠 moyenne | SR-2.2 |
| **ATK-007** | Typosquatting (correspondance par distance d'édition) | Statique | 🟢 faible | SR-2.1 |
| **ATK-008** | Altération de tarball (publié ≠ source) | Statique | 🔴 élevée | SR-8.1 |
| **ATK-009** | Déclencheurs conditionnels/dormants (détection CI, temporel) | Comportementale | 🔴 élevée | SR-9.2 |
| **ATK-010** | Contournement de sandbox / anti-analyse | Comportementale | 🟠 moyenne | SR-10.3 |
| **ATK-011** | Propagation transitive (dissémination latérale de type ver) | Comportementale | 🔴 élevée | SR-11.4 |
| **CVE-2026-48710** | BadHost — contournement d'authentification Starlette par injection d'en-tête Host (CVE-2026-48710, CVSS 7.0). Détection de version de dépendance Python (requirements.txt, pyproject.toml, poetry.lock, Pipfile, setup.py/cfg), heuristique transitive (15 paquets aval connus : fastapi, vllm, litellm, serveurs MCP, etc.), analyse statique de code pour `request.url.path` dangereux en contexte auth/middleware avec suppression par `request.scope["path"]` | Statique + Registre | 🔴 élevée / 🟠 moyenne / ℹ️ info | SR-3.1, SR-5.3 |
| **TRAPDOOR** | Campagne d'attaque multi-écosystème TrapDoor — marqueur de campagne P-2024-001, empreinte de charge utile trap-core.js, liste noire d'éditeur asdxzxc, exfiltration d'identifiants via Gist, empoisonnement de contexte IA (Unicode largeur nulle), noms leurres crypto/DeFi, chiffrement Fernet+ECDH, clé XOR cargo-build-helper-2026, validation d'identifiants STS/API GitHub | Statique + Registre | 🟠 moyenne / 🔴 élevée / ⚫ critique | SR-3.1, SR-5.3, SR-7.5 |
| **NODE_IPC_COMPROMISE** | Compromission de la chaîne d'approvisionnement node-ipc (14 mai 2026) — liste noire de versions (9.1.6/9.2.3/12.0.1) avec épingle de sécurité, vérification SHA-256 du tarball, injection IIFE de charge utile CJS, DNS sur port non standard, résolveur d'amorçage sh.azurestaticprovider.net, zone d'exfiltration DNS TXT bt.node.js, déclencheur d'exécution setImmediate(), artefacts de staging ~/nt-*/, éditeur non autorisé atiertant, détection du rayon d'impact dans les lockfiles avec recommandations d'épingle | Statique + Registre | ⚫ critique | SR-3.1, SR-5.3, SR-7.5 |
| **MSH_SUPPLEMENT** | Supplément Mini Shai-Hulud - obfuscation ctf-scramble-v2 (ARRÊT sur correspondance), persistance de démonisation, détection de killswitch géographique (ru_RU/be_BY), indicateurs C2 dead-drop (OhNoWhatsGoingOnWithGitHub) | Statique + Comportementale | ⚫ critique | SR-3.1, SR-7.5, SR-9.2 |
| **TYPOSQUAT_VPMDHAJ** | Campagne de typosquattage massif (vpmdhaj) - liste noire de mainteneur (ARRÊT sur correspondance), détection de préfixe d'espace de noms vpmdhaj-*, correspondance Levenshtein, stagers de pré-installation, exfiltration d'identifiants cloud (AWS IMDSv2, ECS, Vault, GitHub) | Statique + Registre | ⚫ critique | SR-2.1, SR-3.1, SR-5.3 |
| **AXIOS_POISONING** | Empoisonnement du registre Axios - liste noire de versions (1.14.1/0.30.4, ARRÊT sur correspondance), injection de dépendance leurre (plain-crypto-js), détection de RAT multiplateforme (PowerShell, launchd, systemd, DLL, C2) | Statique + Comportementale | ⚫ critique | SR-3.1, SR-5.3, SR-7.5 |

> **Comment les attaques furtives sont détectées :** ATK-009 détecte les paquets qui vérifient `process.env.CI`, sondent les noms d'hôte ou utilisent une activation temporelle. ATK-009 signale les instructions `debugger`, les sondes `os.hostname()` et l'empreinte environnementale. ATK-011 trace les graphes de dépendances peer pour détecter les schémas de propagation de type ver.  
> Voir [`docs/attack-taxonomy.md`](docs/attack-taxonomy.md) pour la documentation complète de la surface d'évasion et des exemples de PoC.

---

## 📊 Sorties et rapports

### Formats

| Format | Disponibilité | Description |
|--------|-------------|-------------|
| JSON | ✅ Gratuit | Résultats structurés lisibles par machine |
| HTML | ✅ Gratuit | Rapport HTML riche avec tableau de conformité NIST, badges de sévérité, matrice de contrôle |
| Texte | ✅ Gratuit | Rapport texte propre et adapté au terminal |
| CycloneDX SBOM | ✅ Gratuit | SBOM standard de l'industrie avec résultats intégrés comme vulnérabilités |
| SPDX SBOM | ✅ Gratuit | Format de document SPDX 2.3 |
| NIST 800-161 | ✅ Gratuit | Matrice de traçabilité des contrôles (SR-2.1 → SR-11.4) |
| EU CRA | ✅ Gratuit | Cartographie des articles du Cyber Resilience Act |
| PDF | 🔐 Premium | PDF multipage avec page de titre, tableau des résultats, matrice de conformité NIST |
| Splunk CEF | 🔐 Premium | Format d'événement commun pour l'ingestion Splunk |
| Elastic ECS | 🔐 Premium | Format Elastic Common Schema |
| Microsoft Sentinel | 🔐 Premium | Sortie formatée prête pour Sentinel |
| IBM QRadar | 🔐 Premium | Format prêt pour QRadar DSM avec correspondances QID |

### Exemple de sortie

```json
{
  "scanId": 1,
  "findings": [
    {
      "id": "ATK-003",
      "severity": "high",
      "title": "Credential harvesting",
      "evidence": "process.env.NPM_TOKEN detected in postinstall.js:17"
    }
  ]
}
```

---

## ⚙️ Configuration et utilisation avancée

### Politique en tant que code

Définissez des listes blanches, des surcharges de sévérité, des suppressions et des seuils d'échec dans un fichier YAML :

```yaml
# .npm-scan.yml
allowlist:
  - lodash
  - chalk

severity_overrides:
  - id: ATK-001
    severity: medium

suppress:
  - atk_id: ATK-009
  - package: some-package

fail_on: high
```

```bash
npm-scan scan target --policy .npm-scan.yml
```

### Variables d'environnement

| Variable | Description | Défaut |
|----------|-------------|---------|
| `NPM_SCAN_LICENSE_KEY` | Clé de licence Premium / Enterprise | — |
| `NPM_SCAN_DATA_DIR` | Répertoire d'historique des scans | `./.npm-scan` |
| `NPM_SCAN_LOG_LEVEL` | Niveau de verbosité des logs | `info` |

### Licence premium

Contactez leo@lateos.ai pour obtenir une clé de licence premium/enterprise.

```bash
# L'utiliser
npm-scan scan target --license-key <key>
npm-scan report --pdf --license-key <key>
npm-scan report --siem cef --license-key <key>
```

---

## 🔗 Intégrations

### GitHub Actions CI (pour ce dépôt)

Chaque push et PR exécute les tests sur Node 18, 20 et 22 :

```yaml
# .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [18, 20, 22]
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: ${{ matrix.node-version }}
        cache: 'npm'
    - run: npm ci
    - run: npm test
    - run: npm run test:coverage
    - run: node --test test/detectors-corpus.test.js
    - run: npm run lint
    - run: npm run build
```

### GitHub Action (pour les utilisateurs en aval)

Scannez le `package-lock.json` de votre projet à chaque PR — détecte les typosquattings, les charges utiles obfusquées, les voleurs d'identifiants et la propagation de ver avant qu'ils n'atteignent la production :

```yaml
# .github/workflows/scan.yml
name: npm-scan
on:
  pull_request:
    paths:
      - 'package-lock.json'
      - '**/package.json'
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: 20
    - name: Scan lockfile
      uses: lateos/npm-scan@v1
      with:
        scan-type: lockfile
        fail-on: high
```

#### Entrées de l'action

| Entrée | Défaut | Description |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile` pour scanner `package-lock.json` ou `package` pour scanner un paquet npm spécifique |
| `package` | — | Nom du paquet (requis quand `scan-type=package`) |
| `fail-on` | `high` | Faire échouer le workflow à ce seuil de sévérité : `none`, `low`, `medium`, `high`, `critical` |
| `policy-file` | — | Chemin vers un fichier de politique YAML/JSON pour listes blanches, surcharges de sévérité et suppressions |
| `license-key` | — | Clé de licence premium pour l'export SIEM et les rapports PDF |
| `siem-format` | — | Sortie SIEM : `cef`, `ecs`, `sentinel`, `qradar` (premium) |
| `sbom-format` | — | Sortie SBOM : `json`, `xml`, `spdx` |

#### Sorties de l'action

| Sortie | Description |
|--------|-------------|
| `findings-count` | Nombre de résultats détectés |
| `scan-id` | ID du scan pour référence ultérieure dans les rapports |

#### Exemple : scanner un paquet spécifique avec politique + SBOM

```yaml
- uses: lateos/npm-scan@v1
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### Exemple : scanner avec export SIEM (premium)

```yaml
- uses: lateos/npm-scan@v1
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### Pipeline CI/CD

Intégrez directement dans votre pipeline existant sans l'action composite :

```bash
# Scanner le fichier de verrouillage, échouer le build en sévérité élevée
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# Scanner un paquet spécifique, échouer seulement sur critique
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# Générer un SBOM comme artefact de build
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# Générer un rapport de conformité HTML dans le CI
npm-scan report --html > report.html

# Télécharger le rapport comme artefact
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

Voir la [section Démarrage rapide Docker](#-exécutez-lateosnpm-scan-partout-avec-docker--zéro-installation) ci-dessus pour les commandes de tirage, le pipeline Compose et les images multi-arch.

Scannez le `package-lock.json` de votre projet à chaque PR — détecte les typosquattings, les charges utiles obfusquées, les voleurs d'identifiants et la propagation de ver avant qu'ils n'atteignent la production :

```yaml
# .github/workflows/scan.yml
name: npm-scan
on:
  pull_request:
    paths:
      - 'package-lock.json'
      - '**/package.json'
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-node@v4
      with:
        node-version: 20
    - name: Scan lockfile
      uses: lateos/npm-scan@v1
      with:
        scan-type: lockfile
        fail-on: high
```

#### Entrées de l'action

| Entrée | Défaut | Description |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile` pour scanner `package-lock.json` ou `package` pour scanner un paquet npm spécifique |
| `package` | — | Nom du paquet (requis quand `scan-type=package`) |
| `fail-on` | `high` | Faire échouer le workflow à ce seuil de sévérité : `none`, `low`, `medium`, `high`, `critical` |
| `policy-file` | — | Chemin vers un fichier de politique YAML/JSON pour listes blanches, surcharges de sévérité et suppressions |
| `license-key` | — | Clé de licence premium pour l'export SIEM et les rapports PDF |
| `siem-format` | — | Sortie SIEM : `cef`, `ecs`, `sentinel`, `qradar` (premium) |
| `sbom-format` | — | Sortie SBOM : `json`, `xml`, `spdx` |

#### Sorties de l'action

| Sortie | Description |
|--------|-------------|
| `findings-count` | Nombre de résultats détectés |
| `scan-id` | ID du scan pour référence ultérieure dans les rapports |

#### Exemple : scanner un paquet spécifique avec politique + SBOM

```yaml
- uses: lateos/npm-scan@v1
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### Exemple : scanner avec export SIEM (premium)

```yaml
- uses: lateos/npm-scan@v1
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### Pipeline CI/CD

Intégrez directement dans votre pipeline existant sans l'action composite :

```bash
# Scanner le fichier de verrouillage, échouer le build en sévérité élevée
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# Scanner un paquet spécifique, échouer seulement sur critique
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# Générer un SBOM comme artefact de build
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# Générer un rapport de conformité HTML dans le CI
npm-scan report --html > report.html

# Télécharger le rapport comme artefact
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

Voir la [section Démarrage rapide Docker](#-exécutez-lateosnpm-scan-partout-avec-docker--zéro-installation) ci-dessus pour les commandes de tirage, le pipeline Compose et les images multi-arch.

---

## 🗺️ Feuille de route et fonctionnalités Enterprise

### Niveau gratuit (livré)

- Les 11 détecteurs ATK + **MEGALODON** (D1-D6) + **HF_IMPERSONATION** + **MINI_SHAI_HULUD** (D1-D7, 3 vagues, avec **MSH_SUPPLEMENT** D1-D4) + **VSIX_SCAN** (6 détecteurs) + **CVE-2026-48710 (BadHost)** (3 couches) + **TRAPDOOR** (9 règles) + **NODE_IPC_COMPROMISE** (11 règles) + **TYPOSQUAT_VPMDHAJ** (3 règles) + **AXIOS_POISONING** (3 règles)
- Sortie SBOM (CycloneDX + SPDX)
- Rapports HTML, texte et conformité (NIST + EU CRA)
- Moteur de politique en tant que code (YAML)
- Historique de scan local SQLite
- GitHub Action
- Images Docker + pipeline Compose

### Premium (🔐 clé de licence)

- Rapports de conformité PDF avec matrice de traçabilité NIST
- Export SIEM (Splunk CEF, Elastic ECS, Microsoft Sentinel, IBM QRadar)
- Sandbox dynamique (basé sur gVisor — ATK-008–010)
- Analyse d'atteignabilité (filtrage par graphe d'appels)

### Enterprise (🏢 licence personnalisée)

- SAML 2.0 SSO (Okta, Azure AD, OneLogin, Keycloak)
- API REST + webhooks (FastAPI)
- RBAC d'équipe + journaux d'audit
- Chart Helm pour déploiement Kubernetes
- Backend PostgreSQL pour niveau hébergé/équipe
- Support prioritaire avec garantie SLA

---

## 🤝 Contribuer

Nous accueillons les contributions — en particulier les nouveaux détecteurs, l'amélioration de la résistance à l'évasion et les modèles de conformité.

Consultez [`docs/attack-taxonomy.md`](docs/attack-taxonomy.md) pour le processus de gouvernance ATK. Chaque nouveau détecteur nécessite :

1. Un échantillon de preuve de concept
2. Une règle de détection avec tests
3. Une analyse des faux positifs sur les 500 premiers paquets npm
4. Un mappage de contrôle NIST 800-161

### Tests

Le projet utilise **le moteur de test natif Node.js** (`node:test` + `assert/strict`).

```bash
# Exécuter tous les tests
npm test

# Exécuter les tests avec couverture
npm run test:coverage

# Exécuter les tests avec sortie détaillée
npm run test:verbose

# Exécuter le corpus local malveillant/clean (aucun réseau requis)
node --test test/detectors-corpus.test.js
```

**Structure des tests :**
- `test/fixtures/mock-data.js` — simulations partagées, paquets et extraits de code
- `test/db.test.js` — CRUD de base de données (sauvegarde, requête, persistance)
- `test/detectors-edge-cases.test.js` — tests limites par détecteur (no-ops, nettoyages, sévérité)
- `test/detectors-corpus.test.js` — 33 tarballs malveillants + 50 propres (hors ligne)
- `test/fetch.test.js` — extraction de tarball, nettoyage de répertoire temporaire
- `test/policy-edge-cases.test.js` — cas limites dans la suppression, la surcharge, la validation de chargement
- `test/report-snapshots.test.js` — assertions de format HTML/texte/CRA/PDF
- `test/cve-2026-48710-badhost/manifest.test.js` — 13 tests d'analyse de manifeste Python (requirements.txt, pyproject.toml, poetry.lock, cas limites de version)
- `test/cve-2026-48710-badhost/transitive.test.js` — 7 tests de dépendances transitives (Tier 1/2, contrôle de version fastapi, suppression par épinglage)
- `test/cve-2026-48710-badhost/codePattern.test.js` — 6 tests de motifs de code statiques (contexte auth, passage INFO, suppression scope)
- `test/cve-2026-48710-badhost/integration.test.js` — 4 tests d'intégration (résultats composites de bout en bout, projet propre, pas de fichiers Python)
- `test/trapdoor.test.js` — 40 tests de détection de la campagne TrapDoor (D1–D9 : marqueur de campagne, empreinte de charge utile, liste noire d'éditeur, exfiltration Gist, empoisonnement IA, nom leurre, primitives cryptographiques, clé XOR, validation d'identifiants)
- `test/node-ipc.test.js` — 37 tests de détection de compromission node-ipc (D1–D11 : liste noire de versions, hachage tarball, injection CJS, hachage de charge utile, motif DNS C2, résolveur d'amorçage, exfiltration DNS TXT, déclencheur d'exécution, artefacts temporaires, éditeur non autorisé, rayon d'impact)
- `test/msh-supplement.test.js` — 17 tests MSH supplement (obfuscation ctf-scramble-v2, démonisation, killswitch géographique, C2 dead-drop)
- `test/typosquat-vpmdhaj.test.js` — 16 tests campagne typosquattage (blocage mainteneur, détection préfixe, Levenshtein, stagers pré-installation, exfiltration identifiants AWS/ECS/Vault/GitHub)
- `test/axios-poisoning.test.js` — 13 tests empoisonnement Axios (liste noire versions, dépendance leurre, heuristique crypto, RAT multiplateforme, rappel C2)
- `test/cli.test.js` — tests d'intégration commander (aide, version, scan, rapport, gestion d'erreurs)

### Besoin d'aide ?

- 🔒 Voir la [politique de sécurité](SECURITY.md) pour la divulgation des vulnérabilités
- 📖 Lire le [plan du projet](docs/project-plan.md)
- 🧬 Consulter la [taxonomie des attaques](docs/attack-taxonomy.md)
- 🐛 Ouvrir une issue ou une PR

---

## 📄 Licence

Apache-2.0 core + Commons Clause.  
Voir [`LICENSING.md`](LICENSING.md) pour la limite exacte entre les fonctionnalités gratuites et premium.

---

## 👤 À propos du mainteneur

**Roongrunchai Chongolnee** — créateur et mainteneur de `@lateos/npm-scan`. Professionnel de la sécurité certifié (CISSP, CEH, Cisco Security, AWS Cloud Practitioner) avec une décennie d'expérience en sécurité des infrastructures et des applications chez Philips. J'ai construit cet outil pour offrir à la communauté open-source une défense pratique et pilotée par des détecteurs contre les logiciels malveillants de la chaîne d'approvisionnement — et je m'engage à le maintenir transparent, détenu par la communauté et en amélioration continue.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/roongrunchai-chong-c-ab9742108/)
[![GitHub](https://img.shields.io/badge/GitHub-lateos--ai-181717?style=flat-square&logo=github)](https://github.com/lateos-ai/npm-scan)

Les issues, idées et pull requests sont toujours les bienvenus — la sécurité est plus forte quand nous collaborons.

---

```
@lateos/npm-scan — npm supply chain security scanner
Copyright (C) 2026 Lateos

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
```

---

**Scannez votre premier paquet dès maintenant :**

```bash
npx @lateos/npm-scan scan lodash
```