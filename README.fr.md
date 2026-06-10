# npm-scan

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![License](https://img.shields.io/badge/license-MIT%20OR%20BLA-blue?style=flat-square)](LICENSING.md) [![Tests](https://img.shields.io/badge/tests-830%2B%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)

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

## Couverture : npm-scan vs outils du marché

| Vecteur d'attaque | npm-scan | npm audit | Snyk | Socket | Sonatype |
|---|:---:|:---:|:---:|:---:|:---:|
| **Miasma/Hades (binding.gyp)** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 40% | ❌ 0% |
| **Rootkit noyau eBPF** | ✅ 95% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **Ciblage de jetons IA** | ✅ 98% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **Usurpation d'auteur GitHub** | ✅ 99% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **Extraction mémoire de credentials** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 20% | ❌ 0% |
| **Code auto-défensif** | ✅ 95% | ❌ 0% | ⚠️ 25% | ⚠️ 45% | ❌ 0% |
| **Exécution par chargement de module** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 50% | ❌ 0% |
| **CVE connus** | ✅ Oui | ✅ Oui | ✅ Oui | ✅ Oui | ✅ Oui |

**Légende :** ✅ = 85%+ de détection | ⚠️ = 15–80% de détection | ❌ = 0% de détection

---

## Réduction des risques et conformité

**Approche mono-outil = Angle mort = Responsabilité coûteuse**

Un paquet npm compromis coûte à votre entreprise :
- **Violation de données :** 4,5 M$ en moyenne (IBM, 2024)
- **Amendes réglementaires :** Violations SOC 2 (100 K$+), RGPD (10 M$+), audits de conformité
- **Temps d'arrêt :** 5 K$–50 K$ par heure de revenus perdus
- **Réputation :** Atteinte à la marque, érosion de la confiance client
- **Juridique :** Poursuites des clients affectés, demandes d'indemnisation

**Un outil traditionnel seul rate les attaques comportementales.** Si npm audit + Snyk ne voient rien, mais que des attaquants volent vos identifiants AWS via un schéma comportemental, vous êtes responsable.

**npm-scan + npm audit = Couverture complète = Réduction des risques**

En détectant les 95%+ d'attaques que les outils traditionnels manquent, vous réduisez :
- ✅ Probabilité de violation (la détection comportementale capture les attaques avant les dégâts)
- ✅ Risque de non-conformité (diligence raisonnable : vous avez utilisé plusieurs méthodes de détection)
- ✅ Responsabilité financière (les auditeurs demanderont : « Comment avez-vous vérifié la sécurité de la chaîne d'approvisionnement ? »)
- ✅ Impact client (détection plus rapide = correction plus rapide = moins de clients affectés)

**Rentabilité :** npm-scan (2,4 K$/an entreprise) vs violation de données (4,5 M$ en moyenne). ROI : 1 875x.

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
- ✅ **Intégration CI/CD** — fonctionne avec toute plateforme CI/CD
- ✅ **Docker** — Images multi-architecture

---

## Intégration CI/CD

```yaml
# Exemple GitHub Actions
- name: Scan with npm-scan
  run: |
    npm install -g @lateos/npm-scan
    npm-scan scan-lockfile --fail-on critical
```

Fonctionne avec GitHub Actions, GitLab CI, Jenkins, ou toute plateforme CI/CD.

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
