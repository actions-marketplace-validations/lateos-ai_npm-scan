# npm-scan

[![English](https://img.shields.io/badge/lang-en-blue?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.md)
[![中文](https://img.shields.io/badge/lang-zh--CN-red?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.zh.md)
[![日本語](https://img.shields.io/badge/lang-ja-purple?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.ja.md)
[![Français](https://img.shields.io/badge/lang-fr-orange?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.fr.md)
[![Deutsch](https://img.shields.io/badge/lang-de-green?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.de.md)
[![עברית](https://img.shields.io/badge/lang-he--IL-lightblue?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.he.md)

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![npm downloads/week](https://img.shields.io/npm/dw/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![License](https://img.shields.io/badge/license-MIT%20OR%20BLA-blue?style=flat-square)](LICENSING.md) [![Tests](https://img.shields.io/badge/tests-830%2B%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)

**npm audit、Snyk、Socketが見逃すサプライチェーン脅威を検出。**

難読化ペイロード、認証情報窃取、カーネルルートキット、eBPFフック、メモリ抽出、GitHubスプーフィング、AI標的型攻撃を検出します。

---

## npm-scanを選ぶ理由

**従来のツールは時代遅れです。** npm auditは既知のCVEをチェックし、Snykは依存関係のバージョンをスキャンします。どちらも行動パターンを捕捉できません。

**2026年の攻撃の波：**
- eBPFカーネルルートキット（監視から不可視）
- メモリレベルの認証情報抽出（OIDCトークン）
- 自己防衛コード（アンチデバッグ、アンチ改ざん）
- GitHub作者スプーフィング（"claude@users.noreply.github.com"）
- AIプラットフォーム標的化（Claude、OpenAI、Cursor、Mistralキー）
- ワーム型伝播（盗まれたトークンでの自動再公開）

npm-scanはこれらすべてを検出します。**実際のキャンペーンで95%以上の信頼性。**

---

## 検出内容

| カテゴリ | 例 | 検出率 |
|----------|-----|--------|
| **認証情報窃取** | 環境変数収集、トークン流出 | 98% |
| **カーネル攻撃** | eBPFルートキット、権限昇格 | 95% |
| **コード回避** | 難読化、自己防衛コード、アンチデバッグ | 95% |
| **メモリ抽出** | OIDCトークンアクセス、AIキー標的化 | 95% |
| **GitHub攻撃** | 作者スプーフィング、force-push乗っ取り | 99% |
| **ワーム伝播** | 盗まれた認証情報による自動再公開 | 95% |

---

## クイックスタート

```bash
npm install -g @lateos/npm-scan
npm-scan axios
npm-scan scan-lockfile
npm-scan express --json > findings.json
```

---

## 主な機能

- ✅ **23の検出器（D1–D25）**がサプライチェーン攻撃ベクトルをカバー
- ✅ **実際のキャンペーンでの検証**（IronWorm、Miasma、Dependency Confusion）
- ✅ **ローカル実行** — テレメトリなし、クラウド依存なし
- ✅ **高速** — CI/CD実行あたり30秒未満
- ✅ **ポリシー・アズ・コード** — YAML許可リスト、重要度上書き
- ✅ **SBOM + SARIF** — CycloneDX、SPDX、GitHub Security
- ✅ **GitHub Action** — 一行のCI/CD統合
- ✅ **Docker** — マルチアーキテクチャイメージ

---

## GitHub Action

```yaml
- uses: lateos-ai/npm-scan@v1
  with:
    scan-type: lockfile
    fail-on: critical
```

---

## ライセンス

**無料（MIT）：** 個人創業者、非営利団体、学生、オープンソースプロジェクト。
**有料（BLA）：** 従業員のいる企業。

詳細は [LICENSING.md](LICENSING.md) をご覧ください。

**エンタープライズ？** [商用ライセンスを取得](https://lateos.ai/npm-scan/licensing)

---

## 詳細

- [完全なドキュメント](https://github.com/lateos-ai/npm-scan)
- [攻撃分類（ATKシリーズ）](https://github.com/lateos-ai/npm-scan/blob/main/DETECTORS.md)
- [キャンペーン検証データ](https://github.com/lateos-ai/npm-scan/blob/main/VALIDATION.md)

---

**最初のパッケージを今すぐスキャン：**

```bash
npx @lateos/npm-scan scan axios
```
