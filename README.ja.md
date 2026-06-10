# npm-scan

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![License](https://img.shields.io/badge/license-MIT%20OR%20BLA-blue?style=flat-square)](LICENSING.md) [![Tests](https://img.shields.io/badge/tests-830%2B%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)

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

## 比較：npm-scan vs 業界ツール

| 攻撃ベクトル | npm-scan | npm audit | Snyk | Socket | Sonatype |
|---|:---:|:---:|:---:|:---:|:---:|
| **Miasma/Hades (binding.gyp)** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 40% | ❌ 0% |
| **eBPF カーネルルートキット** | ✅ 95% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **AI トークン標的化** | ✅ 98% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **GitHub 作者スプーフィング** | ✅ 99% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **メモリ認証情報抽出** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 20% | ❌ 0% |
| **自己防衛コード** | ✅ 95% | ❌ 0% | ⚠️ 25% | ⚠️ 45% | ❌ 0% |
| **モジュールロード実行** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 50% | ❌ 0% |
| **既知のCVE** | ✅ はい | ✅ はい | ✅ はい | ✅ はい | ✅ はい |

**凡例：** ✅ = 85%+ 検出率 | ⚠️ = 15–80% 検出率 | ❌ = 0% 検出率

---

## リスク低減とコンプライアンス

**単一ツールアプローチ = 盲点 = 高額な責任**

侵害されたnpmパッケージは企業にコストをもたらします：
- **データ漏洩：** 平均450万ドル（IBM、2024年）
- **規制罰金：** SOC 2違反（10万ドル+）、GDPR（1000万ドル+）、コンプライアンス監査
- **ダウンタイム：** 1時間あたり5K～50Kドルの収益損失
- **評判：** ブランド損害、顧客信頼の低下
- **訴訟：** 影響を受けた顧客からの訴訟、賠償責任

**従来のツールだけでは行動攻撃を見逃します。** npm audit + Snykが何も検出しなくても、攻撃者が行動パターンを介してAWS認証情報を盗んだ場合、あなたが責任を負います。

**npm-scan + npm audit = 完全なカバレッジ = リスク低減**

従来のツールが見逃す95%+の攻撃を捕捉することで、以下を低減します：
- ✅ 漏洩確率（行動検出が被害発生前に攻撃を捕捉）
- ✅ コンプライアンス違反リスク（デューデリジェンス：複数の検出方法を使用）
- ✅ 財務責任（監査人は「サプライチェーンセキュリティをどのように検証しましたか？」と尋ねます）
- ✅ 顧客への影響（迅速な検出 = 迅速な修復 = 影響を受ける顧客の減少）

**費用対効果：** npm-scan（エンタープライズ $2.4K/年）vs データ漏洩（平均 $4.5M）。ROI：1,875倍。

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
- ✅ **CI/CD 統合** — あらゆるCI/CDプラットフォームと連携
- ✅ **Docker** — マルチアーキテクチャイメージ

---

## CI/CD 統合

```yaml
# GitHub Actionsの例
- name: Scan with npm-scan
  run: |
    npm install -g @lateos/npm-scan
    npm-scan scan-lockfile --fail-on critical
```

GitHub Actions、GitLab CI、Jenkins、または任意のCI/CDプラットフォームで動作します。

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
