# @lateos/npm-scan

[![English](https://img.shields.io/badge/lang-en-blue?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.md)
[![中文](https://img.shields.io/badge/lang-zh--CN-red?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.zh.md)
[![日本語](https://img.shields.io/badge/lang-ja-purple?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.ja.md)
[![Français](https://img.shields.io/badge/lang-fr-orange?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.fr.md)
[![Deutsch](https://img.shields.io/badge/lang-de-green?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.de.md)

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan)
[![License](https://img.shields.io/badge/license-Apache%202.0%20%2B%20Commons%20Clause-blue?style=flat-square)](LICENSING.md)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen?style=flat-square)](package.json)
[![Tests](https://img.shields.io/badge/tests-696%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)
[![Docker](https://img.shields.io/badge/docker-lateos%2Fnpm--scan-2496ED?style=flat-square&logo=docker)](https://hub.docker.com/r/lateos/npm-scan)
[![Sigstore](https://img.shields.io/static/v1?label=Sigstore&message=Provenance&color=green&style=flat-square&logo=sigstore)](https://github.com/lateos-ai/npm-scan/actions/workflows/publish.yml)

**npmエコシステムのためのモダンなサプライチェーンセキュリティ。**  
静的解析＋行動分析で、npm audit、Snyk、Socketが見逃す脅威——難読化ペイロード、認証情報窃取、条件付きトリガー、サンドボックス回避、ワーム型伝播——を検出します。

---

## 📌 問題

2025～2026年のnpmサプライチェーン攻撃の波は、従来のツールがもはや十分ではないことを証明しました。

攻撃者は単純なタイポスクワッティングを超えています。今や彼らは**難読化されたプリインストールフック**、**環境検出の背後に隠れた認証情報窃取ツール**、**時間ベースのアクティベーションによる潜伏バックドア**、そしてピア依存関係を通じて拡散する**ワーム型の推移的伝播**を仕掛けています。

**Megalodonキャンペーン**（2026年）だけでも、偽のGitHub PR、悪意のあるワークフローインジェクション、クラウド認証情報の外部漏洩を介して5,500以上のリポジトリが侵害されました。**@lateos/npm-scan**はこのキャンペーンの痕跡を標準で検出します。

**Mini Shai-Huludワームキャンペーン**（2026年5月）は3つの波でnpmエコシステムを襲いました - TanStack CI/CDハイジャック（6分で84アーティファクト）、AntV/atoolメンテナー侵害（300以上のパッケージに600以上の悪意のあるバージョン）、およびNx Console VS Code拡張機能ポイズニング（CVE-2026-48027）- すべてctf-scramble-v2難読化、CI環境チェック付きデーモン化永続化、制裁対象地域を標的とした地理的キルスイッチ、トークンリカバリのためのGitHub C2 dead-dropチャネルを使用。**@lateos/npm-scan**は2つの検出スイートにわたる10のMini Shai-Huludシグナルすべてを検出します。

増大する攻撃ベクトルは**HuggingFace組織のなりすまし**です。

**TrapDoorキャンペーン**（2026年5月）はnpm、PyPI、Crates.ioにまたがります。

**node-ipc侵害**（2026年5月14日）は期限切れのメンテナーメールドメインを悪用しました。

**大量タイポスクワッティングキャンペーン（vpmdhaj）**（2026年5月）は、`vpmdhaj` npmメンテナーアカウントを武器化し、4時間で14のタイポスクワッティングパッケージを公開しました - プリインストールステイジャー、Bunランタイム乱用、クラウド認証情報の外部漏洩でAWS/CI/CD環境を標的に。**@lateos/npm-scan**はタイポスクワッティングキャンペーンの3つのシグナルすべてを検出します。

**Axiosレジストリポイズニングキャンペーン**（2026年5月）は、npmレジストリのaxiosパッケージメタデータを侵害し、`axios@1.14.1`および`axios@0.30.4`を、クロスプラットフォームRATペイロードを含む注入された依存関係とともに公開しました。**@lateos/npm-scan**は3つのAxiosポイズニングシグナルすべてを検出します。

**npm audit**は既知のCVEをチェックします。**Snyk**は脆弱性をスキャンします。**Socket**はパッケージの動作を分析します。しかし、これらは2025年に出現した攻撃のために設計されたものではありません。

**@lateos/npm-scan**はこの瞬間のために作られました。

---

## 🔬 なぜ@lateos/npm-scanなのか？

| 機能 | npm audit | Snyk | Socket | **@lateos/npm-scan** |
|---|---|---|---|---|
| 既知CVEマッチング | ✅ | ✅ | ❌ | ✅ |
| 静的解析 | ❌ | ✅ | ✅ | ✅ |
| 難読化ペイロード検出 | ❌ | ❌ | ❌ | ✅ |
| ASTレベル、ヒューリスティック解析 | ❌ | ❌ | ❌ | ✅ |
| ランタイム行動サンドボックス | ❌ | ❌ | ✅ | ✅ |
| 条件付きトリガー検出 (ATK-009) | ❌ | ❌ | ❌ | ✅ |
| サンドボックス回避検出 (ATK-010) | ❌ | ❌ | ❌ | ✅ |
| 推移的ワーム伝播 (ATK-011) | ❌ | ❌ | ❌ | ✅ |
| キャンペーン検出 (Megalodon CI/CD) | ❌ | ❌ | ❌ | ✅ |
| ワームキャンペーン検出 (Mini Shai-Hulud 波1-3) | ❌ | ❌ | ❌ | ✅ |
| HFモデルリポジトリなりすまし + READMEクローン | ❌ | ❌ | ❌ | ✅ |
| VS Code拡張機能サプライチェーンスキャン (--vsix) | ❌ | ❌ | ❌ | ✅ |
| Python脆弱性検出 (CVE-2026-48710 BadHost) | ❌ | ❌ | ❌ | ✅ |
| クロスエコシステム攻撃検出 (TrapDoor) | ❌ | ❌ | ❌ | ✅ |
| 期限切れドメインハイジャック検出 (node-ipc) | ❌ | ❌ | ❌ | ✅ |
| マルウェア難読化検出 (ctf-scramble-v2) | ❌ | ❌ | ❌ | ✅ |
| 大量タイポスクワッティングキャンペーン (vpmdhaj) | ❌ | ❌ | ❌ | ✅ |
| レジストリポイズニング検出 (axios偽バージョン) | ❌ | ❌ | ❌ | ✅ |
| 攻撃分類 (ATKシリーズ) | ❌ | ❌ | ❌ | ✅ |
| SBOM出力 (CycloneDX + SPDX) | ❌ | ✅ | ❌ | ✅ |
| NIST 800-161コンプライアンス報告 | ❌ | ❌ | ❌ | ✅ |
| EU CRAコンプライアンス報告 | ❌ | ❌ | ❌ | ✅ |
| SIEMエクスポート (CEF / ECS / Sentinel / QRadar) | ❌ | ❌ | ❌ | ✅ |
| 完全ローカル実行——テレメトリなし | ✅ | ❌ | ❌ | ✅ |
| ポリシー・アズ・コード (YAML許可リスト) | ❌ | ❌ | ❌ | ✅ |

> **プライバシー第一。** すべてのスキャンはお使いのマシン上で実行されます。コードが環境外に送信されることはありません。テレメトリはありません。クラウド依存もありません。

---

## ✨ 主要機能

| アイコン | 機能 | 説明 |
|------|---------|-------------|
| 🕵️ | **ヒューリスティック静的解析** | ASTレベルの検査で、正規表現ベースのツールでは見逃す難読化、evalチェーン、環境プロービング、疑わしいライフサイクルスクリプトを捕捉 |
| 🧠 | **行動検出** | 条件付きトリガー（時間ベース、CI認識）、サンドボックス回避、潜伏アクティベーションパターンを識別 |
| 🧬 | **ATK攻撃分類** | NIST 800-161マッピング付き11の分類攻撃タイプ——バージョン管理、文書化、PR対応 |
| 🪱 | **ワームキャンペーン検出** | Mini Shai-Hulud - 2スイートにわたる10のサブチェック：バースト公開、兄弟妥協、SLSAアテステーション不一致、パブリッシャードリフト、IOCマッチ、トークン流出、ctf-scramble-v2難読化、デーモン化永続化、地理的キルスイッチ、GitHub C2 dead-drop |
| 🧩 | **VSIX拡張スキャン** | `npm-scan scan --vsix` - VS Code Marketplaceサプライチェーン攻撃を検出 |
| 🐍 | **Python脆弱性検出** | CVE-2026-48710 (BadHost) - Starlette Hostヘッダーインジェクション |
| 🪤 | **クロスエコシステム攻撃検出** | TrapDoor - 9サブチェック |
| 📡 | **期限切れドメインハイジャック検出** | node-ipc侵害 - 11サブチェック |
| ☣️ | **マルウェア難読化検出** | ctf-scramble-v2 - パッケージdist/libを既知のマルウェア難読化パターンについてスキャン、CRITICAL停止条件で即時分析停止 |
| 🎭 | **大量タイポスクワッティングキャンペーン検出** | vpmdhajメンテナーブロックリストと停止条件、Levenshteンベースのタイポスクワッティング検出、プリインストールステイジャー識別、AWS ECS/Vault/GitHub認証情報流出パターン |
| ☠️ | **レジストリポイズニング検出** | Axiosバージョンブロックリスト（1.14.1/0.30.4）と停止条件、デコイ依存関係発見（plain-crypto-js）、クロスプラットフォームRATペイロード検出 |
| 🔏 | **プロvenance監査証跡** | Aureus-Elicitor v1.7フレームワーク - HMAC-SHA256署名付き検出マニフェスト、コンテンツハッシュ検証済み監査証跡、ルールプロvenanceURL、キャンペーンソース属性 |
| 📦 | **SBOM生成** | CycloneDX 1.5およびSPDX 2.3、発見項目は脆弱性として埋め込み |
| 🧾 | **コンプライアンス報告** | NIST SP 800-161トレーサビリティマトリックス＋EUサイバーレジリエンス法マッピング（無料） |
| 🔌 | **SIEMエクスポート** | Splunk CEF、Elastic ECS、Microsoft Sentinel、IBM QRadar形式（プレミアム） |
| 📜 | **ポリシー・アズ・コード** | YAML/JSONポリシーエンジン、許可リスト、重要度上書き、抑制、失敗しきい値をサポート |
| 🐳 | **Docker + GitHub Action** | マルチアーキテクチャイメージ、ワンコマンドComposeパイプライン、PRスキャンアクション |
| 🛡️ | **ゼロテレメトリ** | データはあなたのマシンから離れません。クラウドなし。コールバックなし。 |
| 💾 | **ローカルスキャン履歴** | SQLite駆動の永続化、外部依存関係ゼロ |

---

## ⚡ クイックスタート

```bash
# グローバルインストール
npm install -g @lateos/npm-scan

# 単一パッケージをスキャン
npm-scan scan lodash

# ロックファイルをスキャン
npm-scan scan-lockfile

# 最新のスキャンを表示
npm-scan report
```

**インストール不要？問題ありません：**

```bash
npx @lateos/npm-scan scan commander
```

---

## 🐳 Dockerで@lateos/npm-scanをどこでも実行 — インストール不要

```bash
# 単一スキャンをプルして実行 — Node.jsやnpmは不要
docker run --rm lateos/npm-scan:cli scan lodash

# 永続ストレージとComposeを使用した完全パイプライン
docker compose --profile pipeline up -d
```

Node.js不要。`npm install`不要。グローバルパッケージ不要。Dockerがあればどんなシステムでも動作——CIサーバー、エアギャップ環境、Kubernetesクラスター。`linux/amd64`および`linux/arm64`向けマルチアーキテクチャイメージ。

---

## 🛡️ 政府機関・SOC 2 対応

| 機能 | SOC 2 コントロール | NIST 800-161 | STIG/FedRAMP アライメント |
|------|-------|--------------|--------------|
| 監査ログ (--audit-log) | CC6.8 | AU-2 | ✓ |
| FIPS暗号化 (--fips) | CC6.1 | SC-13 | ✓ |
| STIGレポート (--stig) | CC7.3 | RA-5 | ✓ |
| オフラインキャッシュ (--cache-dir) | A1.2 | SC-8 | ✓ |
| Sigstoreプロvenes | CC6.2 | SI-7 | ✓ |
| SBOM (SPDX/CycloneDX) | CC7.4 | SA-10 | ✓ |

```bash
# エアギャップ環境での完全なコンプライアンススキャンを実行
npm-scan scan-lockfile --cache-dir /offline/cache --audit-log /var/log/npm-scan.audit --fips
npm-scan report --stig
```

---

## 📖 使用例

### 単一パッケージのスキャン

```bash
# デフォルトのJSON出力ですべての発見項目を表示
npm-scan scan axios

# スキャンと同時にSBOMを生成
npm-scan scan express --sbom             # CycloneDX JSON
npm-scan scan express --sbom xml         # CycloneDX XML
npm-scan scan express --sbom spdx        # SPDX 2.3

# YAMLポリシーを適用
npm-scan scan some-package --policy .npm-scan.yml

# ローカルtarballをスキャン（レジストリからの取得不要）
npm-scan scan --file path/to/malicious-package.tgz
```

### ロックファイルのスキャン

```bash
# 現在のプロジェクトの依存関係をスキャン
npm-scan scan-lockfile

# 特定のロックファイルをスキャン
npm-scan scan-lockfile -f ./path/to/package-lock.json

# 高重大または致命的な問題でCI/CDを失敗させる（終了コード1）
npm-scan scan-lockfile --fail-on high

# 任何の発見項目でビルドを失敗させる（low以上）
npm-scan scan-lockfile --fail-on low

# SARIF v2.1出力を生成（GitHub Advanced Security / VS Code向け）
npm-scan scan-lockfile --sarif results.sarif

# リスクスコアのみを出力（0-10）（ダッシュボード/閾値向け）
npm-scan scan-lockfile --score-only
```

### レポートの生成

```bash
# 最近のスキャンをすべて一覧表示
npm-scan report

# 特定のスキャンを表示
npm-scan report -i 42

# HTMLレポートを生成（無料）、完全な発見項目＋NIST表付き
npm-scan report -i 42 --html

# NIST 800-161コンプライアンス表を印刷
npm-scan report -i 42 --nist

# EU CRAコンプライアンス表を印刷
npm-scan report --cra

# テキストレポート（無料）
npm-scan report --text

# PDFレポート（プレミアム）
npm-scan report --pdf --license-key <key>

# SIEMエクスポート（プレミアム）
npm-scan report --siem cef        # Splunk CEF
npm-scan report --siem ecs        # Elastic ECS
npm-scan report --siem sentinel   # Microsoft Sentinel
npm-scan report --siem qradar     # IBM QRadar

# すべてのスキャンを1つのレポートに統合
npm-scan report --html            # すべてのスキャン
npm-scan report --pdf             # すべてのスキャン（プレミアム）
```

---

## 🧬 検出機能（ATK分類）

| ID | 攻撃クラス | 検出方法 | 重要度 | NIST 800-161 |
|---|---|---|---|---|
| **ATK-001** | 悪意のあるライフサイクルスクリプト（`preinstall`、`postinstall`、`install`） | 静的 | 🔴 高 | SR-3.1 |
| **ATK-002** | 難読化ペイロード配信（hex、base64、evalチェーン） | 静的 | 🟠 中 | SR-4.2 |
| **ATK-003** | 認証情報収集（環境変数、.npmrc、SSH鍵） | 静的＋動的 | 🔴 高 | SR-5.3 |
| **ATK-004** | エディター/設定ディレクトリを介した永続化（.vscode、.claude、.cursor） | 静的 | 🔴 高 | SR-6.4 |
| **ATK-005** | ネットワーク外部漏洩（GitHub API、DNSトンネリング、HTTP C2） | 静的＋動的 | ⚫ クリティカル | SR-7.5 |
| **ATK-006** | 依存関係混乱／名前空間スクワッティング | 静的（ロックファイル） | 🟠 中 | SR-2.2 |
| **ATK-007** | タイポスクワッティング（編集距離マッチング） | 静的 | 🟢 低 | SR-2.1 |
| **ATK-008** | tarball改ざん（公開版≠ソース） | 静的 | 🔴 高 | SR-8.1 |
| **ATK-009** | 条件付き／潜伏トリガー（CI検出、時間ベース） | 行動 | 🔴 高 | SR-9.2 |
| **ATK-010** | サンドボックス回避／アンチ解析 | 行動 | 🟠 中 | SR-10.3 |
| **ATK-011** | 推移的伝播（ワーム型横方向拡散） | 行動 | 🔴 高 | SR-11.4 |
| **CVE-2026-48710** | BadHost — Starlette Host ヘッダーインジェクション認証バイパス (CVE-2026-48710, CVSS 7.0)。Python 依存関係バージョン検出 (requirements.txt, pyproject.toml, poetry.lock, Pipfile, setup.py/cfg)、推移的ヒューリスティック (15 の既知ダウンストリームパッケージ：fastapi, vllm, litellm, MCP サーバー等)、auth/middleware コンテキストでの危険な `request.url.path` 使用の静的コードパターンスキャン、`request.scope["path"]` による抑制対応 | 静的 + レジストリ | 🔴 高 / 🟠 中 / ℹ️ 情報 | SR-3.1, SR-5.3 |
| **TRAPDOOR** | TrapDoor クロスエコシステム攻撃キャンペーン — キャンペーンマーカー P-2024-001、trap-core.js ペイロードフィンガープリント、パブリッシャーブロックリスト asdxzxc、Gist ベースの認証情報流出、AI コンテキストポイズニング（ゼロ幅 Unicode）、暗号資産/DeFi ルアー名、Fernet+ECDH 暗号化、XOR キー cargo-build-helper-2026、STS/GitHub API 認証情報検証 | 静的 + レジストリ | 🟠 中 / 🔴 高 / ⚫ クリティカル | SR-3.1, SR-5.3, SR-7.5 |
| **NODE_IPC_COMPROMISE** | node-ipc サプライチェーン侵害（2026年5月14日）— バージョンブロックリスト (9.1.6/9.2.3/12.0.1) と安全な固定、tarball SHA-256 検証、CJS ペイロード IIFE インジェクション、非標準ポート DNS C2 パターン、ブートストラップリゾルバー sh.azurestaticprovider.net、DNS TXT 流出ゾーン bt.node.js、setImmediate() ランタイムトリガー、~/nt-*/ ステージングアーティファクト、未承認パブリッシャー atiertant、ロックファイル影響範囲検出と安全な固定推奨 | 静的 + レジストリ | ⚫ クリティカル | SR-3.1, SR-5.3, SR-7.5 |
| **MSH_SUPPLEMENT** | Mini Shai-Hulud補足 - ctf-scramble-v2難読化（一致で停止）、デーモン化永続化、地理的キルスイッチ検出（ru_RU/be_BY）、C2 dead-drop指標（OhNoWhatsGoingOnWithGitHub） | 静的＋行動 | ⚫ クリティカル | SR-3.1, SR-7.5, SR-9.2 |
| **TYPOSQUAT_VPMDHAJ** | 大量タイポスクワッティングキャンペーン（vpmdhaj） - メンテナーブロックリスト（一致で停止）、vpmdhaj-*名前空間プレフィックス検出、Levenshteinタイポスクワッティング、プリインストールステイジャー、クラウド認証情報流出（AWS IMDSv2、ECS、Vault、GitHub） | 静的＋レジストリ | ⚫ クリティカル | SR-2.1, SR-3.1, SR-5.3 |
| **AXIOS_POISONING** | Axiosレジストリポイズニング - バージョンブロックリスト（1.14.1/0.30.4、一致で停止）、デコイ依存関係インジェクション（plain-crypto-js）、クロスプラットフォームRATペイロード検出（PowerShell、launchd、systemd、DLL、C2） | 静的＋行動 | ⚫ クリティカル | SR-3.1, SR-5.3, SR-7.5 |

> **回避型攻撃の捕捉方法：** ATK-009は`process.env.CI`をチェックする、ホスト名をプローブする、または時間ベースのアクティベーションを使用するパッケージを検出します。ATK-010は`debugger`文、`os.hostname()`プローブ、環境フィンガープリンティングをフラグ付けします。ATK-011はピア依存関係グラフをトレースしてワーム型伝播パターンを検出します。  
> 完全な回避面のドキュメントとPoC例については、[`docs/attack-taxonomy.md`](docs/attack-taxonomy.md)を参照してください。

---

## 📊 出力とレポート

### 形式

| 形式 | 利用可能性 | 説明 |
|--------|-------------|-------------|
| JSON | ✅ 無料 | 構造化された機械可読な発見項目 |
| HTML | ✅ 無料 | NISTコンプライアンス表、重要度バッジ、コントロールマトリックス付きリッチHTMLレポート |
| テキスト | ✅ 無料 | クリーンな端末向けテキストレポート |
| CycloneDX SBOM | ✅ 無料 | 発見項目を脆弱性として埋め込んだ業界標準SBOM |
| SPDX SBOM | ✅ 無料 | SPDX 2.3文書形式 |
| NIST 800-161 | ✅ 無料 | コントロールトレーサビリティマトリックス（SR-2.1 → SR-11.4） |
| EU CRA | ✅ 無料 | サイバーレジリエンス法の条項マッピング |
| PDF | 🔐 プレミアム | タイトルページ、発見項目表、NISTコンプライアンスマトリックス付きマルチページPDF |
| Splunk CEF | 🔐 プレミアム | Splunk取り込み用共通イベント形式 |
| Elastic ECS | 🔐 プレミアム | Elastic Common Schema形式 |
| Microsoft Sentinel | 🔐 プレミアム | Sentinel対応のフォーマット済み出力 |
| IBM QRadar | 🔐 プレミアム | QIDマッピング付きQRadar DSM対応形式 |

### 出力サンプル

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

## ⚙️ 設定と高度な使い方

### ポリシー・アズ・コード

YAMLファイルで許可リスト、重要度上書き、抑制、失敗しきい値を定義：

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

### 環境変数

| 変数 | 説明 | デフォルト |
|----------|-------------|---------|
| `NPM_SCAN_LICENSE_KEY` | プレミアム／エンタープライズライセンスキー | — |
| `NPM_SCAN_DATA_DIR` | スキャン履歴ディレクトリ | `./.npm-scan` |
| `NPM_SCAN_LOG_LEVEL` | ログの詳細レベル | `info` |

### プレミアムライセンス

leo@lateos.ai までお問い合わせいただき、高级版/エンタープライズ版ライセンスキーを取得してください。

```bash
# それを使用
npm-scan scan target --license-key <key>
npm-scan report --pdf --license-key <key>
npm-scan report --siem cef --license-key <key>
```

---

## 🔗 インテグレーション

### GitHub Actions CI（このリポジトリ用）

プッシュとPRごとにNode 18、20、22でテストを実行：

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

### GitHub Action（ダウンストリームユーザー向け）

すべてのPRでプロジェクトの`package-lock.json`をスキャン——タイポスクワッティング、難読化ペイロード、認証情報窃取ツール、ワーム伝播を本番環境に到達する前に検出：

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

#### Action入力

| 入力 | デフォルト | 説明 |
|-------|---------|-------------|
| `scan-type` | `lockfile` | `lockfile`は`package-lock.json`をスキャン、`package`は特定のnpmパッケージをスキャン |
| `package` | — | パッケージ名（`scan-type=package`時に必須） |
| `fail-on` | `high` | この重要度しきい値でワークフローを失敗させる：`none`、`low`、`medium`、`high`、`critical` |
| `policy-file` | — | 許可リスト、重要度上書き、抑制用のYAML/JSONポリシーファイルへのパス |
| `license-key` | — | SIEMエクスポートとPDFレポート用のプレミアムライセンスキー |
| `siem-format` | — | SIEM出力：`cef`、`ecs`、`sentinel`、`qradar`（プレミアム） |
| `sbom-format` | — | SBOM出力：`json`、`xml`、`spdx` |

#### Action出力

| 出力 | 説明 |
|--------|-------------|
| `findings-count` | 検出された発見項目の数 |
| `scan-id` | 後でレポートで参照するためのスキャンID |

#### 例：ポリシー＋SBOMで特定パッケージをスキャン

```yaml
- uses: lateos/npm-scan@v1
  with:
    scan-type: package
    package: lodash
    policy-file: .npm-scan.yml
    sbom-format: spdx
    fail-on: critical
```

#### 例：SIEMエクスポートでスキャン（プレミアム）

```yaml
- uses: lateos/npm-scan@v1
  with:
    scan-type: lockfile
    siem-format: cef
    license-key: ${{ secrets.NPM_SCAN_LICENSE_KEY }}
```

### CI/CDパイプライン

複合アクションを使わずに既存のパイプラインに直接統合：

```bash
# ロックファイルをスキャン、高重要度でビルドを失敗
npm-scan scan-lockfile --policy .npm-scan.yml || exit 1

# 特定のパッケージをスキャン、クリティカルのみで失敗
npm-scan scan lodash --policy .npm-scan.yml || exit 1

# SBOMをビルドアーティファクトとして生成
npm-scan scan express --sbom spdx > express-sbom.spdx.json

# CIでHTMLコンプライアンスレポートを生成
npm-scan report --html > report.html

# レポートをアーティファクトとしてアップロード
# uses: actions/upload-artifact@v4
#   with:
#     name: npm-scan-report
#     path: report.html
```

### Docker

---

## 🗺️ ロードマップとエンタープライズ機能

### 無料版（出荷済み）

- 全11ATK検出器（静的＋行動）+ **MEGALODON**（D1-D6）+ **HF_IMPERSONATION** + **MINI_SHAI_HULUD**（D1-D7、3波、**MSH_SUPPLEMENT** D1-D4含む）+ **VSIX_SCAN**（6検出器）+ **CVE-2026-48710（BadHost）**（3層）+ **TRAPDOOR**（9ルール）+ **NODE_IPC_COMPROMISE**（11ルール）+ **TYPOSQUAT_VPMDHAJ**（3ルール）+ **AXIOS_POISONING**（3ルール）
- SBOM出力（CycloneDX + SPDX）
- HTML、テキスト、コンプライアンスレポート（NIST + EU CRA）
- ポリシー・アズ・コードエンジン（YAML）
- ローカルSQLiteスキャン履歴
- GitHub Action
- Dockerイメージ＋Composeパイプライン

### プレミアム（🔐 ライセンスキー）

- NISTトレーサビリティマトリックス付きPDFコンプライアンスレポート
- SIEMエクスポート（Splunk CEF、Elastic ECS、Microsoft Sentinel、IBM QRadar）
- 動的サンドボックス（gVisorベース — ATK-008–010）
- 到達可能性分析（コールグラフフィルタリング）

### エンタープライズ（🏢 カスタムライセンス）

- SAML 2.0 SSO（Okta、Azure AD、OneLogin、Keycloak）
- REST API + webhooks（FastAPI）
- チームRBAC＋監査ログ
- Kubernetes展開用Helmチャート
- ホスティング/チーム階層向けPostgreSQLバックエンド
- SLA保証付き優先サポート

---

## 🤝 コントリビューション

コントリビューションを歓迎します——特に新しい検出器、回避耐性の向上、コンプライアンステンプレートを募集しています。

ATKガバナンスプロセスについては[`docs/attack-taxonomy.md`](docs/attack-taxonomy.md)を参照してください。新しい検出器には以下が必要です：

1. 概念実証サンプル
2. テスト付き検出ルール
3. トップ500 npmパッケージに対する誤検出分析
4. NIST 800-161コントロールマッピング

### テスト

このプロジェクトは**Node.jsネイティブテストランナー**（`node:test` + `assert/strict`）を使用しています。

```bash
# すべてのテストを実行
npm test

# カバレッジ付きでテストを実行
npm run test:coverage

# 詳細な出力付きでテストを実行
npm run test:verbose

# ローカルの悪意／クリーンコーパスを実行（ネットワーク不要）
node --test test/detectors-corpus.test.js
```

**テスト構造：**
- `test/fixtures/mock-data.js` — 共有モックスキャン、パッケージ、コードスニペット
- `test/db.test.js` — データベースCRUD（保存、クエリ、永続化）
- `test/detectors-edge-cases.test.js` — 検出器ごとの境界テスト（no-op、クリーンクリア、重要度）
- `test/detectors-corpus.test.js` — 33悪意＋50クリーンtarball統合テスト（オフライン）
- `test/fetch.test.js` — tarball抽出、一時ディレクトリクリーンアップ
- `test/policy-edge-cases.test.js` — 抑制、上書き、ロード検証のエッジケース
- `test/report-snapshots.test.js` — HTML/テキスト/CRA/PDF形式のアサーション
- `test/cve-2026-48710-badhost/manifest.test.js` — 13のPythonマニフェスト解析テスト（requirements.txt, pyproject.toml, poetry.lock, バージョンエッジケース）
- `test/cve-2026-48710-badhost/transitive.test.js` — 7の推移的依存関係テスト（Tier 1/2, fastapiバージョンゲーティング, 固定抑制）
- `test/cve-2026-48710-badhost/codePattern.test.js` — 6の静的コードパターンテスト（authコンテキスト, INFOフォールスルー, scope抑制）
- `test/cve-2026-48710-badhost/integration.test.js` — 4の統合テスト（エンドツーエンド複合発見項目, クリーンプロジェクト, Pythonファイルなし）
- `test/trapdoor.test.js` — 40のTrapDoorキャンペーン検出テスト（D1–D9：キャンペーンマーカー、ペイロードフィンガープリント、パブリッシャーブロックリスト、Gist流出、AIポイズニング、ルアー名、暗号プリミティブ、XORキー、認証情報検証）
- `test/node-ipc.test.js` — 37のnode-ipc侵害検出テスト（D1–D11：バージョンブロックリスト、tarballハッシュ、CJSインジェクション、ペイロードハッシュ、DNS C2パターン、ブートストラップリゾルバー、DNS TXT流出、ランタイムトリガー、一時アーティファクト、未承認パブリッシャー、影響範囲）
- `test/msh-supplement.test.js` — 17 MSH補足テスト（ctf-scramble-v2停止、デーモン化、地理的キルスイッチ、C2 dead-drop）
- `test/typosquat-vpmdhaj.test.js` — 16タイポスクワッティングキャンペーンテスト（メンテナーブロック、プレフィックス検出、Levenshtein、プリインストールステイジャー、Bunローダー、AWS/ECS/Vault/GitHub認証情報流出）
- `test/axios-poisoning.test.js` — 13 Axiosポイズニングテスト（バージョンブロックリスト停止、デコイ依存関係、暗号ヒューリスティック、クロスプラットフォームRAT、C2コールバック）
- `test/cli.test.js` — commander統合テスト（ヘルプ、バージョン、スキャン、レポート、エラーハンドリング）

### ヘルプが必要ですか？

- 🔒 [セキュリティポリシー](SECURITY.md)で脆弱性の開示方法を確認
- 📖 [プロジェクト計画](docs/project-plan.md)を読む
- 🧬 [攻撃分類](docs/attack-taxonomy.md)を確認
- 🐛 IssueまたはPRを開く

---

## 📄 ライセンス

Apache-2.0コア＋Commons Clause。  
無料版とプレミアム版機能の正確な境界については[`LICENSING.md`](LICENSING.md)を参照してください。

---

## 👤 メンテナーについて

**Roongrunchai Chongolnee** — `@lateos/npm-scan` の作成者兼メンテナー。CISSP、CEH、Cisco Security、AWS Cloud Practitioner の認定を持つセキュリティ専門家で、Philips で10年間のインフラおよびアプリケーションセキュリティの経験があります。このツールは、オープンソースコミュニティに実用的で検出器駆動型のサプライチェーン型マルウェア防御を提供するために構築しました。透明性、コミュニティ所有、継続的改善に取り組んでいます。

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/roongrunchai-chong-c-ab9742108/)
[![GitHub](https://img.shields.io/badge/GitHub-lateos--ai-181717?style=flat-square&logo=github)](https://github.com/lateos-ai/npm-scan)

Issue、アイデア、PRはいつでも歓迎します——セキュリティは協力によって最も強力になります。

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

**最初のパッケージを今すぐスキャン：**

```bash
npx @lateos/npm-scan scan lodash
```
```