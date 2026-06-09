# npm-scan

[![English](https://img.shields.io/badge/lang-en-blue?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.md)
[![中文](https://img.shields.io/badge/lang-zh--CN-red?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.zh.md)
[![日本語](https://img.shields.io/badge/lang-ja-purple?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.ja.md)
[![Français](https://img.shields.io/badge/lang-fr-orange?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.fr.md)
[![Deutsch](https://img.shields.io/badge/lang-de-green?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.de.md)

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![npm downloads/week](https://img.shields.io/npm/dw/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![License](https://img.shields.io/badge/license-MIT%20OR%20BLA-blue?style=flat-square)](LICENSING.md) [![Tests](https://img.shields.io/badge/tests-830%2B%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)

**捕获 npm audit、Snyk 和 Socket 遗漏的供应链威胁。**

检测混淆载荷、凭证窃取器、内核 rootkit、eBPF 钩子、内存提取、GitHub 伪造和 AI 定向攻击。

---

## 为什么选择 npm-scan？

**传统工具已经过时。** npm audit 检查 CVE 数据库。Snyk 扫描依赖版本。两者都无法捕获行为模式。

**2026 年的攻击浪潮：**
- eBPF 内核 rootkit（对监控不可见）
- 内存级凭证提取（OIDC 令牌）
- 自防御代码（反调试、反篡改）
- GitHub 作者伪造（"claude@users.noreply.github.com"）
- AI 平台定向（Claude、OpenAI、Cursor、Mistral 密钥）
- 蠕虫式传播（使用窃取令牌自动重新发布）

npm-scan 检测所有这些。**在真实攻击活动中达到 95%+ 置信度。**

---

## 检测内容

| 类别 | 示例 | 检测率 |
|----------|----------|-----------|
| **凭证窃取** | 环境变量收集、令牌外泄 | 98% |
| **内核攻击** | eBPF rootkit、权限提升 | 95% |
| **代码规避** | 混淆、自防御代码、反调试 | 95% |
| **内存提取** | OIDC 令牌访问、AI 密钥定向 | 95% |
| **GitHub 攻击** | 作者伪造、强制推送劫持 | 99% |
| **蠕虫传播** | 通过窃取令牌自动重新发布 | 95% |

---

## 快速开始

```bash
npm install -g @lateos/npm-scan
npm-scan axios
npm-scan scan-lockfile
npm-scan express --json > findings.json
```

---

## 核心功能

- ✅ **23 个检测器（D1–D25）**覆盖供应链攻击向量
- ✅ **真实攻击活动验证**（IronWorm、Miasma、依赖混淆）
- ✅ **本地运行** — 无遥测、无云依赖
- ✅ **快速** — 每次 CI/CD 运行 <30 秒
- ✅ **策略即代码** — YAML 白名单、严重性覆盖
- ✅ **SBOM + SARIF** — CycloneDX、SPDX、GitHub 安全
- ✅ **GitHub Action** — 一行 CI/CD 集成
- ✅ **Docker** — 多架构镜像

---

## GitHub Action

```yaml
- uses: lateos-ai/npm-scan@v1
  with:
    scan-type: lockfile
    fail-on: critical
```

---

## 许可

**免费（MIT）：** 独立创始人、非营利组织、学生、开源项目。
**付费（BLA）：** 有员工的公司。

详情请参阅 [LICENSING.md](LICENSING.md)。

**企业版？** [获取商业许可](https://lateos.ai/npm-scan/licensing)

---

## 更多

- [完整文档](https://github.com/lateos-ai/npm-scan)
- [攻击分类（ATK 系列）](https://github.com/lateos-ai/npm-scan/blob/main/DETECTORS.md)
- [攻击活动验证数据](https://github.com/lateos-ai/npm-scan/blob/main/VALIDATION.md)

---

**立即扫描您的第一个包：**

```bash
npx @lateos/npm-scan scan axios
```
