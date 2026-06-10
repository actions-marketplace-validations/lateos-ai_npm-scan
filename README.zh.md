# npm-scan

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![License](https://img.shields.io/badge/license-MIT%20OR%20BLA-blue?style=flat-square)](LICENSING.md) [![Tests](https://img.shields.io/badge/tests-830%2B%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)

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

## 覆盖范围：npm-scan vs 行业工具

| 攻击向量 | npm-scan | npm audit | Snyk | Socket | Sonatype |
|---|:---:|:---:|:---:|:---:|:---:|
| **Miasma/Hades (binding.gyp)** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 40% | ❌ 0% |
| **eBPF 内核 Rootkit** | ✅ 95% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **AI 令牌定向** | ✅ 98% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **GitHub 作者伪造** | ✅ 99% | ❌ 0% | ❌ 0% | ❌ 0% | ❌ 0% |
| **内存凭证提取** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 20% | ❌ 0% |
| **自防御代码** | ✅ 95% | ❌ 0% | ⚠️ 25% | ⚠️ 45% | ❌ 0% |
| **模块加载执行** | ✅ 95% | ❌ 0% | ❌ 0% | ⚠️ 50% | ❌ 0% |
| **已知 CVE** | ✅ 是 | ✅ 是 | ✅ 是 | ✅ 是 | ✅ 是 |

**图例：** ✅ = 85%+ 检测率 | ⚠️ = 15–80% 检测率 | ❌ = 0% 检测率

---

## 风险降低与合规性

**单一工具方法 = 盲点 = 昂贵的责任**

受损的 npm 包将使您的公司付出代价：
- **数据泄露：** 平均 450 万美元（IBM，2024）
- **监管罚款：** SOC 2 违规（10 万美元+）、GDPR（1000 万美元+）、合规审计
- **停机时间：** 每小时损失 5K–50K 美元收入
- **声誉：** 品牌损害、客户信任侵蚀
- **法律：** 受影响客户诉讼、责任索赔

**传统工具单独使用会遗漏行为攻击。** 如果 npm audit + Snyk 什么都没发现，但攻击者通过行为模式窃取了您的 AWS 凭证，您将承担责任。

**npm-scan + npm audit = 完整覆盖 = 风险降低**

通过捕获传统工具遗漏的 95%+ 攻击，您可以降低：
- ✅ 泄露概率（行为检测在损害发生前捕获攻击）
- ✅ 合规违规风险（尽职调查：您使用了多种检测方法）
- ✅ 财务责任（审计师会问："您如何验证供应链安全？"）
- ✅ 客户影响（更快检测 = 更快修复 = 更少受影响客户）

**成本效益：** npm-scan（企业版 $2.4K/年）vs 数据泄露（平均 $4.5M）。ROI：1,875 倍。

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
- ✅ **CI/CD 集成** — 与任意 CI/CD 平台配合使用
- ✅ **Docker** — 多架构镜像

---

## CI/CD 集成

```yaml
# GitHub Actions 示例
- name: Scan with npm-scan
  run: |
    npm install -g @lateos/npm-scan
    npm-scan scan-lockfile --fail-on critical
```

适用于 GitHub Actions、GitLab CI、Jenkins 或任何 CI/CD 平台。

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
