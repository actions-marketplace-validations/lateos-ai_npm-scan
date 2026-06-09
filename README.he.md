# npm-scan

[![English](https://img.shields.io/badge/lang-en-blue?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.md)
[![中文](https://img.shields.io/badge/lang-zh--CN-red?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.zh.md)
[![日本語](https://img.shields.io/badge/lang-ja-purple?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.ja.md)
[![Français](https://img.shields.io/badge/lang-fr-orange?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.fr.md)
[![Deutsch](https://img.shields.io/badge/lang-de-green?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.de.md)
[![עברית](https://img.shields.io/badge/lang-he--IL-lightblue?style=flat-square)](https://github.com/lateos-ai/npm-scan/blob/main/README.he.md)

[![npm version](https://img.shields.io/npm/v/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![npm downloads/week](https://img.shields.io/npm/dw/@lateos/npm-scan?style=flat-square)](https://www.npmjs.com/package/@lateos/npm-scan) [![License](https://img.shields.io/badge/license-MIT%20OR%20BLA-blue?style=flat-square)](LICENSING.md) [![Tests](https://img.shields.io/badge/tests-830%2B%20passing-brightgreen?style=flat-square)](https://github.com/lateos-ai/npm-scan)

**זיהוי איומי שרשרת האספקה ש־npm audit, Snyk ו־Socket מפספסים.**

מזהה מטענים מוסתרים, גנבי אישורים, rootkits בליבת מערכת, hooks מסוג eBPF, חילוץ זיכרון, זיוף GitHub והתקפות ממוקדות בינה מלאכותית.

---

## למה npm-scan?

**כלים מסורתיים מיושנים.** npm audit בודק מאגרי CVE. Snyk סורק גרסאות תלויות. אף אחד מהם לא תופס דפוסי התנהגות.

**גל ההתקפות של 2026:**
- Rootkits בליבת eBPF (בלתי נראים לניטור)
- חילוץ אישורים ברמת הזיכרון (אסימוני OIDC)
- קוד מתגונן עצמי (ניטרול ניפוי שגיאות, ניטרול שינויים)
- זיוף מחבר GitHub ("claude@users.noreply.github.com")
- מיקוד פלטפורמות AI (מפתחות Claude, OpenAI, Cursor, Mistral)
- התפשטות דמוית תולעת (פרסום אוטומטי עם אסימונים גנובים)

npm-scan מזהה את כל אלה. **95%+ ביטחון בקמפיינים אמיתיים.**

---

## מה מזוהה

| קטגוריה | דוגמאות | זיהוי |
|----------|----------|-----------|
| **גניבת אישורים** | איסוף משתני סביבה, חילוץ אסימונים | 98% |
| **התקפות ליבה** | Rootkits eBPF, הסלמת הרשאות | 95% |
| **התחמקות קוד** | הסתרה, קוד מתגונן עצמי, ניטרול ניפוי | 95% |
| **חילוץ זיכרון** | גישה לאסימוני OIDC, מיקוד מפתחות AI | 95% |
| **התקפות GitHub** | זיוף מחבר, חטיפת force-push | 99% |
| **התפשטות תולעת** | פרסום אוטומטי באמצעות אישורים גנובים | 95% |

---

## התחלה מהירה

```bash
npm install -g @lateos/npm-scan
npm-scan axios
npm-scan scan-lockfile
npm-scan express --json > findings.json
```

---

## תכונות עיקריות

- ✅ **23 גלאים (D1–D25)** המכסים וקטורי תקיפה של שרשרת אספקה
- ✅ **אימות מול קמפיינים אמיתיים** (IronWorm, Miasma, Dependency Confusion)
- ✅ **ריצה מקומית** — ללא טלמטריה, ללא תלות בענן
- ✅ **מהיר** — פחות מ־30 שניות להרצת CI/CD
- ✅ **מדיניות כקוד** — רשימות לבנות YAML, עקיפת חומרה
- ✅ **SBOM + SARIF** — CycloneDX, SPDX, אבטחת GitHub
- ✅ **GitHub Action** — שילוב CI/CD בשורה אחת
- ✅ **Docker** — תמונות מרובות ארכיטקטורות

---

## GitHub Action

```yaml
- uses: lateos-ai/npm-scan@v1
  with:
    scan-type: lockfile
    fail-on: critical
```

---

## רישוי

**חינם (MIT):** מייסדים עצמאיים, מלכ"רים, סטודנטים, פרויקטי קוד פתוח.
**בתשלום (BLA):** חברות עם עובדים.

ראה [LICENSING.md](LICENSING.md) לפרטים.

**ארגוני?** [קבל רישיון מסחרי](https://lateos.ai/npm-scan/licensing)

---

## עוד

- [תיעוד מלא](https://github.com/lateos-ai/npm-scan)
- [טקסונומיית התקפות (סדרת ATK)](https://github.com/lateos-ai/npm-scan/blob/main/DETECTORS.md)
- [נתוני אימות קמפיינים](https://github.com/lateos-ai/npm-scan/blob/main/VALIDATION.md)

---

**סרוק את החבילה הראשונה שלך עכשיו:**

```bash
npx @lateos/npm-scan scan axios
```
