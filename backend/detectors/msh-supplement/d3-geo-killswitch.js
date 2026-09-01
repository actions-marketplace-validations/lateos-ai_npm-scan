const LOCALE_CHECKS = [
  /process\.env\.LANG/,
  /process\.env\.LC_ALL/,
  /process\.env\.LC_MESSAGES/,
  /Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone/,
  /Intl\.DateTimeFormat\.resolvedOptions\b/,
];
const TARGET_LOCALES = /ru_RU|be_BY|uk_UA/;
const SILENT_EXIT_RE = /process\.exit\s*\(\s*0\s*\)/;

export function scanGeoKillswitch(files = []) {
  const code = files.map((f) => f.content || '').join('\n');
  if (!code) {
    return { triggered: false, targetedLocales: [], triggerBehavior: null };
  }

  const hasLocaleCheck = LOCALE_CHECKS.some((re) => re.test(code));
  if (!hasLocaleCheck) {
    return { triggered: false, targetedLocales: [], triggerBehavior: null };
  }

  const hasTargetLocale = TARGET_LOCALES.test(code);
  const hasSilentExit = SILENT_EXIT_RE.test(code);

  if (hasTargetLocale || hasSilentExit) {
    const matchedLocales = [];
    if (/ru_RU/.test(code)) {
      matchedLocales.push('ru_RU');
    }
    if (/be_BY/.test(code)) {
      matchedLocales.push('be_BY');
    }
    if (/uk_UA/.test(code)) {
      matchedLocales.push('uk_UA');
    }

    return {
      triggered: true,
      targetedLocales: matchedLocales.length > 0 ? matchedLocales : ['ru_RU', 'be_BY'],
      triggerBehavior: hasSilentExit
        ? 'Silent exit'
        : 'Locale/timezone match with conditional behavior',
    };
  }

  return { triggered: false, targetedLocales: [], triggerBehavior: null };
}
