const ZERO_WIDTH_RANGES = [
  [0x200B, 0x200D],
  [0xFEFF, 0xFEFF],
];

function isZeroWidthChar(code) {
  return ZERO_WIDTH_RANGES.some(([lo, hi]) => code >= lo && code <= hi);
}

const TARGET_FILES = /(^|[\\/])(\.cursorrules|CLAUDE\.md)$/i;

export function scanAIPoisoning(allFiles) {
  const matches = [];

  for (const file of allFiles) {
    const path = file.path?.replace(/\\/g, '/') || '';
    if (!TARGET_FILES.test(path)) continue;

    const content = file.content || '';
    const found = [];

    for (let i = 0; i < content.length; i++) {
      const code = content.charCodeAt(i);
      if (isZeroWidthChar(code)) {
        found.push({ char: `U+${code.toString(16).toUpperCase()}`, position: i });
      }
    }

    if (found.length > 0) {
      matches.push({ file: path, zeroWidthChars: found, count: found.length });
    }
  }

  return { triggered: matches.length > 0, matches };
}
