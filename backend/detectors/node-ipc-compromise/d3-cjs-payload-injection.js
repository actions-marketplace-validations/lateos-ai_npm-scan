const IIFE_END_PATTERN = /}\)\(\);\s*$/;
const SIZE_DIFFERENTIAL_THRESHOLD = 50 * 1024;

export function scanCjsPayloadInjection(allFiles) {
  const matches = [];

  let cjsContent = null;
  let mjsContent = null;
  let cjsPath = null;
  let mjsPath = null;

  for (const file of allFiles) {
    const path = file.path?.replace(/\\/g, '/') || '';
    if (path.endsWith('node-ipc.cjs')) {
      cjsContent = file.content || '';
      cjsPath = path;
    }
    if (path.endsWith('node-ipc.mjs')) {
      mjsContent = file.content || '';
      mjsPath = path;
    }
  }

  if (cjsContent && !mjsContent) {
    matches.push({
      file: cjsPath,
      finding: 'cjs-present-no-esm',
      detail: 'node-ipc.cjs present but node-ipc.mjs not found — unable to cross-reference size',
    });
  }

  if (cjsContent && mjsContent) {
    const cjsSize = Buffer.byteLength(cjsContent, 'utf8');
    const mjsSize = Buffer.byteLength(mjsContent, 'utf8');
    const sizeDiff = cjsSize - mjsSize;

    if (sizeDiff > SIZE_DIFFERENTIAL_THRESHOLD) {
      matches.push({
        file: cjsPath,
        finding: 'size-anomaly',
        cjsSize,
        mjsSize,
        sizeDiff,
        detail: `CJS (${cjsSize} bytes) exceeds ESM (${mjsSize} bytes) by ${sizeDiff} bytes — potential injected payload`,
      });
    }

    if (IIFE_END_PATTERN.test(cjsContent.trim())) {
      const trimmed = cjsContent.trim();
      const iifeMatch = trimmed.match(IIFE_END_PATTERN);
      if (iifeMatch) {
        matches.push({
          file: cjsPath,
          finding: 'iife-suffix',
          detail: 'node-ipc.cjs ends with IIFE pattern — potential obfuscated payload appended after module closure',
        });
      }
    }
  }

  if (cjsContent && IIFE_END_PATTERN.test(cjsContent.trim())) {
    const alreadyReported = matches.some(m => m.finding === 'iife-suffix');
    if (!alreadyReported) {
      matches.push({
        file: cjsPath,
        finding: 'iife-suffix',
        detail: 'node-ipc.cjs ends with IIFE pattern — potential obfuscated payload appended after module closure',
      });
    }
  }

  return { triggered: matches.length > 0, matches };
}
