export function scanPayloadFingerprint(allFiles) {
  const matches = [];
  for (const file of allFiles) {
    const path = file.path || '';
    const content = file.content || '';
    const basename = path.split(/[\\/]/).pop();

    const byteSize = Buffer.byteLength(content, 'utf8');

    if (basename === 'trap-core.js') {
      matches.push({ file: path, matchType: 'filename', byteSize });
    }

    if (byteSize === 48485) {
      const alreadyMatched = matches.some((m) => m.file === path);
      if (!alreadyMatched) {
        matches.push({ file: path, matchType: 'byteSize', byteSize });
      }
    }
  }
  return { triggered: matches.length > 0, matches };
}
