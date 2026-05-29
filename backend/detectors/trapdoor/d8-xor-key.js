export function scanXorKey(allFiles) {
  const matches = [];
  for (const file of allFiles) {
    const path = file.path?.replace(/\\/g, '/') || '';
    const isLockFile = /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|pnpm-lock\.yml|Cargo\.lock|Cargo\.toml)/i.test(path);
    const isBundled = /\.node$|vendor|native/i.test(path);
    if (!isLockFile && !isBundled) continue;

    const content = file.content || '';
    if (content.includes('cargo-build-helper-2026')) {
      matches.push({ file: path });
    }
  }
  return { triggered: matches.length > 0, matches };
}
