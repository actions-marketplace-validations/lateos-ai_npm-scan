const TARGET_EXTENSIONS = ['.md', '.sh', '.json'];
const TARGET_FILENAMES = new Set(['.cursorrules', 'CLAUDE.md', 'README.md', 'package.json']);

export function scanCampaignMarker(allFiles) {
  const matches = [];
  for (const file of allFiles) {
    const path = file.path || '';
    const content = file.content || '';
    const basename = path.split(/[\\/]/).pop();
    const ext = path.includes('.') ? '.' + path.split('.').pop() : '';

    const isTarget = TARGET_FILENAMES.has(basename) || TARGET_EXTENSIONS.includes(ext);
    if (!isTarget) continue;

    if (content.includes('P-2024-001')) {
      matches.push({ file: path });
    }
  }
  return { triggered: matches.length > 0, matches };
}
