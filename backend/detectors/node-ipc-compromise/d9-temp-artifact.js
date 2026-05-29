const NT_DIR_PATTERN = /~\/(nt-(?:[\w-]+))\/.*\.tar\.gz/;

export function scanTempArtifact(allFiles) {
  const matches = [];

  for (const file of allFiles) {
    const path = file.path || '';

    const artifactMatch = path.match(NT_DIR_PATTERN);
    if (artifactMatch) {
      matches.push({
        file: path,
        dirName: artifactMatch[1],
        detail: `Staging artifact found in ~/${artifactMatch[1]}/ — exfil may have been interrupted`,
      });
    }
  }

  return { triggered: matches.length > 0, matches };
}
