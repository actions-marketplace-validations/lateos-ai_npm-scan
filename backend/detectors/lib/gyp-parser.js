export function parseGyp(content) {
  const AST = {
    targets: [],
    conditions: [],
    variables: {},
    includes: [],
    shellExecs: [],
    macroInjections: [],
    linkerFlags: [],
  };

  if (!content) return AST;

  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const lineNum = i + 1;

    const shellMatch = trimmed.match(/<!\(([^)]*)\)/);
    if (shellMatch) {
      AST.shellExecs.push({
        command: shellMatch[1].trim(),
        line: lineNum,
      });
    }

    const includeMatch = trimmed.match(/['"]([^'"]+\.gypi)['"]/);
    if (includeMatch) {
      AST.includes.push({
        path: includeMatch[1],
        line: lineNum,
      });
    }

    const macroMatch = trimmed.match(/-D\s*['"]?([A-Z_]+)=([^'"\s]+)/);
    if (macroMatch) {
      AST.macroInjections.push({
        name: macroMatch[1],
        value: macroMatch[2],
        line: lineNum,
      });
    }

    if (
      trimmed.startsWith('targets') ||
      trimmed.startsWith('"targets"') ||
      trimmed.startsWith("'targets'")
    ) {
      AST.targets.push({ line: lineNum });
    }

    if (
      trimmed.startsWith('conditions') ||
      trimmed.startsWith('"conditions"') ||
      trimmed.startsWith("'conditions'")
    ) {
      AST.conditions.push({ line: lineNum });
    }

    const varMatch = trimmed.match(/['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*:/);
    if (varMatch && !trimmed.startsWith('#')) {
      AST.variables[varMatch[1]] = { line: lineNum };
    }

    const linkerMatch = trimmed.match(/['"](?:-l|-L|-rpath)[^'"]+/g);
    if (linkerMatch) {
      for (const lf of linkerMatch) {
        AST.linkerFlags.push({
          flag: lf.replace(/['"]/g, ''),
          line: lineNum,
        });
      }
    }
  }

  return AST;
}

export function extractShellCommands(gypContent) {
  const results = [];
  const re = /<!\(([^)]*)\)/g;
  let m;
  while ((m = re.exec(gypContent)) !== null) {
    results.push(m[1].trim());
  }
  return results;
}
