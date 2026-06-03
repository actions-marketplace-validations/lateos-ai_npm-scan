import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';

const BINARY_DIRS = ['bin/', 'native/'];
const BINARY_EXTS = ['.exe', '.dll', '.so', '.dylib', '.wasm', '.node', '.o', '.a'];
const BINARY_FILENAMES = ['bun', 'deno', 'go', 'rustc', 'python', 'python3', 'ruby', 'php'];

const CHILD_PROC_RE = /\b(?:spawn|exec|execSync|spawnSync|fork)\s*\(/g;
const FS_CHMOD_RE = /fs\.chmod\s*\(/g;

function detectMagicBytes(content) {
  if (!content || content.length < 4) return null;

  const c0 = content.charCodeAt(0);
  const c1 = content.charCodeAt(1);
  const c2 = content.charCodeAt(2);
  const c3 = content.charCodeAt(3);

  if (c0 === 0x7f && content.slice(1, 4) === 'ELF') return 'elf_embedded';
  if (c0 === 0x4d && c1 === 0x5a) return 'pe_embedded';
  if (c0 === 0x00 && content.slice(1, 4) === 'asm') return 'wasm_embedded';

  const machO = (c0 === 0xfe && c1 === 0xed && c2 === 0xfa && (c3 === 0xce || c3 === 0xcf)) ||
    (c0 === 0xce && c1 === 0xfa && c2 === 0xed && (c3 === 0xfe || c3 === 0xcf)) ||
    (c0 === 0xcf && c1 === 0xfa && c2 === 0xed && c3 === 0xfe);
  if (machO) return 'macho_embedded';

  const universal = c0 === 0xca && c1 === 0xfe && c2 === 0xba && c3 === 0xbe;
  if (universal) return 'macho_embedded';

  return null;
}

function isInBinaryDir(filePath) {
  const normalized = filePath.replace(/\\/g, '/');
  return BINARY_DIRS.some(dir => normalized.includes(`/${dir}`) || normalized.startsWith(dir));
}

function hasBinaryExt(filePath) {
  const lower = filePath.toLowerCase();
  return BINARY_EXTS.some(ext => lower.endsWith(ext));
}

function isKnownBinaryName(fileName) {
  const base = fileName.replace(/\.\w+$/, '').toLowerCase();
  return BINARY_FILENAMES.includes(base);
}

const CROSS_PLATFORM_RE = /-(?:linux|darwin|macos|win32|windows|win)-(?:x64|x86|arm64|ia32)\.?(?:exe)?$/i;

function detectCrossPlatformSets(binaries) {
  const sets = {};
  for (const bin of binaries) {
    const base = bin.file.replace(CROSS_PLATFORM_RE, '').split(/[/\\]/).pop();
    if (!sets[base]) sets[base] = [];
    sets[base].push(bin.file);
  }
  for (const [base, files] of Object.entries(sets)) {
    if (files.length >= 2) {
      return { base, files, count: files.length };
    }
  }
  return null;
}

function isDeclared(pkgJson, fileName) {
  if (!pkgJson) return false;
  const baseName = fileName.split(/[/\\]/).pop();

  if (pkgJson.bin) {
    if (typeof pkgJson.bin === 'string' && pkgJson.bin === baseName) return true;
    if (typeof pkgJson.bin === 'object' && Object.values(pkgJson.bin).some(v => v === baseName || v.endsWith(`/${baseName}`))) return true;
  }

  if (pkgJson.optionalDependencies) {
    for (const [name, val] of Object.entries(pkgJson.optionalDependencies)) {
      if (name === baseName) return true;
    }
  }

  if (pkgJson.gypfile === true || pkgJson.scripts?.install?.includes('node-gyp') || pkgJson.scripts?.install?.includes('node-pre-gyp')) {
    if (baseName.endsWith('.node')) return true;
  }

  return false;
}

export const name = 'tier1-binary-embed';

export async function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const pkgName = pkgJson?.name;
  if (pkgName && KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  if (!allFiles || allFiles.length === 0) return [];

  if (pkgName && (
    pkgName === 'electron' || pkgName === 'puppeteer' || pkgName === 'sharp' ||
    pkgName === 'esbuild' || pkgName === 'node-gyp' || pkgName === 'node-pre-gyp' ||
    pkgName === '@mapbox/node-pre-gyp'
  )) return [];

  const binaries = [];

  for (const f of allFiles) {
    const content = f.content || '';
    const filePath = f.path || f.name || '';
    const fileName = filePath.split(/[/\\]/).pop();
    const fileSize = content.length;

    const magic = detectMagicBytes(content);
    const inBinDir = isInBinaryDir(filePath);
    const hasExt = hasBinaryExt(filePath);
    const knownName = isKnownBinaryName(fileName);
    const largeFile = fileSize > 100000000;

    if (magic || inBinDir || hasExt || knownName) {
      const declared = isDeclared(pkgJson, filePath);

      binaries.push({
        file: filePath,
        size: fileSize,
        magic,
        inBinDir,
        hasExt,
        knownName,
        declared,
        largeFile,
      });
    }
  }

  if (binaries.length === 0) return [];

  const crossPlatformSet = detectCrossPlatformSets(binaries);

  const jsCode = (jsFiles || []).map(f => f.content || '').join('\n');
  const invoked = CHILD_PROC_RE.test(jsCode) || FS_CHMOD_RE.test(jsCode);

  const invokedFiles = [];
  if (jsFiles && invoked) {
    for (const f of jsFiles) {
      const c = f.content || '';
      CHILD_PROC_RE.lastIndex = 0;
      FS_CHMOD_RE.lastIndex = 0;
      if (CHILD_PROC_RE.test(c) || FS_CHMOD_RE.test(c)) {
        invokedFiles.push(f.path || f.name || 'unknown.js');
      }
    }
  }

  const findings = [];

  for (const bin of binaries) {
    let baseScore;
    let subtype;

    // Cross-platform platform set boost
    const isCrossPlatform = crossPlatformSet && crossPlatformSet.files.some(f => f === bin.file || f.includes(bin.file) || bin.file.includes(f.replace(/\.exe$/, '')));

    if (bin.magic === 'elf_embedded') {
      baseScore = 95;
      subtype = isCrossPlatform ? 'cross_platform_elf' : 'elf_embedded';
    } else if (bin.magic === 'pe_embedded') {
      baseScore = 95;
      subtype = isCrossPlatform ? 'cross_platform_pe' : 'pe_embedded';
    } else if (bin.magic === 'macho_embedded') {
      baseScore = 95;
      subtype = isCrossPlatform ? 'cross_platform_macho' : 'macho_embedded';
    } else if (bin.magic === 'wasm_embedded') {
      baseScore = 60;
      subtype = isCrossPlatform ? 'cross_platform_wasm' : 'wasm_embedded';
    } else {
      baseScore = 60;
      subtype = isCrossPlatform ? 'cross_platform_unknown' : 'magic_byte_unknown';
    }

    let score = baseScore;

    if (isCrossPlatform) score += 25;

    if (bin.inBinDir) score += 15;

    if (!bin.declared) score += 50;

    if (invoked && invokedFiles.length > 0) score += 25;

    const confidenceScore = Math.max(50, Math.min(100, score));

    function severityLabel(sc) {
      if (sc >= 90) return 'critical';
      if (sc >= 70) return 'high';
      return 'medium';
    }

    function confidenceLabel(sc) {
      if (sc >= 95) return 'CRITICAL';
      if (sc >= 80) return 'HIGH';
      if (sc >= 60) return 'MEDIUM';
      return 'LOW';
    }

    const evidence = [
      `binary: ${bin.file.split(/[/\\]/).pop()}${bin.magic ? ` (${bin.magic.toUpperCase().replace('_EMBEDDED', '')})` : ''}`,
      `path: ${bin.file}`,
      `declared: ${bin.declared}`,
    ];
    if (isCrossPlatform) {
      evidence.push(`cross-platform binary set: ${crossPlatformSet.count} variants of "${crossPlatformSet.base}"`);
      evidence.push(`platform_files: ${crossPlatformSet.files.join(', ')}`);
    }

    if (invoked && invokedFiles.length > 0) {
      evidence.push(`invoked: child_process usage in ${invokedFiles.length} file(s)`);
      evidence.push(`invoked_file: ${invokedFiles[0]}`);
    }

    const locations = [
      { file: bin.file, size: bin.size },
    ];

    if (invokedFiles.length > 0) {
      locations.push({ file: invokedFiles[0], line: 0 });
    }

    let message;
    if (!bin.declared) {
      message = `Undeclared binary detected: ${bin.file.split(/[/\\]/).pop()}`;
    } else if (invoked) {
      message = `Binary ${bin.file.split(/[/\\]/).pop()} invoked from JavaScript`;
    } else {
      message = `Binary embedded in package: ${bin.file.split(/[/\\]/).pop()}`;
    }

    findings.push({
      detector: 'tier1-binary-embed',
      id: 'TIER1-BINARY-EMBED',
      severity: severityLabel(confidenceScore),
      confidence: confidenceLabel(confidenceScore),
      confidenceScore,
      subtype,
      message,
      evidence,
      locations,
      reference: 'Campaign 2',
    });
  }

  return findings;
}
