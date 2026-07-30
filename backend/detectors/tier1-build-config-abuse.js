import thresholds from './config/thresholds.js';
import { parseGyp } from './lib/gyp-parser.js';
import { verifyProvenance, applyProvenanceDiscount } from './lib/slsa-verifier.js';

const cfg = thresholds['D14-BUILD-CONFIG-ABUSE'];
const PATTERN_WEIGHTS = cfg.pattern_weights;
const PATTERN_CONFIDENCE = cfg.pattern_confidence;
const LEGITIMATE_ADDONS = new Set(cfg.legitimate_native_addons);

function fileByName(files, name) {
  if (!files) return null;
  const target = name.replace(/\\/g, '/').toLowerCase();
  return (
    files.find((f) => {
      const fp = (f.path || f.name || '').replace(/\\/g, '/').toLowerCase();
      return fp === target || fp.endsWith('/' + target);
    }) || null
  );
}

function filesByExt(files, exts) {
  if (!files) return [];
  const lower = exts.map((e) => e.toLowerCase());
  return files.filter((f) => {
    const fp = (f.path || f.name || '').toLowerCase();
    return lower.some((e) => fp.endsWith(e));
  });
}

function extractLines(content, matchIndex) {
  if (!content) return 1;
  const before = content.slice(0, matchIndex);
  return (before.match(/\n/g) || []).length + 1;
}

export const name = 'tier1-build-config-abuse';

export async function scan(pkgJson, jsFiles, registryMeta, allFiles) {
  const pkgName = pkgJson?.name;
  const provenance = await verifyProvenance(pkgName, pkgJson?.version, registryMeta);

  // Known reputable packages skip D14 analysis (provenance verification handled separately)
  if (
    pkgName &&
    !provenance.verified &&
    cfg.known_reputable_packages?.some((r) => pkgName === r || pkgName.startsWith(r + '/'))
  ) {
    return [];
  }

  const files = allFiles || jsFiles || [];
  if (files.length === 0) return [];

  const findings = [];
  let aggregatedRisk = 0;

  const hasGypFile = !!fileByName(files, 'binding.gyp');
  const isLegitimateAddon = pkgName && LEGITIMATE_ADDONS.has(pkgName);

  // Step 1: binding.gyp presence on non-legitimate addon
  const hasGypDeclared =
    pkgJson &&
    (pkgJson.gypfile === true ||
      !!pkgJson.binary ||
      (pkgJson.scripts &&
        typeof pkgJson.scripts.install === 'string' &&
        pkgJson.scripts.install.includes('node-gyp')) ||
      (pkgJson.scripts &&
        typeof pkgJson.scripts.install === 'string' &&
        pkgJson.scripts.install.includes('node-pre-gyp')));

  if (hasGypFile && !isLegitimateAddon && !hasGypDeclared) {
    findings.push({
      detector: 'tier1-build-config-abuse',
      id: 'D14-BUILD-CONFIG-ABUSE',
      severity: 'medium',
      confidence: 'MEDIUM',
      confidenceScore: 40,
      message: `Unexpected binding.gyp in non-native-addon package${pkgName ? ': ' + pkgName : ''}`,
      evidence: ['binding.gyp present but package is not a known native addon'],
      locations: [{ file: 'binding.gyp', line: 1 }],
    });
    aggregatedRisk += 20;
  }

  // Step 2: Parse binding.gyp for suspicious patterns (enhanced)
  if (hasGypFile) {
    const gypFile = fileByName(files, 'binding.gyp');
    const gypContent = gypFile?.content || '';

    if (gypContent) {
      const gypPatterns = {
        shell_exec: /<!?\(.*\)/g,
        process_spawn: /\b(spawn|exec|execSync|spawnSync|fork)\s*\(/g,
        env_access: /process\.env\./g,
        fs_access: /\bfs\.(read|write|readFile|writeFile|readdir|exists|stat|mkdir|rm|unlink)/g,
        http_request: /\b(http|https|curl|wget|fetch)\b/gi,
        path_traversal: /\.\.\//g,
        compile_macro_injection: /-D\s*['"]?[A-Z_]+=(system|exec|shell|popen|fork)/g,
        include_path_manipulation: /-I\s*\.\.\/\.\.\/(?:tmp|var|dev|private|etc)/g,
        linker_library_injection: /['"](?:-lcurl|libcurl|-lssl|libssl|-lpcap|libpcap|-lkqueue)['"]/g,
      };

      for (const [patternName, regex] of Object.entries(gypPatterns)) {
        regex.lastIndex = 0;
        let match;
        while ((match = regex.exec(gypContent)) !== null) {
          const line = extractLines(gypContent, match.index);
          findings.push({
            detector: 'tier1-build-config-abuse',
            id: 'D14-BUILD-CONFIG-ABUSE',
            severity: PATTERN_WEIGHTS[patternName] >= 50 ? 'high' : 'medium',
            confidence: 'HIGH',
            confidenceScore: PATTERN_WEIGHTS[patternName],
            message: `binding.gyp contains ${patternName.replace(/_/g, ' ')} pattern`,
            evidence: [`pattern: ${patternName}`, `match: ${match[0].slice(0, 120)}`],
            locations: [{ file: 'binding.gyp', line }],
          });
          aggregatedRisk += PATTERN_WEIGHTS[patternName] || 30;
        }
      }

      // Gyp AST structural analysis
      const gypAST = parseGyp(gypContent);
      if (gypAST.shellExecs.length > 0) {
        for (const se of gypAST.shellExecs) {
          findings.push({
            detector: 'tier1-build-config-abuse',
            id: 'D14-BUILD-CONFIG-ABUSE',
            severity: 'high',
            confidence: 'HIGH',
            confidenceScore: PATTERN_WEIGHTS.shell_exec || 50,
            message: `binding.gyp shell execution via <!(command)`,
            evidence: [`pattern: gyp_shell_exec`, `command: ${se.command.slice(0, 120)}`],
            locations: [{ file: 'binding.gyp', line: se.line }],
          });
          aggregatedRisk += PATTERN_WEIGHTS.shell_exec || 50;
        }
      }
      if (gypAST.linkerFlags.length > 0) {
        for (const lf of gypAST.linkerFlags) {
          findings.push({
            detector: 'tier1-build-config-abuse',
            id: 'D14-BUILD-CONFIG-ABUSE',
            severity: 'medium',
            confidence: 'MEDIUM',
            confidenceScore: 35,
            message: `binding.gyp linker flag: ${lf.flag}`,
            evidence: [`pattern: linker_flag`, `flag: ${lf.flag}`],
            locations: [{ file: 'binding.gyp', line: lf.line }],
          });
          aggregatedRisk += 35;
        }
      }
    }
  }

  // Step 2b: Analyze Makefile / CMakeLists.txt / configure scripts
  const buildFiles = filesByExt(files, ['.mk', 'Makefile', 'CMakeLists.txt', 'configure', '.cmake']);
  for (const bf of buildFiles) {
    const content = bf.content || '';
    if (!content) continue;

    const buildPatterns = {
      makefile_shell_exec: /\$\(shell\s+[^)]+\)/g,
      cmake_execute_process: /\bexecute_process\s*\([^)]*COMMAND\b/g,
      cmake_custom_command: /\badd_custom_command\s*\([^)]*(COMMAND|DEPENDS)/g,
      cmake_custom_target: /\badd_custom_target\s*\([^)]*(COMMAND|DEPENDS)/g,
      makefile_curl_download: /\b(curl|wget|fetch)\s+(--insecure|-k\s+)?(http|https):/g,
      makefile_npm_publish: /\bnpm\s+(publish|version|dist-tag)/g,
    };

    for (const [patternName, regex] of Object.entries(buildPatterns)) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = extractLines(content, match.index);
        findings.push({
          detector: 'tier1-build-config-abuse',
          id: 'D14-BUILD-CONFIG-ABUSE',
          severity: 'high',
          confidence: 'HIGH',
          confidenceScore: 50,
          message: `${bf.path || bf.name || 'build file'} contains ${patternName.replace(/_/g, ' ')} pattern`,
          evidence: [`pattern: ${patternName}`, `match: ${match[0].slice(0, 120)}`],
          locations: [{ file: bf.path || bf.name || 'unknown', line }],
        });
        aggregatedRisk += 50;
      }
    }
  }

  // Step 3: Analyze C/C++ Source Code
  const cppFiles = filesByExt(files, ['.cc', '.cpp', '.c', '.cxx', '.h', '.hpp']);
  for (const cppFile of cppFiles) {
    const content = cppFile.content || '';
    if (!content) continue;

    const cPatterns = {
      hardcoded_key:
        /(?:AWS|GITHUB|SLACK|STRIPE|TOKEN|SECRET|API_KEY|PASSWORD)\s*[:=]\s*['"][A-Za-z0-9_-]{20,}['"]|['"](?:sk_live_|sk_test_|ghp_|gho_|ghs_|ghu_)[A-Za-z0-9_-]{20,}['"]/g,
      getenv_call: /\b(getenv|secure_getenv|getenv_s)\s*\(/g,
      curl_call: /\b(curl_easy_perform|curl_slist_append|CURLOPT_URL|curl_easy_setopt)\s*\(/g,
      execve_call: /\b(execve|execvp|execl|execlp|system|popen|pclose)\s*\(/g,
      credential_scan: /(~\/\.aws|~\/\.ssh|\.env|credentials\.json|\/etc\/passwd)/g,
      socket_call: /\b(socket\s*\(|listen\s*\(|accept\s*\(|connect\s*\(AF_)/g,
      environ_access: /\b(environ|__environ)\s*\[/g,
    };

    for (const [patternName, regex] of Object.entries(cPatterns)) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = extractLines(content, match.index);
        const confidence = PATTERN_CONFIDENCE[patternName] || 0.7;
        const risk = PATTERN_WEIGHTS[patternName] || 30;

        findings.push({
          detector: 'tier1-build-config-abuse',
          id: 'D14-BUILD-CONFIG-ABUSE',
          severity: risk >= 50 ? 'high' : 'medium',
          confidence: confidence >= 0.85 ? 'HIGH' : confidence >= 0.7 ? 'MEDIUM' : 'LOW',
          confidenceScore: risk,
          message: `C/C++ code contains ${patternName.replace(/_/g, ' ')} pattern`,
          evidence: [
            `pattern: ${patternName}`,
            `match: ${match[0].slice(0, 120)}`,
            `confidence: ${confidence}`,
          ],
          locations: [{ file: cppFile.path || cppFile.name || 'unknown.cc', line }],
        });
        aggregatedRisk += risk;
      }
    }
  }

  // Step 4: Check .node file legitimacy
  const nodeFiles = filesByExt(files, ['.node']);
  for (const nodeFile of nodeFiles) {
    const content = nodeFile.content || '';
    const fileSize = content.length;

    if (fileSize > cfg.max_binary_size_bytes) {
      findings.push({
        detector: 'tier1-build-config-abuse',
        id: 'D14-BUILD-CONFIG-ABUSE',
        severity: 'medium',
        confidence: 'MEDIUM',
        confidenceScore: cfg.binary_size_weight,
        message: 'Large prebuilt .node binary',
        evidence: [
          `file: ${nodeFile.path || nodeFile.name}`,
          `size: ${(fileSize / (1024 * 1024)).toFixed(1)} MB`,
          `max allowed: ${(cfg.max_binary_size_bytes / (1024 * 1024)).toFixed(1)} MB`,
        ],
        locations: [{ file: nodeFile.path || nodeFile.name || 'unknown.node' }],
      });
      aggregatedRisk += cfg.binary_size_weight;
    }
  }

  // Step 5: Cross-reference — undeclared binding.gyp
  if (hasGypFile && pkgJson && !hasGypDeclared) {
    findings.push({
      detector: 'tier1-build-config-abuse',
      id: 'D14-BUILD-CONFIG-ABUSE',
      severity: 'high',
      confidence: 'HIGH',
      confidenceScore: cfg.undeclared_gyp_weight,
      message: 'Undeclared binding.gyp — package.json does not advertise native build',
      evidence: ['binding.gyp exists but no gypfile/binary/install-script in package.json'],
      locations: [{ file: 'binding.gyp', line: 1 }],
    });
    aggregatedRisk += cfg.undeclared_gyp_weight;
  }

  // Step 6: Lifecycle hook + binding.gyp cross-reference
  if (hasGypFile && pkgJson?.scripts) {
    const lifecycleScripts = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'];
    const hasNodeGypInHook = lifecycleScripts.some((hook) => {
      const script = pkgJson.scripts[hook];
      return typeof script === 'string' && script.includes('node-gyp rebuild');
    });
    const hasMaliciousGypPattern = findings.some((f) =>
      f.evidence?.some((e) => e.includes('shell_exec') || e.includes('compile_macro') || e.includes('gyp_shell_exec'))
    );

    if (hasNodeGypInHook && hasMaliciousGypPattern) {
      findings.push({
        detector: 'tier1-build-config-abuse',
        id: 'D14-BUILD-CONFIG-ABUSE',
        severity: 'critical',
        confidence: 'CRITICAL',
        confidenceScore: 99,
        message: 'Lifecycle hook triggers node-gyp rebuild on binding.gyp with malicious patterns',
        evidence: [
          'lifecycle_hook: node-gyp rebuild',
          'binding.gyp: contains malicious build patterns',
          'execution confirmed at install time',
        ],
        locations: [{ file: 'binding.gyp', line: 1 }],
        recommendation: 'BLOCK - Malicious native build will execute during npm install',
      });
      aggregatedRisk += 99;
    }
  }

  // Apply provenance discount if verified
  const hasMaliciousFindings = findings.length > 0;
  if (provenance.verified && hasMaliciousFindings) {
    const discounted = applyProvenanceDiscount(findings, provenance);
    findings.length = 0;
    findings.push(...discounted);
    aggregatedRisk = Math.round(aggregatedRisk * (1 - Math.min(0.3, provenance.slsaLevel * 0.1)));
  }

  if (findings.length === 0) return [];

  const overallScore = Math.min(100, Math.max(0, aggregatedRisk));
  let severity;
  if (overallScore >= cfg.flag_threshold) {
    severity = 'critical';
  } else if (overallScore >= cfg.warn_threshold) {
    severity = 'high';
  } else if (overallScore >= 30) {
    severity = 'medium';
  } else {
    severity = 'low';
  }

  function confidenceLabel(sc) {
    if (sc >= 80) return 'HIGH';
    if (sc >= 50) return 'MEDIUM';
    return 'LOW';
  }

  const hasShellExec = findings.some((f) => f.evidence?.some((e) => e.includes('shell_exec')));
  const hasCreds = findings.some((f) => f.evidence?.some((e) => e.includes('hardcoded_key')));
  const hasNetwork = findings.some((f) =>
    f.evidence?.some((e) => e.includes('curl_call') || e.includes('http_request'))
  );
  const hasExec = findings.some((f) => f.evidence?.some((e) => e.includes('execve_call')));

  let recommendation = 'PASS';
  if (hasShellExec || hasCreds || hasExec) {
    recommendation = 'BLOCK - Native addon build contains malicious patterns';
  } else if (hasNetwork) {
    recommendation = 'WARN - Native addon build makes network calls';
  } else if (aggregatedRisk > cfg.warn_threshold) {
    recommendation = 'REVIEW - Suspicious build configuration detected';
  }

  return [
    {
      detector: 'tier1-build-config-abuse',
      id: 'D14-BUILD-CONFIG-ABUSE',
      severity,
      confidence: confidenceLabel(overallScore),
      confidenceScore: overallScore,
      message: `Build Configuration Abuse detected (aggregated risk: ${aggregatedRisk})`,
      evidence: [
        `total_findings: ${findings.length}`,
        `aggregated_risk: ${aggregatedRisk}`,
        ...findings.map((f) => {
          const loc = f.locations?.[0];
          return `${f.message}${loc ? ' @ ' + (loc.file || '') + (loc.line ? ':' + loc.line : '') : ''}`;
        }),
      ],
      locations: findings.flatMap((f) => f.locations || []),
      recommendation,
      detail: findings.map((f) => ({
        type:
          f.evidence?.find((e) => e.startsWith('pattern:'))?.replace('pattern: ', '') || 'unknown',
        pattern: f.evidence?.find((e) => e.startsWith('pattern:'))?.replace('pattern: ', ''),
        confidence: f.confidenceScore,
        risk: f.confidenceScore,
        location: f.locations?.[0] || null,
      })),
    },
  ];
}
