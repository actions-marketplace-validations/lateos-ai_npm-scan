import { KNOWN_REPUTABLE_PACKAGES } from '../policy.js';
import * as acorn from 'acorn';
import * as walk from 'acorn-walk';

const SECURITY_SENSITIVE_FUNCTIONS = [
  'fromMnemonic',
  'fromPrivateKey',
  'fromSeed',
  'fromHex',
  'derivePath',
  'deriveKeypair',
  'sign',
  'signTransaction',
  'signMessage',
  'getPrivateKey',
  'exportPrivateKey',
];

const NETWORK_CALL_PATTERNS = [
  'fetch',
  'axios',
  'http.request',
  'https.request',
  'XMLHttpRequest',
  'WebSocket',
];

const DYNAMIC_CODE_PATTERNS = [
  'eval',
  'new Function',
  'vm.runInContext',
  'vm.runInNewContext',
];

function extractFunctions(code) {
  const functions = new Map();
  try {
    const ast = acorn.parse(code, { ecmaVersion: 2022, sourceType: 'module' });
    walk.simple(ast, {
      FunctionDeclaration(node) {
        if (node.id && node.id.name) {
          functions.set(node.id.name, {
            name: node.id.name,
            code: code.slice(node.start, node.end),
            node: node,
          });
        }
      },
      MethodDefinition(node) {
        if (node.key && node.key.name) {
          functions.set(node.key.name, {
            name: node.key.name,
            code: code.slice(node.start, node.end),
            node: node,
          });
        }
      },
      VariableDeclarator(node) {
        if (
          node.id &&
          node.id.name &&
          node.init &&
          (node.init.type === 'FunctionExpression' || node.init.type === 'ArrowFunctionExpression')
        ) {
          functions.set(node.id.name, {
            name: node.id.name,
            code: code.slice(node.start, node.end),
            node: node,
          });
        }
      },
    });
  } catch (err) {
    // Silent fail - parsing errors are expected for non-JS files
  }
  return functions;
}

function detectNetworkCalls(code) {
  return NETWORK_CALL_PATTERNS.filter((pattern) => code.includes(pattern));
}

function detectDynamicCode(code) {
  return DYNAMIC_CODE_PATTERNS.filter((pattern) => code.includes(pattern));
}

function findAccountsFile(files) {
  return files.find((f) => f.path && f.path.includes('accounts'));
}

export const name = 'tier1-crypto-primitive-tamper';

export async function scan(pkgJson, _jsFiles, registryMeta, allFiles, options = {}) {
  const pkgName = pkgJson?.name;
  if (!pkgName) return [];
  if (KNOWN_REPUTABLE_PACKAGES.has(pkgName)) return [];

  if (!allFiles || allFiles.length === 0) {
    return [];
  }

  const findings = [];

  const accountsFile = findAccountsFile(allFiles);
  if (!accountsFile) {
    return [];
  }

  const currentFunctions = extractFunctions(accountsFile.content);

  let previousFunctions = null;
  if (options.previousFiles) {
    const previousAccountsFile = findAccountsFile(options.previousFiles);
    if (previousAccountsFile) {
      previousFunctions = extractFunctions(previousAccountsFile.content);
    }
  } else if (options.fetchPreviousVersion) {
    try {
      const previousPkg = await options.fetchPreviousVersion(pkgName, pkgJson.version);
      if (previousPkg && previousPkg.files) {
        const previousAccountsFile = findAccountsFile(previousPkg.files);
        if (previousAccountsFile) {
          previousFunctions = extractFunctions(previousAccountsFile.content);
        }
      }
    } catch (err) {
      // Silent fail - previous version fetch is optional
    }
  }

  if (!previousFunctions) {
    return [];
  }

  for (const funcName of SECURITY_SENSITIVE_FUNCTIONS) {
    const currentFunc = currentFunctions.get(funcName);
    const previousFunc = previousFunctions.get(funcName);

    if (!currentFunc) {
      continue;
    }

    const currentNetworkCalls = detectNetworkCalls(currentFunc.code);
    const currentDynamicCode = detectDynamicCode(currentFunc.code);

    if (currentNetworkCalls.length === 0 && currentDynamicCode.length === 0) {
      continue;
    }

    let newNetworkCalls = currentNetworkCalls;
    let newDynamicCode = currentDynamicCode;

    if (previousFunc) {
      const previousNetworkCalls = detectNetworkCalls(previousFunc.code);
      const previousDynamicCode = detectDynamicCode(previousFunc.code);

      newNetworkCalls = currentNetworkCalls.filter((c) => !previousNetworkCalls.includes(c));
      newDynamicCode = currentDynamicCode.filter((c) => !previousDynamicCode.includes(c));
    }

    if (newNetworkCalls.length > 0 || newDynamicCode.length > 0) {
      const confidenceScore = 85;
      const severity = 'high';

      const evidence = [
        `function: ${funcName}`,
        `previous_version: ${options.previousVersion || 'unknown'}`,
        `current_version: ${pkgJson.version}`,
      ];

      if (newNetworkCalls.length > 0) {
        evidence.push(`new_network_calls: ${newNetworkCalls.join(', ')}`);
      }
      if (newDynamicCode.length > 0) {
        evidence.push(`new_dynamic_code: ${newDynamicCode.join(', ')}`);
      }

      findings.push({
        detector: 'tier1-crypto-primitive-tamper',
        id: 'TIER1-CRYPTO-TAMPER',
        severity,
        confidence: 'HIGH',
        confidenceScore,
        subtype: 'semantic_backdoor',
        message: `Semantic backdoor detected: ${funcName}() newly contains network/dynamic code execution`,
        evidence,
        locations: [{ file: accountsFile.path, line: 0 }],
        crossFiles: [],
        reference: 'Injective SDK 2026-07-08: semantic backdoor in crypto primitives',
      });
    }
  }

  return findings;
}
