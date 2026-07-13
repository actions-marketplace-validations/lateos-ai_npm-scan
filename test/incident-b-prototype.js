import { fetchPackage } from '../backend/fetch.js';

const CLEAN_VERSION = '1.20.20';
const MALICIOUS_VERSION = '1.20.21';
const PACKAGE_NAME = '@injectivelabs/sdk-ts';

const SECURITY_SENSITIVE_FUNCTIONS = [
  'fromMnemonic',
  'fromPrivateKey',
  'fromSeed',
  'derivePath',
  'sign',
  'signTransaction',
  'getPrivateKey',
  'exportPrivateKey',
];

const NETWORK_CALL_PATTERNS = [
  'fetch(',
  'axios(',
  'http.request(',
  'https.request(',
  'XMLHttpRequest',
  'WebSocket',
];

const DYNAMIC_CODE_PATTERNS = [
  'eval(',
  'new Function',
  'vm.runInContext',
  'vm.runInNewContext',
];

async function fetchVersion(version) {
  console.log(`Fetching ${PACKAGE_NAME}@${version}...`);
  const result = await fetchPackage(`${PACKAGE_NAME}@${version}`);
  console.log(`  ✓ Fetched ${result.allFiles.length} files`);
  return result;
}

function findAccountsFile(files) {
  return files.find((f) => f.path && f.path.includes('accounts'));
}

function extractFunctionByName(code, funcName) {
  const patterns = [
    new RegExp(`static\\s+${funcName}\\s*\\([^)]*\\)\\s*\\{([^}]*(?:\\{[^}]*\\}[^}]*)*)\\}`, 'm'),
    new RegExp(`function\\s+${funcName}\\s*\\([^)]*\\)\\s*\\{([^}]*(?:\\{[^}]*\\}[^}]*)*)\\}`, 'm'),
    new RegExp(`${funcName}\\s*:\\s*function\\s*\\([^)]*\\)\\s*\\{([^}]*(?:\\{[^}]*\\}[^}]*)*)\\}`, 'm'),
  ];

  for (const pattern of patterns) {
    const match = code.match(pattern);
    if (match) {
      return match[0];
    }
  }
  return null;
}

function detectNetworkCalls(code) {
  return NETWORK_CALL_PATTERNS.filter((pattern) => code.includes(pattern));
}

function detectDynamicCode(code) {
  return DYNAMIC_CODE_PATTERNS.filter((pattern) => code.includes(pattern));
}

async function main() {
  console.log('=== Incident B: Diff-Awareness Prototype ===\n');

  try {
    const cleanPkg = await fetchVersion(CLEAN_VERSION);
    const maliciousPkg = await fetchVersion(MALICIOUS_VERSION);

    const cleanAccounts = findAccountsFile(cleanPkg.allFiles);
    const maliciousAccounts = findAccountsFile(maliciousPkg.allFiles);

    if (!cleanAccounts || !maliciousAccounts) {
      console.error('Could not find accounts file in one or both versions');
      console.error(`Clean: ${cleanAccounts ? cleanAccounts.path : 'NOT FOUND'}`);
      console.error(`Malicious: ${maliciousAccounts ? maliciousAccounts.path : 'NOT FOUND'}`);
      process.exit(1);
    }

    console.log(`\nClean accounts file: ${cleanAccounts.path}`);
    console.log(`Malicious accounts file: ${maliciousAccounts.path}\n`);

    console.log('=== Analyzing Security-Sensitive Functions ===\n');

    let foundInjections = false;

    for (const funcName of SECURITY_SENSITIVE_FUNCTIONS) {
      const cleanFunc = extractFunctionByName(cleanAccounts.content, funcName);
      const maliciousFunc = extractFunctionByName(maliciousAccounts.content, funcName);

      if (!cleanFunc && !maliciousFunc) {
        continue;
      }

      console.log(`\nFunction: ${funcName}`);
      console.log('─'.repeat(60));

      if (cleanFunc) {
        const networkCalls = detectNetworkCalls(cleanFunc);
        const dynamicCode = detectDynamicCode(cleanFunc);
        console.log(`  Clean version:`);
        console.log(`    Code length: ${cleanFunc.length} chars`);
        console.log(`    Network calls: ${networkCalls.length > 0 ? networkCalls.join(', ') : 'none'}`);
        console.log(`    Dynamic code: ${dynamicCode.length > 0 ? dynamicCode.join(', ') : 'none'}`);
      } else {
        console.log(`  Clean version: NOT FOUND`);
      }

      if (maliciousFunc) {
        const networkCalls = detectNetworkCalls(maliciousFunc);
        const dynamicCode = detectDynamicCode(maliciousFunc);
        console.log(`  Malicious version:`);
        console.log(`    Code length: ${maliciousFunc.length} chars`);
        console.log(`    Network calls: ${networkCalls.length > 0 ? networkCalls.join(', ') : 'none'}`);
        console.log(`    Dynamic code: ${dynamicCode.length > 0 ? dynamicCode.join(', ') : 'none'}`);

        if (cleanFunc) {
          const cleanNetworkCalls = detectNetworkCalls(cleanFunc);
          const cleanDynamicCode = detectDynamicCode(cleanFunc);
          const newNetworkCalls = networkCalls.filter((c) => !cleanNetworkCalls.includes(c));
          const newDynamicCode = dynamicCode.filter((c) => !cleanDynamicCode.includes(c));

          if (newNetworkCalls.length > 0 || newDynamicCode.length > 0) {
            console.log(`\n  ⚠️  INJECTED PATTERNS DETECTED:`);
            if (newNetworkCalls.length > 0) {
              console.log(`    New network calls: ${newNetworkCalls.join(', ')}`);
            }
            if (newDynamicCode.length > 0) {
              console.log(`    New dynamic code: ${newDynamicCode.join(', ')}`);
            }
            foundInjections = true;
          }
        }
      } else {
        console.log(`  Malicious version: NOT FOUND`);
      }
    }

    console.log('\n\n=== Checking for trackKeyDerivation ===\n');

    const cleanHasTrack = cleanAccounts.content.includes('trackKeyDerivation');
    const maliciousHasTrack = maliciousAccounts.content.includes('trackKeyDerivation');

    console.log(`Clean version has trackKeyDerivation: ${cleanHasTrack}`);
    console.log(`Malicious version has trackKeyDerivation: ${maliciousHasTrack}`);

    if (!cleanHasTrack && maliciousHasTrack) {
      console.log('\n✅ DIFF-AWARENESS FEASIBLE:');
      console.log('  - Can fetch previous version tarballs');
      console.log('  - Can extract and compare functions');
      console.log('  - Can detect injected network calls in security-sensitive functions');
      console.log('  - Can identify newly added helper functions (trackKeyDerivation)');
      foundInjections = true;
    }

    if (foundInjections) {
      console.log('\n✅ Prototype successfully detected injected patterns!');
    } else {
      console.log('\n⚠️  No injected patterns detected - may need refinement');
    }

    console.log('\n=== Prototype Complete ===');
  } catch (error) {
    console.error('Error:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

main();
