import { test, describe } from 'node:test';
import assert from 'assert/strict';
import * as detectors from './detectors/index.js';

describe('D7: Obfuscation Heuristics', () => {
  test('D7: flags heavily obfuscated postinstall script', async () => {
    const obfuscated =
      `var _0x=["eval","fromCharCode","charCodeAt"];for(var i=0;i<999;i++){var x=String.fromCharCode(i);if(i>500){eval(atob("Y29uc3QgeCA9ICdtYWxpY2lvdXMnO2V2YWwoeCk7Y29uc3QgeSA9ICdiYWNrZG9vcic7ZXZhbCh5KTs="))}}var _0xe="\\x65\\x76\\x61\\x6c\\x28\\x61\\x74\\x6f\\x62\\x28\\x22\\x59\\x6d\\x39\\x75\\x62\\x47\\x38\\x67"`;
    const pkg = {
      name: 'malicious-pkg',
      version: '1.0.0',
      scripts: { postinstall: obfuscated },
    };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-OBFUSCATION-HEURISTICS');
    assert(match, 'Expected TIER1-OBFUSCATION-HEURISTICS finding');
    assert(match.confidenceScore >= 75, `confidenceScore ${match.confidenceScore} < 75`);
  });

  test('D7: detects XOR cipher pattern in preinstall script', async () => {
    const xorCode =
      `var _0xk=[0x66,0x6c,0x61,0x67];var _0xd="LzdHJKdUp4VWt5S292RXBsb3Zlck5pZ2h0U2VjcmV0S2V5Rm9yRW50cm9weUJvb3N0";let r='';for(let i=0;i<str.length;i++){r+=String.fromCharCode(str.charCodeAt(i)^_0xk[i%4]);if(i>50){eval(atob("RGV0ZWN0ZWQ="))}}`;
    const pkg = {
      name: 'suspicious-pkg',
      version: '1.0.0',
      scripts: { preinstall: xorCode },
    };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-OBFUSCATION-HEURISTICS');
    assert(match, 'Expected TIER1-OBFUSCATION-HEURISTICS finding');
    assert(match.confidenceScore >= 70, `confidenceScore ${match.confidenceScore} < 70`);
  });

  test('D7: does NOT flag normal string reversal (palindrome check)', async () => {
    const normalCode = `
      function isPalindrome(s) {
        return s === s.split('').reverse().join('');
      }
    `;
    const pkg = {
      name: 'normal-pkg',
      version: '1.0.0',
      scripts: { postinstall: normalCode },
    };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-OBFUSCATION-HEURISTICS');
    assert(!match, 'Should not flag normal palindrome function');
  });

  test('D7: flags high entropy in postinstall script', async () => {
    const highEntropyCode =
      `var x="T3NobmFJc0VudHJvcHlCb29zdGVkV2l0aEJhc2U2NFBheWxvYWRUaGF0U2hvdWxkQmVQbGVudHlPZkNoYXJhY3RlcnNGb3JIaWdoRW50cm9weVNjb3JlQW5kSXRTaG91bGRCZU9mVmVyeUhpZ2hRdWFsaXR5VG9NYWtlVGhlVGVzdFBhc3NBbmRJdFNob3VsZEJlT2ZNaXhlZENhc2VXaXRoTnVtYmVyc0FuZFNwZWNpYWxDaGFyYWN0ZXJzRm9yTWF4RW50cm9weQ==";`;
    const pkg = {
      name: 'high-entropy-pkg',
      version: '1.0.0',
      scripts: { postinstall: highEntropyCode },
    };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-OBFUSCATION-HEURISTICS');
    assert(match, 'Expected TIER1-OBFUSCATION-HEURISTICS finding');
    assert(match.confidenceScore >= 55, `confidenceScore ${match.confidenceScore} < 55`);
  });

  test('D7: no finding on clean build script', async () => {
    const cleanCode = `
      const path = require('path');
      const fs = require('fs');
      fs.mkdirSync(path.join(__dirname, 'dist'));
      console.log('build complete');
    `;
    const pkg = {
      name: 'clean-pkg',
      version: '1.0.0',
      scripts: { postinstall: cleanCode },
    };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-OBFUSCATION-HEURISTICS');
    assert(!match, 'Should not flag clean build script');
  });

  test('D7: no finding on KNOWN_REPUTABLE_PACKAGES', async () => {
    const pkg = {
      name: 'lodash',
      version: '4.17.21',
      scripts: { postinstall: 'eval(atob("dmFyIHg9J21hbGljaW91cyc7"))' },
    };
    const findings = await detectors.runAll(pkg);
    const match = findings.find(f => f.id === 'TIER1-OBFUSCATION-HEURISTICS');
    assert(!match);
  });
});
