import * as atk001 from './atk-001-lifecycle.js';
import * as atk002 from './atk-002-obfusc.js';
import * as atk003 from './atk-003-creds.js';
import * as atk004 from './atk-004-persist.js';
import * as atk005 from './atk-005-exfil.js';
import * as atk006 from './atk-006-depconf.js';
import * as atk007 from './atk-007-typosquat.js';
import * as atk008 from './atk-008-tarball-tamper.js';
import * as atk009 from './atk-009-dormant-trigger.js';
import * as atk010 from './atk-010-sandbox-evasion.js';
import * as atk011 from './atk-011-transitive-prop.js';
import { scanAll as megalodonScan } from './megalodon/index.js';
import { scan as hfScan } from './hf-impersonation/index.js';
import { scan as miniShaiHuludScan } from './mini-shai-hulud/index.js';
import { scan as badhostScan } from './cve-2026-48710-badhost/index.js';
import { scan as trapdoorScan } from './trapdoor/index.js';

export async function runAll(pkgJson, files = [], registryMeta = null, allFiles = null) {
  const findings = [];
  findings.push(...await atk001.scan(pkgJson, files));
  findings.push(...await atk002.scan(pkgJson, files));
  findings.push(...await atk003.scan(pkgJson, files));
  findings.push(...await atk004.scan(pkgJson, files));
  findings.push(...await atk005.scan(pkgJson, files));
  findings.push(...await atk006.scan(pkgJson, files));
  findings.push(...await atk007.scan(pkgJson, files));
  findings.push(...await atk008.scan(pkgJson, files));
  findings.push(...await atk009.scan(pkgJson, files));
  findings.push(...await atk010.scan(pkgJson, files));
  findings.push(...await atk011.scan(pkgJson, files));
  findings.push(...await megalodonScan(pkgJson, allFiles || files, registryMeta));
  findings.push(...await hfScan(pkgJson, files, registryMeta, allFiles || files));
  findings.push(...await miniShaiHuludScan(pkgJson, files, registryMeta, allFiles || files));
  findings.push(...await badhostScan(pkgJson, files, registryMeta, allFiles || files));
  findings.push(...await trapdoorScan(pkgJson, files, registryMeta, allFiles || files));
  return findings.sort((a, b) => b.severity.localeCompare(a.severity));
}