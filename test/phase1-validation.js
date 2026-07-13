import { scan as lifecycleHookScan } from '../backend/detectors/tier1-lifecycle-hook.js';
import { scan as hookFollowthroughScan } from '../backend/detectors/tier1-lifecycle-hook-followthrough.js';
import { scan as binaryEmbedScan } from '../backend/detectors/tier1-binary-embed.js';
import { scan as maintainerCompromiseScan } from '../backend/detectors/tier1-maintainer-compromise.js';
import { scan as multistagePostinstallScan } from '../backend/detectors/tier1-multistage-postinstall.js';
import { scan as infostealerScan } from '../backend/detectors/tier1-infostealer.js';
import { jscramblerPreinstall } from './fixtures/campaigns/jscrambler-2026-07/preinstall-hook.js';
import { injectiveBackdoor } from './fixtures/campaigns/injective-sdk-ts-2026-07/backdoor.js';

async function testIncidentA() {
  console.log('=== INCIDENT A: Jscrambler ===\n');
  
  const { pkgJson, allFiles, registryMeta } = jscramblerPreinstall;
  
  console.log('Test 1: tier1-lifecycle-hook.js');
  const hookFindings = await lifecycleHookScan(pkgJson, allFiles.filter(f => f.path.endsWith('.js')), registryMeta, allFiles);
  console.log(`  Result: ${hookFindings.length > 0 ? '✅ FINDING' : '❌ NO FINDING'}`);
  if (hookFindings.length > 0) {
    console.log(`  Finding: ${hookFindings[0].id} - ${hookFindings[0].message}`);
  }
  
  console.log('\nTest 2: tier1-lifecycle-hook-followthrough.js');
  const followthroughFindings = await hookFollowthroughScan(pkgJson, allFiles.filter(f => f.path.endsWith('.js')), registryMeta, allFiles);
  console.log(`  Result: ${followthroughFindings.length > 0 ? '✅ FINDING' : '❌ NO FINDING'}`);
  if (followthroughFindings.length > 0) {
    console.log(`  Finding: ${followthroughFindings[0].id} - ${followthroughFindings[0].message}`);
  }
  
  console.log('\nTest 3: tier1-binary-embed.js');
  const binaryFindings = await binaryEmbedScan(pkgJson, allFiles.filter(f => f.path.endsWith('.js')), registryMeta, allFiles);
  console.log(`  Result: ${binaryFindings.length > 0 ? '✅ FINDING' : '❌ NO FINDING'}`);
  if (binaryFindings.length > 0) {
    console.log(`  Finding: ${binaryFindings[0].id} - ${binaryFindings[0].message}`);
  }
  
  console.log('\nTest 4: tier1-maintainer-compromise.js');
  const maintainerFindings = await maintainerCompromiseScan(pkgJson, allFiles.filter(f => f.path.endsWith('.js')), registryMeta, allFiles);
  console.log(`  Result: ${maintainerFindings.length > 0 ? '✅ FINDING' : '❌ NO FINDING'}`);
  if (maintainerFindings.length > 0) {
    console.log(`  Finding: ${maintainerFindings[0].id} - ${maintainerFindings[0].message}`);
  }
  
  console.log('\nTest 5: tier1-multistage-postinstall.js');
  const multistageFindings = await multistagePostinstallScan(pkgJson, allFiles.filter(f => f.path.endsWith('.js')), registryMeta, allFiles);
  console.log(`  Result: ${multistageFindings.length > 0 ? '✅ FINDING' : '❌ NO FINDING'}`);
  if (multistageFindings.length > 0) {
    console.log(`  Finding: ${multistageFindings[0].id} - ${multistageFindings[0].message}`);
  }
}

async function testIncidentB() {
  console.log('\n\n=== INCIDENT B: @injectivelabs/sdk-ts ===\n');
  
  const { pkgJson, allFiles, registryMeta } = injectiveBackdoor;
  
  console.log('Test 1: tier1-infostealer.js');
  const infostealerFindings = await infostealerScan(pkgJson, allFiles, registryMeta, allFiles);
  console.log(`  Result: ${infostealerFindings.length > 0 ? '✅ FINDING' : '❌ NO FINDING'}`);
  if (infostealerFindings.length > 0) {
    console.log(`  Finding: ${infostealerFindings[0].id} - ${infostealerFindings[0].message}`);
  }
  
  console.log('\nTest 2: tier1-lifecycle-hook.js (no hook present)');
  const hookFindings = await lifecycleHookScan(pkgJson, allFiles, registryMeta, allFiles);
  console.log(`  Result: ${hookFindings.length > 0 ? '✅ FINDING' : '❌ NO FINDING'}`);
  if (hookFindings.length > 0) {
    console.log(`  Finding: ${hookFindings[0].id} - ${hookFindings[0].message}`);
  }
}

async function main() {
  await testIncidentA();
  await testIncidentB();
  console.log('\n\n=== SUMMARY ===');
  console.log('Incident A: Jscrambler - 2/5 detectors fire (hook-followthrough, maintainer-compromise)');
  console.log('Incident B: Injective SDK - 0/2 detectors fire (semantic backdoor not detected)');
}

main().catch(console.error);
