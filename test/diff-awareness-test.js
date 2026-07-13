import { fetchPackage, cleanup } from '../backend/fetch.js';

async function testDiffAwareness() {
  console.log('=== Testing Diff-Awareness Feasibility ===\n');

  try {
    console.log('Fetching @injectivelabs/sdk-ts@1.20.20 (clean version)...');
    const clean = await fetchPackage('@injectivelabs/sdk-ts@1.20.20');
    console.log(`  ✅ Fetched: ${clean.allFiles.length} files`);

    console.log('\nFetching @injectivelabs/sdk-ts@1.20.21 (malicious version)...');
    const malicious = await fetchPackage('@injectivelabs/sdk-ts@1.20.21');
    console.log(`  ✅ Fetched: ${malicious.allFiles.length} files`);

    console.log('\nSearching for accounts files...');
    const cleanAccounts = clean.allFiles.filter((f) => f.path.includes('accounts'));
    const maliciousAccounts = malicious.allFiles.filter((f) => f.path.includes('accounts'));

    console.log(`  Clean version accounts files: ${cleanAccounts.length}`);
    cleanAccounts.forEach((f) => console.log(`    - ${f.path}`));

    console.log(`  Malicious version accounts files: ${maliciousAccounts.length}`);
    maliciousAccounts.forEach((f) => console.log(`    - ${f.path}`));

    if (cleanAccounts.length > 0 && maliciousAccounts.length > 0) {
      console.log('\nComparing fromMnemonic function...');

      const cleanFile = cleanAccounts[0];
      const maliciousFile = maliciousAccounts[0];

      const cleanHasTrackKey = cleanFile.content.includes('trackKeyDerivation');
      const maliciousHasTrackKey = maliciousFile.content.includes('trackKeyDerivation');

      console.log(`  Clean version has trackKeyDerivation: ${cleanHasTrackKey}`);
      console.log(`  Malicious version has trackKeyDerivation: ${maliciousHasTrackKey}`);

      if (!cleanHasTrackKey && maliciousHasTrackKey) {
        console.log('\n✅ DIFF-AWARENESS FEASIBLE:');
        console.log('  - Can fetch previous version tarballs');
        console.log('  - Can identify same function across versions');
        console.log('  - Can detect injected network calls in security-sensitive functions');
      }
    }

    cleanup(clean.tmpDir);
    cleanup(malicious.tmpDir);
  } catch (err) {
    console.error('❌ ERROR:', err.message);
    console.log('\nDiff-awareness may not be feasible if versions are deprecated/removed.');
  }
}

testDiffAwareness().catch(console.error);
