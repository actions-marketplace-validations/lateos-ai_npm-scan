import { test } from 'node:test';
import assert from 'assert/strict';
import { scan } from '../backend/detectors/tier1-version-backfill.js';

function makeTimeMap(count, spreadHours) {
  const time = { created: '2026-07-08T10:00:00.000Z', modified: '2026-07-08T13:00:00.000Z' };
  const baseTs = new Date('2026-07-08T10:00:00.000Z').getTime();
  const spreadMs = spreadHours * 60 * 60 * 1000;
  const interval = spreadMs / (count - 1);
  const majors = [0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
  const minors = [1, 2, 3, 4, 5, 6, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
  for (let i = 0; i < count; i++) {
    const major = majors[i] ?? 1;
    const minor = minors[i] ?? i;
    const ver = `${major}.${minor}.0`;
    const ts = new Date(baseTs + interval * i).toISOString();
    time[ver] = ts;
  }
  return time;
}

test('TIER1-VERSION-BACKFILL: 20 versions in 3 hours with wide range detected', async () => {
  const pkgJson = { name: 'test-pkg', version: '1.13.0' };
  const registryMeta = { time: makeTimeMap(20, 3) };
  const findings = await scan(pkgJson, [], registryMeta, []);
  assert(findings.length > 0);
  assert.equal(findings[0].id, 'TIER1-VERSION-BACKFILL');
  assert.equal(findings[0].severity, 'high');
  assert.ok(findings[0].message.includes('backfilled'));
});

test('TIER1-VERSION-BACKFILL: fewer than 8 versions returns no findings', async () => {
  const pkgJson = { name: 'test-pkg', version: '1.5.0' };
  const registryMeta = { time: makeTimeMap(5, 2) };
  const findings = await scan(pkgJson, [], registryMeta, []);
  assert.equal(findings.length, 0);
});

test('TIER1-VERSION-BACKFILL: spread over 48 hours returns no findings', async () => {
  const pkgJson = { name: 'test-pkg', version: '1.13.0' };
  const registryMeta = { time: makeTimeMap(20, 48) };
  const findings = await scan(pkgJson, [], registryMeta, []);
  assert.equal(findings.length, 0);
});

test('TIER1-VERSION-BACKFILL: sequential patches (no wide range) returns no findings', async () => {
  const pkgJson = { name: 'test-pkg', version: '1.0.7' };
  const time = { created: '2026-07-08T10:00:00.000Z', modified: '2026-07-08T12:00:00.000Z' };
  const baseTs = new Date('2026-07-08T10:00:00.000Z').getTime();
  for (let i = 0; i < 10; i++) {
    time[`1.0.${i}`] = new Date(baseTs + i * 10 * 60 * 1000).toISOString();
  }
  const registryMeta = { time };
  const findings = await scan(pkgJson, [], registryMeta, []);
  assert.equal(findings.length, 0);
});

test('TIER1-VERSION-BACKFILL: no registry meta returns no findings', async () => {
  const pkgJson = { name: 'test-pkg', version: '1.0.0' };
  const findings = await scan(pkgJson, [], null, []);
  assert.equal(findings.length, 0);
});

test('TIER1-VERSION-BACKFILL: no time field returns no findings', async () => {
  const pkgJson = { name: 'test-pkg', version: '1.0.0' };
  const registryMeta = { versions: ['1.0.0'] };
  const findings = await scan(pkgJson, [], registryMeta, []);
  assert.equal(findings.length, 0);
});

test('TIER1-VERSION-BACKFILL: known reputable package returns no findings', async () => {
  const pkgJson = { name: 'react', version: '1.13.0' };
  const registryMeta = { time: makeTimeMap(20, 3) };
  const findings = await scan(pkgJson, [], registryMeta, []);
  assert.equal(findings.length, 0);
});

test('TIER1-VERSION-BACKFILL: evidence includes version count and time spread', async () => {
  const pkgJson = { name: 'test-pkg', version: '1.13.0' };
  const registryMeta = { time: makeTimeMap(20, 3) };
  const findings = await scan(pkgJson, [], registryMeta, []);
  assert(findings.length > 0);
  assert.ok(findings[0].evidence.some((e) => e.startsWith('versions_count:')));
  assert.ok(findings[0].evidence.some((e) => e.startsWith('time_spread_hours:')));
});
