export const versionBackfillManifest = {
  pkgJson: {
    name: 'ollama-helpers',
    version: '1.13.0',
    description: 'Helper utilities for Ollama local LLM integrations',
    main: 'index.js',
  },
  registryMeta: {
    time: (() => {
      const time = {
        created: '2026-07-08T10:00:00.000Z',
        modified: '2026-07-08T13:00:00.000Z',
      };
      const baseTs = new Date('2026-07-08T10:00:00.000Z').getTime();
      const spreadHours = 3;
      const spreadMs = spreadHours * 60 * 60 * 1000;
      const count = 20;
      const interval = spreadMs / (count - 1);
      const versions = [
        '0.1.0', '0.2.0', '0.3.0', '0.4.0', '0.5.0', '0.6.0',
        '1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0',
        '1.6.0', '1.7.0', '1.8.0', '1.9.0', '1.10.0', '1.11.0',
        '1.12.0', '1.13.0',
      ];
      for (let i = 0; i < count; i++) {
        time[versions[i]] = new Date(baseTs + interval * i).toISOString();
      }
      return time;
    })(),
  },
  expectedFindings: [
    { detector: 'tier1-version-backfill', id: 'TIER1-VERSION-BACKFILL' },
  ],
};
