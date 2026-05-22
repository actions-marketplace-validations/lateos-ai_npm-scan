import { MegalodonSignal } from './types.js';
import yaml from 'js-yaml';

const C2_EXFIL_RE = /curl\s+.*?https?:\/\/(?!github\.com|githubusercontent\.com|raw\.githubusercontent\.com)[^\s'"]+/i;
const SECRETS_REF_RE = /\$\{\{?\s*secrets\.\w+/;
const B64_DECODE_CHAIN_RE = /base64\s+-d\s*[|>]\s*(ba)?sh/;

function isWorkflowFile(f) {
  const p = f.path.replace(/\\/g, '/');
  return /\.github\/workflows\/.+\.(yml|yaml)$/i.test(p);
}

function countExecutableLines(text) {
  return text.split('\n').filter(l => l.trim() && !l.trim().startsWith('#')).length;
}

function extractRunBlocks(parsed) {
  const runs = [];
  if (!parsed || typeof parsed !== 'object') return runs;

  const walk = (obj) => {
    if (!obj || typeof obj !== 'object') return;
    if (Array.isArray(obj)) { obj.forEach(walk); return; }
    for (const [k, v] of Object.entries(obj)) {
      if (k === 'run' && typeof v === 'string') {
        runs.push(v);
      }
      if (k === 'env' && typeof v === 'object' && v !== null) {
        runs.push({ _env: v });
      }
      walk(v);
    }
  };
  walk(parsed);
  return runs;
}

function extractRunBlocksRaw(text) {
  const runs = [];
  const runMatch = text.match(/run:\s*[|>]\s*\n(\s{2,}.*(?:\n\s{2,}.*)*)/g);
  if (runMatch) runs.push(...runMatch.map(m => m.replace(/^run:\s*[|>]\s*\n/, '')));

  const inlineRe = /run:\s*['"](.+?)['"]\s*$/gm;
  let m;
  while ((m = inlineRe.exec(text)) !== null) runs.push(m[1]);

  const envRe = /env:\s*\n((?:\s{2,}\w+:\s*.+\n?)*)/g;
  let em;
  while ((em = envRe.exec(text)) !== null) runs.push({ _env: em[1] });
  return runs;
}

function runInStepHasBoth(step, signal) {
  const runVal = step.run;
  const envVals = step.env ? Object.values(step.env).filter(v => typeof v === 'string').join(' ') : '';
  const combined = typeof runVal === 'string' ? `${runVal} ${envVals}` : '';

  if (signal === 'exfil') {
    return C2_EXFIL_RE.test(combined) && SECRETS_REF_RE.test(combined);
  }
  if (signal === 'decode') {
    return B64_DECODE_CHAIN_RE.test(combined);
  }
  return false;
}

export async function scan(allFiles) {
  const evidence = [];
  const workflowFiles = allFiles.filter(isWorkflowFile);

  for (const f of workflowFiles) {
    if (f.content.length > 512 * 1024) continue;

    let parsed = null;
    let parseError = null;
    try {
      parsed = yaml.load(f.content);
    } catch (e) {
      parseError = e;
    }

    const rawRunBlocks = parsed ? extractRunBlocks(parsed) : extractRunBlocksRaw(f.content);
    const runStrings = rawRunBlocks.filter(r => typeof r === 'string');
    const envBlocks = rawRunBlocks.filter(r => typeof r === 'object' && r._env);

    let exfilTriggered = false;
    let decodeTriggered = false;

    for (const runStr of runStrings) {
      if (!exfilTriggered && C2_EXFIL_RE.test(runStr) && SECRETS_REF_RE.test(runStr)) {
        exfilTriggered = true;
        evidence.push({
          signal: MegalodonSignal.WORKFLOW_C2_EXFIL,
          file: f.path,
          excerpt: runStr.slice(0, 120),
          detail: 'C2 outbound call co-occurs with credentials reference in run block',
        });
      }

      if (!decodeTriggered && B64_DECODE_CHAIN_RE.test(runStr)) {
        decodeTriggered = true;
        evidence.push({
          signal: MegalodonSignal.WORKFLOW_DECODE_CHAIN,
          file: f.path,
          excerpt: runStr.slice(0, 120),
          detail: 'Base64 decode pipe to shell — obfuscated payload execution',
        });
      }
    }

    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const steps = parsed.jobs ? Object.values(parsed.jobs).flatMap(j => j.steps || []) : [];
      for (const step of steps) {
        if (!exfilTriggered && runInStepHasBoth(step, 'exfil')) {
          exfilTriggered = true;
          const runVal = step.run || '';
          evidence.push({
            signal: MegalodonSignal.WORKFLOW_C2_EXFIL,
            file: f.path,
            excerpt: runVal.slice(0, 120),
            detail: 'C2 outbound call co-occurs with secrets reference in same step',
          });
        }
        if (!decodeTriggered && runInStepHasBoth(step, 'decode')) {
          decodeTriggered = true;
          const runVal = step.run || '';
          evidence.push({
            signal: MegalodonSignal.WORKFLOW_DECODE_CHAIN,
            file: f.path,
            excerpt: runVal.slice(0, 120),
            detail: 'Base64 decode pipe to shell — obfuscated payload execution',
          });
        }
      }
    }

    const lineCount = countExecutableLines(f.content);
    if ((exfilTriggered || decodeTriggered) && lineCount >= 100 && lineCount <= 120) {
      const found = evidence.find(e => e.signal === MegalodonSignal.WORKFLOW_C2_EXFIL || e.signal === MegalodonSignal.WORKFLOW_DECODE_CHAIN);
      if (found) {
        found.detail += ` | Matches ${lineCount}-line Megalodon payload footprint`;
      }
    }
  }

  return evidence;
}
