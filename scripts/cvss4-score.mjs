import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const here = dirname(fileURLToPath(import.meta.url));
const vendor = join(here, 'vendor', 'cvss-v4');
const ctx = vm.createContext({});
for (const f of ['cvss_lookup.js', 'max_composed.js', 'max_severity.js', 'cvss_score.js']) {
  vm.runInContext(readFileSync(join(vendor, f), 'utf8'), ctx, { filename: f });
}

const DEFAULTS = {
  AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
  VC: 'N', VI: 'N', VA: 'N', SC: 'N', SI: 'N', SA: 'N',
  E: 'X', CR: 'X', IR: 'X', AR: 'X',
  MAV: 'X', MAC: 'X', MAT: 'X', MPR: 'X', MUI: 'X',
  MVC: 'X', MVI: 'X', MVA: 'X', MSC: 'X', MSI: 'X', MSA: 'X',
  S: 'X', AU: 'X', R: 'X', V: 'X', RE: 'X', U: 'X',
};

export function score(vector) {
  const parts = String(vector).split('/');
  if (parts.shift() !== 'CVSS:4.0') throw new Error(`not a CVSS:4.0 vector: ${vector}`);
  const selected = { ...DEFAULTS };
  for (const p of parts) {
    const [k, v] = p.split(':');
    if (!(k in DEFAULTS)) throw new Error(`unknown metric ${k} in ${vector}`);
    selected[k] = v;
  }
  ctx.__sel = selected;
  const macro = vm.runInContext('macroVector(__sel)', ctx);
  const s = vm.runInContext(
    'cvss_score(__sel, cvssLookup_global, maxSeverity, macroVector(__sel))', ctx);
  return { score: Math.round(s * 10) / 10, macroVector: macro };
}

export function band(s) {
  if (s === 0) return 'none';
  if (s < 4.0) return 'low';
  if (s < 7.0) return 'medium';
  if (s < 9.0) return 'high';
  return 'critical';
}

const arg = process.argv[2];
if (arg) {
  const r = score(arg);
  console.log(`${r.score}\t${band(r.score)}\tmacro ${r.macroVector}`);
}
