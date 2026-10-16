import { readFileSync, writeFileSync } from 'node:fs';
import { score, band } from './cvss4-score.mjs';

const path = 'Sources/ScannerKit/Resources/Rules/taxonomy/severity-derivation.json';
const d = JSON.parse(readFileSync(path, 'utf8'));
let n = 0;
for (const [id, e] of Object.entries(d.rules)) {
  if (e.method !== 'cvss') continue;
  const r = score(e.cvss);
  e.cvssScore = r.score;
  n++;
  console.log(`${id}\t${r.score}\t${band(r.score)}`);
}
writeFileSync(path, JSON.stringify(d, null, 2) + '\n');
console.error(`scored ${n} rules`);
