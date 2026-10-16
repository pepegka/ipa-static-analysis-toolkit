#!/usr/bin/env python3
"""Rewrites `severity:` in Resources/Rules/vectors/*.yaml to whatever the derivation table
produces for each rule.

The YAML keeps a severity so a rule stays readable and greppable on its own; the derivation is
the authority. SeverityDerivationTests fails if the two disagree, and this script is how you
make them agree after changing an anchor. Run it, read the diff, commit both."""
import json, re, glob, sys, collections

D = json.load(open('Sources/ScannerKit/Resources/Rules/taxonomy/severity-derivation.json'))
BANDS = sorted(D['cvssBands'], key=lambda b: -b['min'])
HR = D['gdprHighRisk']

def band(score):
    for b in BANDS:
        if score >= b['min']:
            return b['severity']
    return 'info'

def severity(e):
    m = e['method']
    if m == 'capability':
        return 'info'
    if m == 'cvss':
        return band(e['cvssScore'])
    if m == 'privacy':
        met = set(e['wp248']) - set(HR['notScored'])
        return HR['atOrAbove'] if len(met) >= HR['threshold'] else HR['below']
    if m == 'compliance':
        return D['compliance'][e['kind']]
    raise SystemExit(f'unknown method {m}')

def entry(rule_id, vector_id):
    key = rule_id
    while True:
        if key in D['rules']:
            return D['rules'][key]
        if '.' not in key:
            break
        key = key.rsplit('.', 1)[0]
    return D['vectors'].get(vector_id)

changed = collections.Counter()
unanchored = []
for path in sorted(glob.glob('Sources/ScannerKit/Resources/Rules/vectors/*.yaml')):
    lines = open(path).read().split('\n')
    current = None
    for i, line in enumerate(lines):
        m = re.match(r'^(\s*-?\s*)id:\s*(\S+)\s*$', line)
        if m:
            current = m.group(2)
            continue
        m = re.match(r'^(\s*)severity:\s*(\S+)\s*$', line)
        if m and current:
            e = entry(current, current.split('.')[0])
            if e is None:
                unanchored.append(current)
                continue
            want = severity(e)
            if want != m.group(2):
                changed[(m.group(2), want)] += 1
                print(f'{current:46s} {m.group(2):9s} -> {want}')
            lines[i] = f'{m.group(1)}severity: {want}'
    open(path, 'w').write('\n'.join(lines))

if unanchored:
    print('\nUNANCHORED (the test will fail on these):', file=sys.stderr)
    for u in unanchored:
        print('  ' + u, file=sys.stderr)
print(f'\n{sum(changed.values())} rule(s) changed')
for (a, b), n in sorted(changed.items(), key=lambda x: -x[1]):
    print(f'  {a:9s} -> {b:9s} {n}')
sys.exit(1 if unanchored else 0)
