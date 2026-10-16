#!/usr/bin/env python3
"""Regenerates the OWASP MAS catalogues under Resources/Rules/taxonomy/ from upstream.

Writes maswe.json, mastg.json (iOS tests, deprecated v1 tests, best practices) and
masvs.json (the 24 controls), each stamped with the upstream commit it was read from.

    python3 scripts/sync-mas-catalogues.py            # rewrite the three files
    python3 scripts/sync-mas-catalogues.py --check    # exit 1 if upstream has moved on

Reads the OWASP/maswe, OWASP/mastg and OWASP/masvs GitHub trees, not the rendered site.
Set GITHUB_TOKEN to lift the anonymous API limit."""
import concurrent.futures as cf
import json
import os
import re
import sys
import urllib.request

OUT = 'Sources/ScannerKit/Resources/Rules/taxonomy'
SITE = 'https://mas.owasp.org'
REPOS = {'maswe': 'main', 'mastg': 'master', 'masvs': 'master'}


def api(path):
    req = urllib.request.Request('https://api.github.com/repos/OWASP/' + path)
    if os.environ.get('GITHUB_TOKEN'):
        req.add_header('Authorization', 'Bearer ' + os.environ['GITHUB_TOKEN'])
    return json.load(urllib.request.urlopen(req, timeout=60))


def raw(repo, sha, path):
    url = f'https://raw.githubusercontent.com/OWASP/{repo}/{sha}/{path}'
    return urllib.request.urlopen(url, timeout=60).read().decode()


def front_matter(text):
    """The YAML subset MAS front matter uses: scalars, [inline, lists], block lists and
    one level of nested mappings. Enough for these files; not a YAML parser."""
    m = re.match(r'---\n(.*?)\n---', text, re.S)
    out, parent, last = {}, None, None
    for line in (m.group(1) if m else '').splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        body = line.strip()
        if body.startswith('- '):
            target = out[parent] if parent and indent > 0 and isinstance(out.get(parent), dict) else out
            target.setdefault(last, [])
            if isinstance(target[last], list):
                target[last].append(body[2:].strip().strip('"\''))
            continue
        key, _, value = body.partition(':')
        value = value.strip()
        if value.startswith('['):
            value = [v.strip().strip('"\'') for v in value.strip('[]').split(',') if v.strip()]
        elif value == '':
            value = None
        else:
            value = value.strip('"\'')
        if indent == 0:
            out[key] = value if value is not None else {}
            parent, last = key, key
            if value is None:
                out[key] = {}
        else:
            if not isinstance(out.get(parent), dict):
                out[parent] = {}
            out[parent][key] = value if value is not None else []
            last = key
    for k, v in list(out.items()):
        if v == {}:
            out[k] = []
    return out


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def fetch_all(repo, sha, paths):
    with cf.ThreadPoolExecutor(16) as ex:
        return dict(zip(paths, ex.map(lambda p: front_matter(raw(repo, sha, p)), paths)))


def head(repo):
    c = api(f'{repo}/commits/{REPOS[repo]}')
    return c['sha'], c['commit']['committer']['date'][:10]


def latest_release(repo):
    rel = api(f'{repo}/releases?per_page=1')
    return rel[0]['tag_name'].lstrip('v') if rel else None


def tree(repo, sha):
    return [x['path'] for x in api(f'{repo}/git/trees/{sha}?recursive=1')['tree']]


def source(repo, sha, date):
    return {'repo': f'https://github.com/OWASP/{repo}', 'commit': sha, 'date': date,
            'release': latest_release(repo)}


def build_maswe():
    sha, date = head('maswe')
    paths = [p for p in tree('maswe', sha) if re.search(r'/MASWE-\d{4}\.md$', p)]
    weaknesses = {}
    for path, fm in sorted(fetch_all('maswe', sha, paths).items()):
        group = path.split('/')[-2]
        maps = fm.get('mappings') or {}
        weaknesses[fm['id']] = {
            'title': fm['title'],
            'group': group,
            'url': f'{SITE}/MASWE/{group}/{fm["id"]}/',
            'platforms': as_list(fm.get('platform')),
            'profiles': as_list(fm.get('profiles')),
            'masvsControls': as_list(maps.get('masvs-v2')),
            'cwe': [f'CWE-{int(c)}' for c in as_list(maps.get('cwe')) if str(c).isdigit()],
            'threat': fm.get('threat'),
        }
    return {
        'version': source('maswe', sha, date)['release'],
        'source': source('maswe', sha, date),
        'weaknesses': dict(sorted(weaknesses.items())),
    }


def build_mastg():
    sha, date = head('mastg')
    paths = tree('mastg', sha)
    v2 = [p for p in paths if re.match(r'tests-beta/ios/[^/]+/MASTG-TEST-\d{4}\.md$', p)]
    v1 = [p for p in paths if re.match(r'tests/ios/[^/]+/MASTG-TEST-\d{4}\.md$', p)]
    best = [p for p in paths if re.match(r'best-practices/MASTG-BEST-\d{4}\.md$', p)]
    fms = fetch_all('mastg', sha, v2 + v1 + best)

    tests = {}
    for p in v2:
        fm, group, tid = fms[p], p.split('/')[-2], p.split('/')[-1][:-3]
        if fm.get('status') == 'deprecated':
            continue
        tests[tid] = {
            'title': fm['title'],
            'group': group,
            'type': as_list(fm.get('type')),
            'maswe': as_list(fm.get('maswe')),
            'bestPractices': as_list(fm.get('best-practices')),
            'url': f'{SITE}/MASTG/tests/ios/{group}/{tid}/',
        }
    deprecated = {}
    for p in v1:
        fm, group, tid = fms[p], p.split('/')[-2], p.split('/')[-1][:-3]
        if fm.get('status') == 'deprecated':
            deprecated[tid] = {'title': fm.get('title'), 'coveredBy': as_list(fm.get('covered_by')),
                               'url': f'{SITE}/MASTG/tests/ios/{group}/{tid}/'}
    practices = {}
    for p in best:
        fm, bid = fms[p], p.split('/')[-1][:-3]
        platforms = as_list(fm.get('platform'))
        if platforms and 'ios' not in platforms and 'generic' not in platforms:
            continue
        practices[bid] = {'title': fm['title'], 'url': f'{SITE}/MASTG/best-practices/{bid}/'}

    src = source('mastg', sha, date)
    return {
        'version': src['release'],
        'source': src,
        'tests': dict(sorted(tests.items())),
        'deprecated': dict(sorted(deprecated.items())),
        'bestPractices': dict(sorted(practices.items())),
    }


def build_masvs():
    sha, date = head('masvs')
    paths = [p for p in tree('masvs', sha) if re.match(r'controls/MASVS-[A-Z]+-\d\.md$', p)]
    with cf.ThreadPoolExecutor(16) as ex:
        texts = dict(zip(paths, ex.map(lambda p: raw('masvs', sha, p), paths)))
    controls = {}
    for p, text in texts.items():
        cid = p.split('/')[-1][:-3]
        m = re.search(r'## Control\s+(.+?)\n', text)
        controls[cid] = {'statement': m.group(1).strip() if m else '',
                         'url': f'{SITE}/MASVS/controls/{cid}/'}
    src = source('masvs', sha, date)
    return {
        'version': src['release'],
        'source': src,
        'controls': dict(sorted(controls.items(), key=lambda kv: (kv[0].rsplit('-', 1)[0], int(kv[0].rsplit('-', 1)[1])))),
    }


def dump(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False) + '\n'


def main():
    check = '--check' in sys.argv
    built = {'maswe.json': build_maswe(), 'mastg.json': build_mastg(), 'masvs.json': build_masvs()}
    drift = []
    for name, obj in built.items():
        path = os.path.join(OUT, name)
        new = dump(obj)
        old = open(path).read() if os.path.exists(path) else ''
        if check:
            strip = lambda s: re.sub(r'"(commit|date)": "[^"]*"', '', s)
            if strip(old) != strip(new):
                drift.append(name)
        else:
            open(path, 'w').write(new)
            print(f'{path}: written')
    if check:
        if drift:
            print('upstream has changed: ' + ', '.join(drift) + '. Run without --check and review the diff.')
            sys.exit(1)
        print('MAS catalogues match upstream.')


if __name__ == '__main__':
    main()
