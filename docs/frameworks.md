# Frameworks

Every finding is tied to a published source. Below are those sources, how a rule is bound to
them, and how to update them.

## OWASP MAS catalogues

| File | Holds | Source |
|---|---|---|
| `Rules/taxonomy/maswe.json` | The MASWE weaknesses, each with the MASVS v2 controls, CWE ids and verification profiles MASWE publishes for it | [OWASP/maswe](https://github.com/OWASP/maswe) |
| `Rules/taxonomy/mastg.json` | The current iOS MASTG tests (id, title, static or dynamic, MASWE, best practices), the deprecated iOS v1 tests with the v2 tests that replace them, and the iOS best practices | [OWASP/mastg](https://github.com/OWASP/mastg) |
| `Rules/taxonomy/masvs.json` | The 24 MASVS v2 controls and their statements | [OWASP/masvs](https://github.com/OWASP/masvs) |

All three are generated, and stamped with the upstream commit and release they were read from:

```sh
python3 scripts/sync-mas-catalogues.py          # regenerate from upstream
python3 scripts/sync-mas-catalogues.py --check  # exit 1 if upstream has moved on
```

After a sync, run `swift test`. `MASCatalogTests` fails on any binding to a test that upstream has
deprecated or that is not static, and on any weakness that is not an iOS one.

## How a rule is bound

Each YAML rule declares its own binding:

```yaml
- id: SECH-02.backup_exclusion_marker
  maswe: [MASWE-0006]
  mastg: [MASTG-TEST-0215]
```

Analyser rules declare the same two keys in `Rules/messages/findings.json`. An empty list is a
statement: no MASWE weakness or MASTG test describes the check. A rule pack without the keys
falls back to its vector's crosswalk entry.

The binding has to hold against upstream:

- A cited MASTG test must be static and current, and MASTG must file it under one of the rule's
  MASWE weaknesses. Cite a test only when the rule's evidence is what that test inspects.
- A rule-level CWE (in `severity-derivation.json`) must be one MASWE publishes for the rule's
  weakness. Without one, the finding carries every CWE its weaknesses map to.

From the binding, each finding gets:

| Field | From |
|---|---|
| `maswe` | the rule's binding |
| `masvsControls` | the MASVS v2 controls those weaknesses map to |
| `mastg` | the rule's binding |
| `cwe` | the anchor's CWE, or the weaknesses' mappings |
| `references` | the rule's own citations, then the MASWE, MASTG test and MASTG best-practice pages |

Reports link each id to its page: the MASVS control, the MASWE weakness, the MASTG test, the CWE
entry, the ATT&CK technique, and FIRST's CVSS v4.0 calculator loaded with the vector. The MASWE
verification profiles (L1, L2, P for privacy, R for resilience) are shown next to the weakness.

Findings with no MASWE weakness and no MASTG test go to the `INDICATORS` cluster, outside the
MASVS clusters. Each cites its own primary source.

## Apple sources

| File | Holds | Source |
|---|---|---|
| `Rules/privacy/required-reason-apis.json` | The required-reason API categories, the APIs Apple lists for each, and the 17 approved reason codes | [NSPrivacyAccessedAPIType](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacyaccessedapitypes/nsprivacyaccessedapitype) |
| `Rules/privacy/apple-listed-sdks.json` | The SDKs that must ship a privacy manifest | [Third-party SDK requirements](https://developer.apple.com/support/third-party-SDK-requirements/) |
| `Rules/privacy/collected-data-types.json` | The collected-data types and purposes | [NSPrivacyCollectedDataType](https://developer.apple.com/documentation/bundleresources/app-privacy-configuration/nsprivacycollecteddatatypes/nsprivacycollecteddatatype) |
| `Rules/platform/requirements.json` | The SDK App Store Connect requires for uploads | [Upcoming requirements](https://developer.apple.com/news/upcoming-requirements/?id=04282026a) |

These are copied by hand from the pages above. Only values on Apple's page belong in them: a probe
for an API Apple does not list would report an obligation Apple does not impose. Apple's DocC JSON endpoint
(`developer.apple.com/tutorials/data/documentation/<path>.json`) is the reliable way to read these
pages from a script.

Symbol-based rules name symbols the iOS SDK exports. Before adding one, confirm the symbol is in
the SDK's `.tbd` export lists (`xcrun --sdk iphoneos --show-sdk-path`); enum constants such as
`kCCAlgorithmDES` or `LAPolicyDeviceOwnerAuthentication` compile to integers and never appear as
symbols or strings.

## What a static scan can read

FairPlay encrypts each App Store binary's `__TEXT` segment. The symbol table, entitlements, plists
and bundled files stay readable, so rules written against imported symbols, plist keys and
entitlements work on any IPA. Rules that search only code strings see only unencrypted binaries.
Each report records this under `coverage` (binaries, binaries with readable code strings, and the
string-only rules) and says it in the scan notes.

## SARIF

SARIF output carries MASWE, MASTG, CWE and MASVS-control taxonomies, each taxon with its name and
page, and each result lists the taxa of its own finding (SARIF 2.1.0, `result.taxa`).
