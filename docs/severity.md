# Clusters and severity

A report is a list of findings. Each one is filed under the framework control it relates to and
carries a severity computed from a published anchor. `Construct` (DCS/TRK/TGAP/SURV/SECH/PLAT)
only groups vectors for browsing.

## Cluster rollup

`Collection<Finding>.clusterRollup()` (`Sources/ScannerKit/Models/ClusterRollup.swift`) files
every finding twice.

The first level is the cluster. `FindingCluster.of` puts each finding in exactly one of:

- one of the eight OWASP MASVS control groups, namely the group MASWE files the finding's weakness
  under (the vector's own group breaks ties);
- `APPLE-POLICY` for the TGAP vectors, which are App Store obligations;
- `INDICATORS` for findings bound to no MASWE weakness and no MASTG test. These cite their own
  source, usually Apple documentation or published research.

The second level is the MASWE weakness class. A finding bound to two weaknesses counts under
both, so the children can add up to more than the parent. The parent count is the number of
findings.

Each cluster has a per-severity tally, for example `MASVS-NETWORK · 6 findings (1 high)`.

### MASVS groups

The group of each vector is set in `Rules/taxonomy/vectors.json` (`MASVSGroup` in
`Models/Vector.swift`).

| Group | Covers | Vectors |
|---|---|---|
| `MASVS-PRIVACY` | data collection, tracking, fingerprinting, exfiltration | DCS-01…07, TRK-01/02/04/05, TGAP-01…03, SURV-01/03 |
| `MASVS-NETWORK` | transport security | SECH-01 |
| `MASVS-STORAGE` | data at rest, Keychain, secrets shipped in the bundle | SECH-02, SECH-05 |
| `MASVS-CRYPTO` | primitives, modes and keys | SECH-03 |
| `MASVS-PLATFORM` | platform APIs, IPC, WebViews, background execution | PLAT-01…04 |
| `MASVS-CODE` | build settings, hardening, dependencies, platform version | SECH-04/06/08/09 |
| `MASVS-RESILIENCE` | anti-tampering, anti-analysis, malware indicators | SURV-02/04/05 |
| `MASVS-AUTH` | authentication and authorization | SECH-07 |

A vector's construct and its MASVS group can differ: transport security is construct SECH and
group Network.

### Polarity

A MASWE binding names the weakness a finding is about. The rule's `polarity` (`polarity` in the
YAML or in `messages/findings.json`) says what the evidence shows:

| Polarity | Meaning | Cluster count | Weakness row |
|---|---|---|---|
| `offensive` (default) | evidence of the weakness or of risky behaviour | yes | yes |
| `neutral` | a reference to the API a MASTG test inspects, such as WKWebView | yes | no |
| `defensive` | evidence of a published mitigation (App Attest for MASWE-0056, pasteboard expiry for MASWE-0036, capture detection for MASWE-0038) | no | listed under Mitigations observed |

`PolarityTests` requires every `capability`-anchored rule to declare a non-offensive polarity
unless it is a named weakness banded at info.

How each rule is bound to MASWE, MASTG and MASVS is described in [frameworks.md](frameworks.md).

## Ordering

Apps in a mass scan are sorted by `(critical, high, medium, low, name)`
(`MassScanAppEntry.severityRank`). `MassScanReport.ordered` applies it in both `build` and
`rederivedFromDetail`, so a live run and a re-render sort the same way. Every table column can
still be sorted by hand.

## Severity

Each rule names its anchor in `Rules/taxonomy/severity-derivation.json` and the band is computed
from it:

| Method | Anchor | Band |
|---|---|---|
| `cvss` | the rule's CVSS v4.0 base vector | the score, through the CVSS v4.0 qualitative scale |
| `privacy` | the WP 248 criteria the processing meets, plus the GDPR article, LINDDUN threat and Solove harm | two or more criteria: `medium`, otherwise `info` |
| `compliance` | a declared-versus-evidenced mismatch against Apple's rules or GDPR Art. 13 | `info` |
| `capability` | an API, entitlement or setting is present and the MASTG test needs the call site to decide | `info` |

### Security: CVSS v4.0

Scores come from FIRST's calculator, vendored under `scripts/vendor/cvss-v4/` (BSD-2-Clause) and
run by `scripts/cvss4-score.mjs`. Pasting the same vector into
<https://www.first.org/cvss/calculator/4-0> gives the same number. The score is stored next to
the vector, and a stale score fails a test.

A rule gets a CVSS score only when the failing condition of its MASTG test is visible in the
bundle: ATS configuration (MASTG-TEST-0322, -0342), a hard-coded credential, an entitlement, a
build flag. When the test result depends on how code uses an API (MD5 for a checksum or a
password, MASTG-TEST-0211; `rand()` for a nonce, -0311; a CFStream socket with or without TLS,
-0323; a URL-scheme handler with or without validation, -0370), that code is FairPlay-encrypted,
so the rule is a `capability` and records the API for review.

How the metrics are chosen:

- Attack Vector is Network when the weakness is on a network path, and Local or Physical when the
  scan only sees a primitive or entitlement.
- Confidentiality is `VC:H` only where the scan can tell what is exposed, and `VC:L` otherwise.
  `NSAllowsArbitraryLoads` scores `VC:L/VI:L` (6.3, medium), since HTTPS traffic stays encrypted
  and what goes out in cleartext is not visible.

### Privacy: WP 248 high-risk criteria

MASVS, MASWE, LINDDUN and Solove publish no severity. GDPR Art. 35 separates processing that is
likely to result in a high risk, and the WP29 DPIA guidelines (WP 248 rev.01, endorsed by the EDPB
in Endorsement 1/2018) list nine criteria for it:

| # | Criterion |
|---|---|
| 1 | Evaluation or scoring, including profiling and predicting |
| 2 | Automated decision-making with legal or similar significant effect |
| 3 | Systematic monitoring |
| 4 | Sensitive data or data of a highly personal nature |
| 5 | Data processed on a large scale |
| 6 | Matching or combining datasets |
| 7 | Data concerning vulnerable data subjects |
| 8 | Innovative use or new technological or organisational solutions |
| 9 | Processing that prevents data subjects from exercising a right or using a service |

The guidelines say a processing meeting two criteria will in most cases need a DPIA. Each privacy
anchor lists the criteria it meets (`wp248`) and quotes the guideline in `why`. Two or more is
`medium`, fewer is `info`. Criterion 5 is never counted because the number of users is not in the
IPA.

A criterion can depend on what the app declares (`wp248When`). Systematic monitoring of location
only counts when `Info.plist` has `NSLocationAlwaysAndWhenInUseUsageDescription`; without it iOS
cannot grant Always authorization. The scanner lowers the band per app and names the criterion
that did not hold.

A declared permission (`perm.<key>`) is reported on its own unless a code finding needing the same
key is at least as severe. The deprecated `NSLocationAlwaysUsageDescription` meets no criterion,
since only iOS 10 and earlier read it.

Tracker SDKs take their criteria from the tracker category (`trackerCategories`): advertising and
attribution 1 and 6, session replay 1 and 3, anti-fraud 1 and 9, analytics and push engagement 1.

### Tests

`SeverityDerivationTests` fails if any rule's `severity:` differs from what its anchor produces, or
if a rule has no anchor. The YAML keeps `severity:` so a rule can be read on its own.

`SeverityCallSiteTests` covers severities raised by the Swift analyzers. It reads the literal
`.derived(...)` ids from the sources, and for ids built at runtime (`perm.<key>`,
`privacy.<api>`, `privacy.gap.<category>`, `SECH-05.<class>`) it walks the same tables the
analyzers use. Built ids must hit a rule-level anchor; literal ids may fall back to their vector.

After changing an anchor:

```sh
node scripts/cvss4-fill.mjs
python3 scripts/sync-rule-severities.py
swift test --filter SeverityDerivation
```

## Framework identifiers

Every finding carries `mastg`, `maswe`, `cwe`, `linddun`, `solove`, `gdpr` and `cvss` in
`report.json` and SARIF. The rule's anchor supplies them where it has them, and
`Rules/taxonomy/crosswalk.json` fills in the rest from the vector. A rule with no CVSS anchor
prints no CVSS. Each finding also carries `why`, the anchor's one-line reason, into the Markdown
and HTML reports, the CycloneDX properties and the app.

Coverage is listed by `FrameworkCrosswalk.implementedMASTGTests` and `implementedMASWEWeaknesses`.
Each report records the framework versions it was built against (`FrameworkVersions`: MASVS 2.1.0,
MASTG 2.0.0, MASWE 1.0.0, ATT&CK Mobile 18.1, CVSS 4.0). Rendered MASWE titles come from the
catalogue in the current build, which is why the cluster table shows `MASWECatalog.version`.

## Declaration gaps

`compliance` findings cover a privacy-manifest category the binary uses but no manifest declares,
tracking domains missing from `NSPrivacyTrackingDomains` (MASTG-TEST-0281), and purpose strings
that explain nothing. They are `info`. iOS blocks requests to domains a manifest declares when ATT
permission is denied; an undeclared tracking domain is not blocked.
