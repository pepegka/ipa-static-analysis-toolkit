# Architecture

## Scan pipeline

`Scanner.scanIndexed` (`Sources/ScannerKit/Pipeline/Scanner.swift`) runs one IPA:

1. Extract the `.ipa` to a temp directory (`Extractor/IPAExtractor.swift`).
2. Walk the `.app` bundle and collect Mach-O binaries, frameworks and privacy manifests. Symbolic
   links are not followed.
3. Parse the provisioning profile (`Provisioning/MobileProvisionParser.swift`), the code signature
   (`CodeSigning/CodeSignReader.swift`) and `Info.plist` (`Plist/InfoPlistAnalyzer.swift`).
4. Index the strings and symbols of every binary in parallel (`Indexer/BinaryIndex.swift`), keyed by
   Mach-O section.
5. Evaluate the YAML rule pack against the index and metadata (`Rules/RuleEngine.swift`) and run the
   analyzers written in Swift: privacy-manifest gap and validation, ATS, binary hardening, secrets,
   storage, app extensions.
6. Attribute the extracted URLs and hosts (`Network/NetworkInventoryBuilder.swift`).
7. Apply suppressions (`Rules/Suppression.swift`), roll findings up into clusters and build the
   report.

## Terms

- **Vector**: a category of behaviour such as `SURV-01`, declared in
  `Rules/taxonomy/vectors.json` with a title, a MASVS group, MITRE ATT&CK Mobile technique IDs and
  advice for users.
- **Rule**: one detector (`Rules/Rule.swift`) loaded from `Rules/vectors/*.yaml`. It has one or more
  `search` patterns (strings, symbols, dylibs, plist keys and values, URL schemes, background modes,
  entitlements, framework names), an `attribution` block naming frameworks where the signal is
  benign or the SDK that owns it, `mitre`/`masvs`/`maswe`/`mastg` tags, and optional
  `requires_permission`, `tracker_ids` and `user_advice`. Some vectors come from Swift analyzers
  rather than YAML; [vectors.md](vectors.md) lists which.
- **Finding**: a rule that fired (`Models/Finding.swift`). It carries a severity, the evidence (the
  matched value plus the file and Mach-O section it came from), the owning frameworks, the affected
  binaries and any permission gating (the `Info.plist` usage keys the capability needs and whether
  they are declared).
- **Evidence kind**: `stringMatch`, `symbol`, `objcSelector`, `plistKey`, `plistValue`,
  `entitlement`, `linkedDylib`, `url`, `file` or `manifestGap`.

## Network endpoints and trackers

Endpoints are hosts found in the bundle (binary strings, resources, privacy manifests). Nothing is
observed on the wire.

- The registrable domain comes from the Mozilla [Public Suffix List](https://publicsuffix.org/),
  vendored at `Rules/domains/public_suffix_list.dat` including the private section, so two tenants
  of `appspot.com` or `blob.core.windows.net` are two owners.
- Tracker identity (id, category, tracker flag) is only taken from a domain the tracker database
  lists, or a subdomain of it. Ownership (owner, country) may extend to the registrable domain:
  `www.amazon.com` belongs to Amazon but is not Amazon Ads.
- First-party hosts sit under the app's own associated domains. Entries under a catalogued
  organisation are skipped, because attribution vendors and identity providers host universal
  links and OAuth redirects for their customers (`*.onelink.me`, `*.adj.st`, `*.app.link`).
- URLs inside reference documents (an IAB TCF vendor list, a JSON list of partner privacy
  policies, licence and acknowledgement files), bare symbol names and reverse-DNS identifiers such
  as `io.ktor.utils.io` are not endpoints.
- Country is the owning organisation's home jurisdiction, not where a server sits.

## Rule data

Everything the scanner matches against lives under `Sources/ScannerKit/Resources/Rules/`:

| Folder | Contents |
|---|---|
| `vectors/` | YAML detection rules, one file per vector |
| `taxonomy/` | vectors, MASVS/MASWE/MASTG catalogues, crosswalk, permissions, regions, severity anchors, cited sources |
| `trackers/` | tracker database (domains, owner, country, category) |
| `domains/` | Public Suffix List, AI endpoints, TLDs, hosts that are not endpoints, reference-document markers |
| `privacy/` | Apple's required-reason APIs, listed SDKs, collected-data types, purpose strings |
| `secrets/` | secret patterns and the public-client exceptions |
| `security/` | pinning, storage and resource-scan indicator lists |
| `platform/` | App Store minimum SDK requirements |
| `messages/` | finding and dashboard text |
| `suppressions/` | default suppressions |

`ISAT --update-rules <https-url>` installs a rule pack (YAML or `.tar.gz`) into
`~/Library/Application Support/ISAT/Rules/`. When that folder holds rules, they are used instead
of the bundled pack.

## Suppressions

`Rules/suppressions/default.yaml` removes known noise. An entry without `value_pattern` drops a
whole finding, scoped by rule, vector or binary glob. An entry with `value_pattern` drops only the
evidence rows whose value matches; a finding left with no evidence is dropped too. For example,
stock `/bin/bash` debug strings only count as jailbreak evidence when a real Cydia or
MobileSubstrate path is also present. Suppression files in
`~/Library/Application Support/ISAT/Rules/suppressions/` replace the default set.

## Reporting

Findings are rolled up by cluster (`Models/ClusterRollup.swift`): one of the eight OWASP MASVS
control groups, `APPLE-POLICY` for App Store obligations MASVS does not cover (privacy manifest,
tracking domains, ATT, kids category), or `INDICATORS` for checks no framework describes. Each
cluster breaks down into the MASWE weakness classes its findings bind to. Every count can be
checked against the findings list.

Severity is derived from published anchors, see [severity.md](severity.md). Mass-scan apps are
ordered by a severity tally `(critical, high, medium, low, name)`.

`ISAT --render-dashboard dashboard.json` rebuilds the cluster counts from each app's embedded
detail with the current taxonomy and rewrites `dashboard.json` and the HTML, without re-scanning or
reading the `.ipa` files.
