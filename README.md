# ISAT: IPA Static Analysis Toolkit

ISAT is a static analyser for iOS `.ipa` files. It unpacks the app bundle and looks at the Mach-O
binaries, entitlements, provisioning profile, `Info.plist`, privacy manifests and embedded strings
to find privacy and security issues. Everything runs locally and offline.

It ships as a SwiftUI macOS app and a command-line tool, both built on the `ScannerKit` library.

ISAT can also fetch apps from the App Store through the bundled
[`ipatool`](https://github.com/majd/ipatool): sign in with your Apple ID, search, download and
scan. The password goes only to Apple and is not stored by ISAT; the session is kept in the macOS
keychain.

## What it checks

Each rule is bound to the OWASP MASWE weakness it detects and, where one fits, the static OWASP
MASTG test whose evidence it checks. Findings are grouped by the OWASP MASVS control group of their
weakness and carry the MASVS controls, CWE ids and MASWE profiles that MASWE publishes for it, all
linked. App Store obligations that MASVS does not cover go to an `APPLE-POLICY` cluster, and checks
that no framework describes go to `INDICATORS` with their own cited source. Severity is derived
from CVSS v4.0 or the GDPR WP 248 criteria, see [docs/severity.md](docs/severity.md).

Rules are grouped into six constructs, and every vector has a code such as `DCS-02` or `SURV-01`:

- **DCS, data collection**: device fingerprinting, location, clipboard, contacts and photos,
  motion sensors, audio/video/screen capture, installed-app enumeration, proximity sensing (BLE,
  UWB, Wi-Fi, Bonjour).
- **TRK, tracking**: analytics, attribution and anti-fraud SDKs, data brokers, owner
  jurisdictions of referenced servers, cloud AI endpoints.
- **TGAP, transparency gaps**: privacy-manifest gaps and validation against Apple's rules (reason
  codes, SDKs that must ship a manifest, collected-data types, tracking domains), ATT ordering,
  child safety and age assurance.
- **SURV, surveillance and evasion**: VPN and proxy detection, anti-debug and anti-jailbreak,
  hidden exfiltration, obfuscation, known spyware and stalkerware indicators.
- **SECH, security hygiene**: ATS, TLS and pinning, hard-coded `http://` URLs, data protection,
  cryptography, binary hardening (PIE, canary, ARC, debug symbols), hard-coded secrets, code
  signing and sensitive entitlements, keychain and authentication, SDK provenance, minimum iOS and
  build SDK.
- **PLAT, platform attack surface**: WebView JavaScript bridges, URL handlers, app extensions and
  custom keyboards, silent and VoIP push, background modes.

## Build and run

Requires macOS 14 or later and a recent Swift toolchain.

```sh
swift build                      # library, app and CLI
swift test
swift run ISAT                   # launch the macOS app
scripts/build-dmg.sh             # build an unsigned .app and .dmg into dist/
```

In the app, drop an `.ipa` on the window or press Cmd-O, or use Log In and Search App Store to
fetch one. Reports export as HTML, Markdown, JSON or SARIF (with MASWE, MASTG, CWE and MASVS
taxonomies), and as a CycloneDX SBOM. Downloaded apps show up in the sidebar with Scan, Reveal and
Delete actions.

## CLI

`ISAT --help` lists every option.

```sh
# Scan and report
ISAT --scan App.ipa > report.json            # JSON report to stdout
ISAT --report sarif App.ipa out.sarif        # json | md | markdown | html | sarif
ISAT --sbom cyclonedx App.ipa sbom.json      # CycloneDX SBOM of detected SDKs and frameworks
ISAT --diff old.json new.json                # compare two reports (add --json)
ISAT --time App.ipa                          # per-phase timing
ISAT --canary App.ipa                        # probe a fixed list of indicators
ISAT --index-stats App.ipa                   # string and symbol index statistics

# Store metadata is not in the IPA; the child-safety checks (TGAP-03) need it
ISAT --scan App.ipa --store-genre Kids --content-rating "4+"

# Rules
ISAT --rules-info                            # rules by construct, MASWE/MASTG coverage
ISAT --update-rules <https-url>              # install a rule pack (YAML or .tar.gz)

# App Store
ISAT --login --email me@example.com          # password via prompt, --password or $ISAT_APPLE_ID_PASSWORD
ISAT --login --email me@example.com --gui    # macOS dialogs for password and 2FA
ISAT --login --email me@example.com --auth-code 123456
ISAT --account-info
ISAT --search "telegram" --limit 10 --platform iphone
ISAT --download 686449807 --scan             # by app ID or bundle ID, then scan
ISAT --download ph.telegra.Telegraph --output ./ipas
ISAT --logout

# Mass-scan
ISAT --massscan --top 100                    # top-100 free apps: download, scan, dashboard
ISAT --massscan --top 50 --formats json,html # also write per-app HTML reports
ISAT --massscan --dry-run --top 20           # print the chart list only
ISAT --massscan --scan-only ./ipas           # aggregate a folder of .ipa files
ISAT --render-report massscan-.../apps html  # render report.html from saved report.json files
ISAT --render-dashboard massscan-.../dashboard.json
```

## Mass-scan

`--massscan` takes the most popular apps from Apple's public RSS charts (no login needed for the
list), downloads each `.ipa` with `ipatool` (this part needs `--login`), scans it, writes the
per-app reports and builds an aggregate dashboard (`dashboard.html`, `.json`, `.md`).

The HTML dashboard uses [Apache ECharts](https://echarts.apache.org/): KPI and insight cards,
findings by cluster, cluster profiles, distributions, per-app severity bars, a MASVS radar,
tracker and endpoint rollups, an app-to-tracker graph, sortable tables and a list of failures. A
Compare tool puts 2 to 10 apps side by side with a drill-down per metric. ECharts is saved next to
the HTML so the page works offline. See [docs/dashboard.md](docs/dashboard.md).

`--render-dashboard <dashboard.json> [out-dir]` rebuilds the HTML and Markdown from an existing run
without downloading or scanning again, and inlines ECharts when it is available.
`--render-report <path> [fmt]` does the same for per-app reports. Every finding has a "For users"
note next to the developer remediation.

```
ISAT --massscan [options]
  --top N            number of apps (default 100; one chart feed returns at most 100-200
                     apps, so a larger N is filled from genre charts)
  --feed F           top-free | top-paid (default top-free; paid apps cannot be downloaded)
  --kind K           apps | games | all (default all)
  --max-size SIZE    skip apps larger than SIZE, e.g. 100MB, 1.5GB (default no limit), using
                     sizes from the iTunes Lookup API before downloading
  --country CC       App Store storefront; must match the Apple ID's region (default: the Mac's)
  --genre ID         restrict to one App Store genre ID
  --output DIR       output root (default ./massscan-<date>)
  --formats LIST     per-app report formats: json,html,md,sarif (default json)
  --dashboard LIST   dashboard formats: html,json,md (default html,json,md)
  --delay S          seconds between download batches (default 4)
  --concurrency N    parallel downloads and scans per batch (default 1)
  --max-retries N    download retries with exponential backoff (default 3)
  --rescan           re-scan even when report.json already exists
  --keep-ipa         keep downloaded .ipa files (default: delete after a successful scan);
                     a kept <output>/ipas/<bundleID>.ipa is reused on the next run
  --scan-only DIR    skip charts and downloads; aggregate a folder of .ipa files
  --store-metadata F with --scan-only: take App Store identity (id, category, developer, chart
                     rank) from an earlier dashboard.json, matched by bundle ID
  --dry-run          print the app list only
  --platform P       iphone | ipad | appletv (default iphone)
  --email/--password/--auth-code/--gui
                     sign in before downloading, as for --login
```

Downloads run one at a time with a 4 second gap and back off when throttled. A failed download or
scan is recorded and the run continues. Downloaded IPAs are deleted after scanning unless
`--keep-ipa` is set, since 100 apps can take tens of GB. Only free apps and apps already in your
library can be downloaded.

Every downloaded file is saved as `<bundleID>.ipa`. For `--download <appID>` the bundle ID comes
from the iTunes Lookup API.

The Apple ID password is passed to a single `ipatool` login call and is never stored or logged by
ISAT. `ipatool` only accepts it as a command-line argument, so while the login runs it is visible
to other processes of the same user. `ipatool` keeps the session token in the keychain; the first
time, macOS asks for permission, and Always Allow avoids the prompt on later runs.

## FairPlay

App Store binaries are FairPlay-encrypted, so the `__TEXT` strings of the main executable cannot be
read without a decrypted dump (for example from `frida-ios-dump` or `bagbak`). Embedded frameworks
are usually encrypted as well. What stays readable is `__LINKEDIT` (symbol tables, imported and
defined symbols, linked dylibs), every plist, the entitlements and the bundled resources. Rules
built on symbols, plists and entitlements therefore work on any IPA, while rules that only search
code strings see only unencrypted binaries. Each report records which binaries were encrypted.

## Documentation

- [docs/architecture.md](docs/architecture.md): scan pipeline, terms, endpoint attribution, rule
  data and suppressions
- [docs/vectors.md](docs/vectors.md): every vector and its rules
- [docs/severity.md](docs/severity.md): clusters, polarity and how severity is derived
- [docs/frameworks.md](docs/frameworks.md): MASVS, MASWE, MASTG and Apple sources and how rules
  bind to them
- [docs/app-tabs.md](docs/app-tabs.md): the macOS app, tab by tab
- [docs/dashboard.md](docs/dashboard.md): the mass-scan dashboard and `dashboard.json`
- [scripts/README.md](scripts/README.md): helper scripts

## Third-party code

| Component | Use | License |
|---|---|---|
| [`ipatool`](https://github.com/majd/ipatool) by Majd Alfhaily | bundled binary (`Sources/ISAT/Resources/ipatool`) run as a subprocess for App Store login, search and download | MIT, (c) 2021 Majd Alfhaily |
| [Yams](https://github.com/jpsim/Yams) by JP Simard | Swift package dependency of `ScannerKit` for parsing the YAML rule packs | MIT, (c) 2016 JP Simard |
| [Apache ECharts](https://echarts.apache.org/) | dashboard charts; `echarts.min.js` 5.5.0 is downloaded from jsDelivr next to the generated dashboard, not committed here | Apache-2.0 |

Detection rules and the taxonomy are based on public frameworks, guides and datasets, which are
cited rather than copied; see [docs/vectors.md](docs/vectors.md#sources). When extending the
tracker database or the rules, only use sources whose licences allow modification and
redistribution, and record them in [THIRD_PARTY.md](THIRD_PARTY.md).

## License

MIT, see [LICENSE](LICENSE). Third-party notices and the sourcing policy are in
[THIRD_PARTY.md](THIRD_PARTY.md).
