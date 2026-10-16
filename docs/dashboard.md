# Mass-scan dashboard

`--massscan` scans a batch of App Store apps and writes one aggregate dashboard for the batch. The
generator is `Sources/ScannerKit/Reports/MassScanDashboardExporter*.swift` and the data model is
`Sources/ScannerKit/Models/MassScanReport.swift`.

A run writes three files to the output root: `dashboard.html`, `dashboard.json` (see the
[schema](#dashboardjson-schema)) and `dashboard.md`. `--dashboard` picks which ones (default
`html,json,md`).

## Generating it

```sh
ISAT --massscan --top 100                    # top-100 free apps: download, scan, dashboard
ISAT --massscan --top 50 --formats json,html # also write a per-app HTML report
ISAT --massscan --scan-only ./ipas           # aggregate a folder of existing .ipa files
ISAT --massscan --dry-run --top 20           # print the chart list only
```

The runner (`Sources/ISAT/Services/MassScanRunner.swift`) reads the chart from Apple's public RSS
feed, downloads each `.ipa` with the bundled `ipatool`, scans it, writes the per-app reports,
builds the statistics (`MassScanReport.make`) and writes the dashboard. All options are listed in
the [README](../README.md#mass-scan).

## Re-rendering

```sh
ISAT --render-dashboard <dashboard.json> [out-dir]
```

This rebuilds `dashboard.html`, `dashboard.md` and `dashboard.json` from an existing
`dashboard.json` without downloading or scanning anything.

- The output directory defaults to the folder holding `dashboard.json`.
- Apps without drill-down detail get it filled in from their `report.json`
  (`reportPaths["json"]`, resolved relative to `dashboard.json`). Apps that already have
  `details`, failed apps and apps whose report is missing are left alone.
- Cluster rollups, cluster and MASVS-group reach and MASWE frequencies are recomputed from each
  app's detail, so a taxonomy or polarity change shows up without a rescan.
- When an `echarts.min.js` sits next to the JSON (or in the Application Support cache), it is
  inlined and the HTML becomes a single self-contained file. Otherwise the page keeps the external
  loader.
- Progress goes to stderr: `Enriched <n> app(s) with drill-down detail` when `n > 0`, then one
  `Wrote <bytes> bytes to <path>` line per file. On error it prints `Render failed: …` and exits 1.

## Page sections

The page is drawn with [Apache ECharts](https://echarts.apache.org/). The report is embedded as
JSON in `<script id=msdata type="application/json">` and every chart and table is built from it in
the browser. Sections, in order:

### Header and KPI cards

The title row shows feed, storefront, genre, scanned and failed counts, total IPA size, total scan
time and the generation time. The KPI cards are: apps scanned, total findings, critical and high
(when non-zero), apps with an Apple-policy gap (when non-zero), distinct tracker SDKs, apps allowing
arbitrary loads, and apps shipping a hard-coded credential. Public client identifiers, such as a
Firebase API key in its config file, are not counted as credentials.

The storefront also matters for `--scan-only` runs, because "outside {country}" on the sovereignty
cards is relative to it. Pass `--country` to such a run.

### Key insights

Stat cards grouped under tracking, AI and child safety, surveillance, security, data sovereignty
and footprint. Each card has a value, a sentence and a footnote. The wording is in
`Rules/messages/insights.json` and the arithmetic in `MassScanDashboardExporter+Insights.swift`. A
card at 0% is dropped; a card at 100% is greyed out as a baseline.

How the cards count:

- Behaviour cards count apps with weakness evidence at low severity or above
  (`appsWithWeakness`). Info-level inventory such as an imported symbol or a linked WKWebView is
  in nearly every app, so it is not counted. Mitigations (`defensive`) and bare references
  (`neutral`) are never counted.
- An embedded SDK or a referenced endpoint is what the scan sees, so the cards say "embed" and
  "reference" rather than "send data to".
- Country is the owner's home jurisdiction from the tracker database. "Outside {country}" is
  relative to the run's storefront.

Ties are reported as ties ("12 apps have none"), and a category needs at least five apps before it
is called the busiest.

### Findings by cluster

| Card | Chart |
|---|---|
| Findings by cluster (severity) | stacked bars, one row per MASVS group plus `APPLE-POLICY` and `INDICATORS`; mitigations left out |
| Cluster reach | apps with offensive evidence at low or above in each cluster |
| MASWE weakness classes | offensive findings per MASWE weakness (top 18) |

Only `offensive` findings count under a weakness. `defensive` findings are evidence of a published
mitigation (App Attest for MASWE-0056, the backup-exclusion API for MASWE-0006, capture detection
for MASWE-0038) and are listed under Mitigations observed. `neutral` findings reference an API a
MASTG test inspects. See [severity.md](severity.md#polarity).

### Cluster profiles

One card per cluster with findings, then a Mitigations observed card. These are rendered in Swift
rather than by ECharts, so they work offline. `dashboard.md` has the same numbers as tables.

| Part | Contents |
|---|---|
| Header | apps with a low-or-above weakness in the cluster, "N of M apps", the same number as Cluster reach (`ClusterProfileTests` checks this on the local corpora) |
| Weakness chips | the MASWE weaknesses behind the counted findings, each with its app count and a link |
| Bars | counted findings (offensive, low or above), most apps first, as a share of the corpus and coloured by the worst severity reached. Eight show; the rest are under "+N more findings" |
| Also filed here, not counted | the cluster's neutral and info-level findings, collapsed |

Rows count apps and are keyed by rule. A check that creates one rule per value
(`privacy.gap.<category>`, `perm.<key>`, `tracker.<id>`, `SECH-05.<class>.<type>`) is a single row:
its family is the `Rules/messages/findings.json` entry the rule resolves to (`Messages.familyKey`),
each app is counted once, and the members are listed under the bar with their own app counts.

### Where findings come from

| Card | Chart |
|---|---|
| First-party code vs embedded SDKs | findings stacked by severity, split by whether the evidence came from the app's own binaries (extensions included) or an embedded framework |
| Embedded SDKs raising the most findings | findings per embedded framework (top 18), app count in the tooltip |

A finding with no owning framework, or one owned by `(main)`, belongs to the app's own code.

### Distributions

Findings by severity, binary hardening flags (% of binaries) and app categories. The hardening
card shows PIE, stack canary, ARC and the FairPlay-encrypted share. Where a binary is encrypted,
its `__TEXT` strings were not available to any rule (see the README's
[FairPlay](../README.md#fairplay) section).

### Per-app analysis

Severity composition per app as stacked bars, a MASVS radar for the six apps with the most severe
findings, and MASVS group frequency.

### Patterns

| Card | Chart |
|---|---|
| Findings per app by category (3+ apps) | mean per app, `(n)` after each category |
| Trackers per app | buckets `0,1,2,3,4,5+` |
| App size distribution | buckets `<50 MB … 500 MB+` |
| Privacy-sensitive permissions (% of apps) | a fixed list of sensitive `NS…UsageDescription` keys |
| Trackers vs privacy findings | scatter of trackers against MASVS-PRIVACY findings |
| App size vs findings | scatter of MB against findings |

### Trackers

Built from each app's tracker detail (`details.trackers`), so an app counts once per company,
category or country.

| Card | Chart |
|---|---|
| Tracker SDKs by category | donut |
| Tracker owners by country | donut over the owners' home jurisdictions |
| Top tracker owners | bars |
| Findings per app by category and severity (3+ apps) | stacked bars, mean per app |
| Developers by findings per app (2+ apps) | bars; only when the run has App Store metadata |
| Tracker category reach | treemap |

### Top-N rollups

Top trackers, top endpoint owners (treemap), top endpoint countries, top requested permissions,
and most common vectors (apps with a low-or-above weakness under the vector).

### App and tracker network

A force-directed graph of apps (sized by tracker count) linked to trackers (sized by how many apps
embed them). Shown when at least one app has a tracker.

### Data tables

Server-rendered tables that repeat the rollups, so they work without ECharts.

### Method and limits

The MASWE/MASTG binding counts, the polarity rule, the Public Suffix List version and what a
static scan cannot see.

### All apps and failures

A sortable table with one row per app: position, name, bundle ID, category, version, finding total
with a severity bar, one collapsed column per cluster, trackers, flags, size, scan time and a link
to the per-app report. Rows are ordered by `(critical, high, medium, low, name)`. The failures
table lists apps that could not be downloaded or scanned, with the reason.

## Compare apps

A picker for 2 to 10 apps that renders a side-by-side comparison. It reads the embedded `msdata`
JSON itself, so the table works offline; only its two charts need ECharts.

### Picking apps

- Type to filter by name, bundle ID or category. Each row shows a worst-severity dot, the name,
  category and version, and the finding count.
- ↓/↑ move the highlight, Enter adds it, Esc closes the list, Backspace on an empty field removes
  the last chip.
- Picked apps become removable chips. Clear all resets. With fewer than two apps nothing is shown.

### Table

One row per metric, one column per app, with a sticky first column. Numeric rows mark the best
(green) and worst (red) value when they differ; a value most of the selection shares is left
uncoloured.

| Section | Rows |
|---|---|
| Findings by cluster | one row per cluster present; mitigations not counted |
| Findings | total, critical, high, medium, low, info |
| Attack vectors | distinct vectors detected |
| Privacy and network | trackers, declared permissions, hard-coded credentials, ATS arbitrary loads |
| Binary hardening | binaries without PIE, FairPlay-encrypted binaries |
| Metadata | category, developer, version, chart rank, download size, scan time; rows empty for every app are omitted |

Next to the table sits a Findings by severity bar with one row per app.

### Drill-down

Rows backed by per-app detail expand into a presence matrix: entities down the left, one ✓/✗ (or
count) per app. This works for total findings and each severity, distinct vectors, trackers,
declared permissions, the two hardening rows and each cluster row.

- The matrix is the union over the picked apps. Vector rows show artifact counts; hardening rows
  list the flags known for each binary.
- Entities are grouped by family: findings by cluster, permissions by their leading CamelCase
  word (`Location*`, `Photo*`), trackers by category and owner. Families are ordered by worst
  severity, entities shared by every app are dimmed.
- Rows are built on first expand. Apps without [`AppCompareDetail`](#appcomparedetail) show
  "no detail".
- Finding and vector rows have an ⓘ marker with advice for users (what to switch off in Settings,
  what to avoid). The advice (`Vectors.userAdvice`) is embedded as `<script id=msadvice>` and also
  appears in each per-app report as "For users:".

## Offline use

The page loads a local `echarts.min.js` first and falls back to the jsDelivr CDN (`loader.js`).
During a `--massscan` run with an HTML dashboard, `echarts@5.5.0` is downloaded next to the HTML
and cached in Application Support. If neither copy loads, an offline banner appears and the
server-rendered tables, the all-apps table and the comparator table still work.

## `dashboard.json` schema

`dashboard.json` is the encoded `MassScanReport`: a `run` summary, an `apps` array (scanned apps
in severity order, then failures) and a `stats` block. The HTML embeds a compact copy in
`<script id=msdata>`.

- `run` (`MassScanRun`): `createdAt`, `country`, `feed` (`top-free`, `top-paid` or `scan-only`),
  `genre`, `requested`, `downloaded`, `scanned`, `failed`, `totalScanSeconds`, `totalIPABytes`.
- `apps[]` (`MassScanAppEntry`): App Store metadata (`appID`, `bundleID`, `appStoreName`,
  `artist`, `category`, `chartRank`, `version`) and the scan summary (`findingsCount`,
  `criticalCount`, `highCount`, `trackerCount`, `secretCount`, `atsArbitraryLoads`, `sizeBytes`,
  `scanSeconds`, `reportPaths`, `severityCounts`, `masvsCounts`, `clusterCounts`, `trackerNames`,
  `error`). Failed apps carry only metadata and `error`.
- `stats` (`MassScanStats`): `appsScanned`, `totalFindings`, `totalUniqueTrackers`,
  `appsWithATSArbitraryLoads`, `appsWithSecrets` and the rollups (`severityHistogram`,
  `clusterFrequency`, `masweFrequency`, `topTrackers`, `topEndpointOwners`,
  `topEndpointCountries`, `topPermissions`, `topVectors`, `masvsGroupFrequency`), each a list of
  `{ label, count, detail? }`.

### `AppCompareDetail`

Each app may also carry `details`, a small slice of its `ScanReport` used by the comparator. It
has short keys and no evidence, so 150 apps add a few MB to the HTML.

| Field | Element | Holds |
|---|---|---|
| `findings` | `DFinding` | `severity`, `vector`, `title`, `group` (MASVS group, `""` if none), `framework?`, `label`, `count?`, `detail?`, `maswe?`, `mastg?`, `cluster?` (nil for a mitigation), `rule?`, `polarity?` (`defensive` or `neutral`; absent means offensive) |
| `vectors` | `DVector` | `code`, `title`, `group`, `severity` (max), `artifacts` |
| `trackers` | `DTracker` | `name`, `owner`, `country`, `category` |
| `hardening` | `DHardening` | `name`, `pie`, `canary?`, `arc?`, `encrypted` |
| `permissions` | `DPermission` | `key`, `category?` |

`details` is filled in during a scan (`MassScanAppEntry.withScan` and `AppCompareDetail.from`) or
by `--render-dashboard`.
