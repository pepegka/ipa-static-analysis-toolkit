# macOS app

ISAT is a SwiftUI macOS app. The window is a `NavigationSplitView` (`Views/ContentView.swift`):
a **sidebar** of scanned reports on the left, and the **report detail** with a segmented tab bar on
the right (`Views/ReportDetailView.swift`).

## Getting a report in

- **Drag & drop** one or more `.ipa` files onto the window (a blue dashed border appears on hover),
  or press **⌘O** to open the file picker. Each scan runs in the background; the sidebar shows a
  progress row with the current phase until it completes.
- **Pull from the App Store:** the toolbar's **Log In with Apple ID** and **Search App Store…**
  actions (backed by the bundled `ipatool` helper, `Services/IpatoolService.swift`) let you search
  for and download an app's `.ipa` straight into the app, where it can be scanned.
- The **Export…** toolbar menu (enabled when a report is selected) writes the current report as
  **HTML**, **Markdown**, **JSON** or **SARIF** (`Reports/ReportExporter.swift`), and offers
  **Update rule pack…** to install a YAML/`.tar.gz` rule pack from a URL.

## Sidebar (`Views/SidebarView.swift`)

- **Scanning:** pending scans with a progress spinner / phase text (or a red error).
- **Downloaded:** `.ipa` files pulled from the App Store but not yet scanned, each with
  **Scan** / **Reveal in Finder** / **Delete** actions (only shown when there are downloads).
- **Scanned apps:** one row per report: a worst-severity dot, the app display/bundle name, the
  bundle ID, and the finding count. Right-click → **Remove**.

## Report header (every tab)

One badge per severity present (critical to info, each a count coloured by severity), app
metadata (name, bundle ID, version, min iOS, embedded binary and framework counts) and scan
metadata (duration, finding count).

## The six report sections

The segmented picker has six top-level sections; some expand into sub-tabs.

### 1. Overview (`Views/Tabs/OverviewTab.swift`)
A single scrollable form:
- **Scanner notes** (if any).
- **Findings by cluster:** one row per MASVS control group present, plus `APPLE-POLICY`, each with
  a worst-severity dot and a finding count. Tap a cluster to expand its OWASP MASWE weakness
  classes.
- **Vector coverage:** horizontal bar chart of unique-artifact counts per vector, severity
  colour-coded, with a **Show all / hits-only** toggle.
- **Bundle:** name, bundle ID, version/build, executable, min iOS, platforms, signed team ID, and
  provisioning profile type/team/expiry.
- **Top findings:** the 12 highest-severity findings (via the shared [FindingRow](#finding-rows)),
  with a "see tabs for full list" footer when truncated.

### 2. Privacy
- **Findings:** `Views/Tabs/VectorsTab.swift` filtered to the privacy group: findings grouped by
  MASVS group → vector (code, title, count), each vector expandable to its findings or description.
  A **Show empty** toggle includes zero-hit vectors.
- **SDKs:** detected SDKs (name, country & category chips, red **TRACKER** badge, hit count,
  owner, endpoints, linked frameworks) plus the embedded-frameworks grid.
- **Permissions:** `Info.plist` usage-description keys (key, category, usage text, and the gated
  vector code), `LSApplicationQueriesSchemes`, `UIBackgroundModes`, and provisioning entitlements.
- **Privacy Manifest:** `PrivacyInfo.xcprivacy` path, declared accessed-API categories (with
  human descriptions) and declared tracking domains.

### 3. Security
- **Findings:** `VectorsTab` filtered to the security groups (storage, crypto, auth, platform,
  code, resilience).
- **Hardening:** per-binary architectures and **PIE / Canary / ARC / Encrypted** chips
  (✓ / ✗ / ? unknown), and the binary path.
- **Secrets:** redacted hardcoded secrets: severity badge, type, entropy, redacted value, and
  source + Mach-O section, with a type/binary filter field.

### 4. Network
- **Findings:** `VectorsTab` filtered to the network group.
- **Endpoints:** classified hosts with a host/owner filter, **Trackers only** toggle and country
  picker; each row shows a known/tracker/unknown icon, host, country & category chips, occurrence
  count, and expands to owner, registrable domain, sample paths and source binaries.
- **Transport (ATS):** pass/fail chips for global / web-content / media arbitrary loads and local
  networking; exception domains (with **CLEARTEXT** badge, subdomains, min TLS, forward secrecy);
  and the **URL-scheme attack surface** (the app's own `CFBundleURLSchemes`).

### 5. Research
- **Binaries:** embedded Mach-O list: encrypted-lock / cpu icon, name, size, architectures, path,
  and a disclosure group of linked dylibs.
- **Strings:** two-column string explorer (`Views/Tabs/StringsTab.swift`): a binary list (main
  executable starred, with per-binary string counts) and a search pane with **literal or regex**
  filter, **case-sensitive** toggle, per-Mach-O-section toggles, encrypted-section/cap warnings, and
  results showing section, hex offset, UTF-16 flag and the selectable string.
- **Files:** bundle file browser (`Views/Tabs/FilesTab.swift`): a filterable file tree
  (directories first, **Flagged** = suspicious-only toggle) and a preview pane rendering text,
  images or a hex dump (with a >2 MB guard), plus filename, category, size, SHA-256 and any
  suspicion reason.

### 6. Compare (`Views/Tabs/CompareTab.swift`)
Pick another scanned report to diff against. Shows a side-by-side header (severity tally, findings,
endpoint/SDK counts), paired vector bars, three-column SDK and endpoint comparisons
(only-in-A / shared / only-in-B), and a findings diff (only-in-A / only-in-B by rule ID). If no
other report exists, it shows a "drop another IPA to compare" empty state.

## Finding rows

Findings render through a shared `FindingRow` (`Views/Tabs/FindingRow.swift`).

- **Collapsed:** severity chip (colour-coded), title, a permission-gate badge when the capability
  needs an `Info.plist` permission (lock icon: all-granted / partial / none), and a chevron.
- **Expanded:** the explanation; a metadata row (rule ID, vector ID, **MASVS** pill, **MITRE** tags);
  the permission-gate detail (each required key ✓/○ by whether it's declared); **Frameworks** and
  **Binaries** chip flows; and **Evidence:** grouped by (kind, value) with the matched value, the
  Mach-O sections, and the source-binary chips it was found in.

## Report data

Besides findings, a `ScanReport` (`Models/ScanReport.swift`) carries these blocks. Each one shows
up in a tab above and in the HTML, Markdown, JSON and SARIF exports.

| Block | Model | Contents |
|---|---|---|
| Bundle metadata | `BundleMetadata` | bundle ID, names, version and build, executable, min iOS, platforms, signed team ID, provisioning, embedded binaries and frameworks, permissions, queried URL schemes, background modes, own URL schemes, privacy-manifest APIs and tracking domains |
| Network inventory | `NetworkInventory` | classified endpoints (country, category, owner, tracker flag, occurrences, sample paths, source binaries) and detected SDKs |
| Binary hardening | `[BinaryHardening]` | per-binary PIE, stack canary, ARC and FairPlay flags |
| Secrets | `[SecretHit]` | redacted secrets with type, entropy, binary and Mach-O section ([SECH-05](vectors.md#sech-05-hardcoded-secrets--credentials)) |
| Transport | `ATSConfig` | parsed `NSAppTransportSecurity`, including per-domain exceptions |
| File manifest | `[FileManifestEntry]` | every bundle file with kind, size, SHA-256 and a `suspicious` flag with its reason |
| Scanner notes | `[String]` | FairPlay encryption of the main binary, a missing provisioning profile, applied suppressions |
