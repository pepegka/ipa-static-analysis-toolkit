import Foundation

extension MassScanDashboardExporter {

    static func h2(_ title: String, _ id: String, nav: String? = nil, trailing: String = "") -> String {
        let navAttr = nav.map { " data-nav=\"\(HTML.esc($0))\"" } ?? ""
        return "<h2 id=\(id)\(navAttr)>\(title)\(trailing)</h2>"
    }

    static func card(_ title: String, _ chartID: String, span: Int = 1, tall: Bool = false) -> String {
        let spanCls = span > 1 ? " span\(span)" : ""
        let tallCls = tall ? " tall" : ""
        return "<div class=\"card\(spanCls)\"><h3>\(HTML.esc(title))</h3><div id=\(chartID) class=\"chart\(tallCls)\"></div></div>"
    }

    static func siblingReports(_ entry: MassScanAppEntry, root: URL?) -> [(String, String)] {
        var found: [(String, String)] = []
        var seen = Set<String>()
        func add(_ format: String, _ rel: String) {
            guard !seen.contains(format) else { return }
            seen.insert(format); found.append((format, rel))
        }
        for format in ["html", "json", "md", "sarif"] {
            if let rel = entry.reportPaths[format] {
                if root == nil || FileManager.default.fileExists(atPath: root!.appendingPathComponent(rel).path) {
                    add(format, rel)
                }
            }
        }
        if let root, let anyRel = entry.reportPaths.values.first {
            let dir = (anyRel as NSString).deletingLastPathComponent
            for format in ["html", "json", "md", "sarif"] where !seen.contains(format) {
                let rel = dir.isEmpty ? "report.\(format)" : "\(dir)/report.\(format)"
                if FileManager.default.fileExists(atPath: root.appendingPathComponent(rel).path) {
                    add(format, rel)
                }
            }
        }
        let order = ["html", "json", "md", "sarif"]
        return found.sorted { (order.firstIndex(of: $0.0) ?? 9) < (order.firstIndex(of: $1.0) ?? 9) }
    }

    public static func html(_ report: MassScanReport, inlineECharts: String? = nil,
                            assetRoot: URL? = nil) -> String {
        let run = report.run, st = report.stats
        let scanned = report.apps.filter(\.ok)
        let failures = report.apps.filter { !$0.ok }
        let policyGaps = scanned.filter { ($0.clusterCounts[FindingCluster.applePolicy.id] ?? 0) > 0 }.count
        let hasCategories = scanned.contains { ($0.category.map { !$0.isEmpty && $0 != "(unknown)" }) ?? false }

        var s = "<!doctype html><html lang=en><head><meta charset=utf-8>"
        s += "<meta name=viewport content=\"width=device-width, initial-scale=1\">"
        s += "<title>Mass-scan dashboard: \(scanned.count) apps</title><style>"
        s += Self.css
        s += "</style></head><body>"

        s += "<div class=pagehead><h1>Mass-scan dashboard</h1>"
        s += "<button id=theme-toggle type=button title=\"Switch theme\" aria-label=\"Switch theme\"></button></div>"
        s += "<div class=sub>"
        s += "\(HTML.esc(run.feed))"
        s += " · storefront <code>\(HTML.esc(run.country.uppercased()))</code>"
        if let g = run.genre { s += " · genre <code>\(HTML.esc(g))</code>" }
        s += " · \(run.scanned) scanned · \(run.failed) failed · "
        s += "\(HTML.byteSize(run.totalIPABytes)) of IPAs · \(seconds(run.totalScanSeconds))s scan · "
        s += "generated \(ISO8601DateFormatter().string(from: run.createdAt))</div>"
        s += "<div id=offline class=banner style=\"display:none\">⚠︎ Charts need an internet connection (ECharts CDN). The tables below always work offline.</div>"
        s += "<nav id=secnav aria-label=\"Sections\"></nav>"

        s += "<div class=kpis>"
        s += kpi("\(st.appsScanned)", "apps scanned")
        s += kpi("\(st.totalFindings)", "total findings")
        let crit = st.severityHistogram.first { $0.label == "critical" }?.count ?? 0
        let high = st.severityHistogram.first { $0.label == "high" }?.count ?? 0
        if crit + high > 0 { s += kpi("\(crit + high)", "critical + high", accent: "sev-critical") }
        if policyGaps > 0 { s += kpi("\(policyGaps)", "apps with an Apple policy gap", accent: "sev-high") }
        s += kpi("\(st.totalUniqueTrackers)", "distinct tracker SDKs")
        s += kpi("\(st.appsWithATSArbitraryLoads)", "apps allowing arbitrary loads (ATS)")
        s += kpi("\(st.appsWithSecrets)", "apps shipping a hard-coded credential")
        s += "</div>"

        let insights = insightCards(report)
        if !insights.isEmpty {
            s += h2("Key insights", "s-insights", trailing: "<button id=insight-restore type=button hidden>↺ show <span class=n>0</span> hidden</button>") + insights
        }

        s += h2("Findings by cluster", "s-clusters", nav: "Clusters") + "<div class=charts>"
        s += card("Findings by cluster (severity)", "c_cluster", span: 2, tall: true)
        s += card("Cluster reach (apps with a low-or-above weakness)", "c_clusterreach", tall: true)
        s += card("MASWE weakness classes (weakness findings)", "c_maswe", span: 3, tall: true)
        s += "</div>"

        let profiles = clusterProfilesHTML(report)
        if !profiles.isEmpty {
            s += h2("Cluster profiles (apps per finding)", "s-profiles", nav: "Profiles") + profiles
        }

        s += h2("Where findings come from", "s-origin", nav: "Attribution") + "<div class=charts>"
        s += card("First-party code vs embedded SDKs", "c_origin", tall: true)
        s += card("Embedded SDKs raising the most findings", "c_sdkfindings", span: 2, tall: true)
        s += "</div>"

        s += h2("Distributions", "s-dist") + "<div class=charts>"
        s += card("Findings by severity", "c_sev")
        s += card("Binary hardening flags (% of binaries)", "c_hardflags", span: hasCategories ? 1 : 2)
        if hasCategories { s += card("App categories", "c_cats") }
        s += "</div>"

        s += h2("Per-app analysis", "s-perapp") + "<div class=charts>"
        s += card("Findings severity composition (per app)", "c_appsev", span: 3, tall: true)
        s += card("MASVS coverage \u{2014} 6 apps with the most severe findings", "c_radar", span: 2, tall: true)
        s += card("MASVS groups (apps with a low-or-above weakness)", "c_masvs", tall: true)
        s += "</div>"

        s += h2("Patterns &amp; correlations", "s-risk", nav: "Patterns") + "<div class=charts>"
        if hasCategories { s += card("Findings per app by category (3+ apps)", "c_catrisk", tall: true) }
        s += card("Trackers per app (distribution)", "c_trkdist")
        s += card("App size distribution", "c_sizedist")
        s += card("Privacy-sensitive permissions (% of apps)", "c_sensperm")
        s += card("Trackers vs privacy findings", "c_trkpriv")
        s += card("App size vs findings", "c_sizefind", span: hasCategories ? 1 : 2)
        s += "</div>"

        s += h2("Trackers &amp; data flow", "s-trackers", nav: "Trackers") + "<div class=charts>"
        s += card("Tracker SDKs by category", "c_trkcat")
        s += card("Tracker owners by country (data sovereignty)", "c_trkcountry")
        s += card("Top tracker owners (companies)", "c_trkowner", tall: true)
        if hasCategories {
            s += card("Findings per app by category and severity (3+ apps)", "c_catsev", span: 2, tall: true)
            s += card("Developers by findings per app (2+ apps)", "c_devs", tall: true)
        }
        s += card("Tracker category reach (treemap)", "c_trktree", span: 3)
        s += "</div>"

        s += h2("Top-N rollups", "s-topn") + "<div class=charts>"
        s += card("Top trackers (by app count)", "c_trackers")
        s += card("Top endpoint owners (treemap)", "c_owners")
        s += card("Top endpoint countries", "c_countries")
        s += card("Top requested permissions", "c_perms")
        s += card("Most common vectors (apps with a low-or-above weakness)", "c_vectors", span: 2)
        s += "</div>"

        if scanned.contains(where: { !$0.trackerNames.isEmpty }) {
            s += h2("App ↔ tracker network", "s-graph", nav: "Network") + "<div class=charts>"
            s += card("Shared-tracker graph", "c_graph", span: 3, tall: true)
            s += "</div>"
        }

        s += h2("Data tables", "s-tables") + "<div class=charts>"
        s += dataTable("Top trackers", st.topTrackers, unit: "Tracker")
        s += dataTable("Top endpoint owners", st.topEndpointOwners, unit: "Owner")
        s += dataTable("Top endpoint countries", st.topEndpointCountries, unit: "Country",
                       rename: { "\(flag($0.label)) \($0.label)".trimmingCharacters(in: .whitespaces) })
        s += dataTable("Top requested permissions", st.topPermissions, unit: "Permission",
                       rename: { $0.detail?.isEmpty == false ? $0.detail! : readablePermission($0.label) },
                       demote: { $0.label })
        func vectorCode(_ i: CountItem) -> String {
            String(i.label.split(whereSeparator: { $0 == "\u{2014}" || $0 == "\u{2013}" || $0 == "," })
                     .first ?? "").trimmingCharacters(in: .whitespaces)
        }
        func vectorTitle(_ i: CountItem) -> String {
            let parts = i.label.split(maxSplits: 1, whereSeparator: { $0 == "\u{2014}" || $0 == "\u{2013}" || $0 == "," })
            return parts.count > 1 ? String(parts[1]).trimmingCharacters(in: .whitespaces) : i.label
        }
        s += dataTable("Most common vectors", st.topVectors, unit: "Vector",
                       rename: { vectorTitle($0) },
                       demote: { vectorCode($0) })
        s += dataTable("MASVS group frequency", st.masvsGroupFrequency, unit: "Group")
        s += "</div>"

        s += h2("Compare apps", "s-compare") + "<div class=cmp-wrap>"
        s += "<div class=cmp-combo id=cmpCombo>"
        s += "<div class=cmp-chips id=cmpChips></div>"
        s += "<input type=search id=cmpSearch placeholder=\"Search apps to compare, pick 2 to 10…\" autocomplete=off role=combobox aria-expanded=false>"
        s += "<div class=cmp-drop id=cmpDrop hidden></div>"
        s += "</div>"
        s += "<div class=cmp-bar>"
        s += "<span class=cmp-count id=cmpCount>Pick 2–10 apps to compare</span>"
        s += "<button id=cmpClear class=ghost>Clear all</button>"
        s += "<span class=cmp-hint>Click any metric row to drill into finding-by-finding detail.</span>"
        s += "</div>"
        s += "<div class=cmp-out id=cmpOut></div></div>"

        s += h2("All apps (\(scanned.count))", "s-apps", nav: "All apps",
                trailing: "<button id=cluster-cols type=button aria-pressed=false>Show MASVS cluster columns</button>")
        let clusterCols = FindingCluster.allOrdered.map(\.id)
        var cols = ["#", "App", "Bundle ID"]
        if hasCategories { cols.append("Category") }
        cols += ["Ver", "Findings", "Severity"] + clusterCols
            + ["Trackers", "Flags", "Size", "Scan", "Report"]
        let textCols: Set<String> = ["App", "Bundle ID", "Category", "Ver", "Severity", "Flags", "Report"]
        let numCols = Set(cols.enumerated().filter { !textCols.contains($0.element) }.map(\.offset))
        let clusterIdx = Set(cols.enumerated().filter { clusterCols.contains($0.element) }.map(\.offset))

        func span(_ label: String, _ n: Int, _ cls: String = "") -> String {
            "<th colspan=\(n)\(cls.isEmpty ? "" : " class=\(cls)")>\(HTML.esc(label))</th>"
        }
        s += "<div class=scroll><table id=apps><thead>"
        s += "<tr class=colgroups>"
        s += span("Identity", hasCategories ? 5 : 4)
        s += span("Findings", 2)
        s += span("MASVS clusters \u{2014} a finding can sit in several, so these sum above the total",
                  clusterCols.count, "cl")
        s += span("Signals", 2)
        s += span("Meta", 3)
        s += "</tr><tr>"
        for (i, c) in cols.enumerated() {
            var cls: [String] = []
            if numCols.contains(i) { cls.append("num") }
            if clusterIdx.contains(i) { cls.append("cl") }
            let attr = cls.isEmpty ? "" : " class=\"\(cls.joined(separator: " "))\""
            let title = clusterIdx.contains(i)
                ? " title=\"Findings mapped to \(HTML.esc(c)). A finding can map to more than one cluster.\""
                : ""
            s += "<th\(attr)\(title) onclick=\"sortT(\(i))\">\(HTML.esc(c))</th>"
        }
        s += "</tr></thead><tbody>"
        for (i, a) in scanned.enumerated() {
            let link = siblingReports(a, root: assetRoot)
                .map { "<a href=\"\(HTML.esc($0.1))\">\($0.0)</a>" }
                .joined(separator: " \u{00B7} ")
            func numCell(_ v: Int) -> String { "<td class=num data-v=\(v)>\(v)</td>" }
            s += "<tr>"
            s += "<td class=num data-v=\(i + 1)>\(i + 1)</td>"
            s += "<td>\(HTML.esc(a.appStoreName))</td>"
            s += "<td><code>\(HTML.esc(a.bundleID))</code></td>"
            if hasCategories { s += "<td>\(HTML.esc(a.category ?? ""))</td>" }
            s += "<td>\(HTML.esc(a.version ?? ""))</td>"
            s += numCell(a.findingsCount ?? 0)
            s += severityCell(a)
            for k in clusterCols { s += "<td class=\"num cl\" data-v=\(a.clusterCounts[k] ?? 0)>\(a.clusterCounts[k] ?? 0)</td>" }
            s += numCell(a.trackerCount ?? 0)
            s += flagsCell(a)
            s += "<td class=num data-v=\(a.sizeBytes ?? 0)>\(a.sizeBytes.map(HTML.byteSize) ?? "")</td>"
            s += "<td class=num data-v=\(String(format: "%.0f", (a.scanSeconds ?? 0) * 1000))>\(seconds(a.scanSeconds ?? 0))s</td>"
            s += "<td>\(link)</td>"
            s += "</tr>"
        }
        s += "</tbody></table></div>"

        if !failures.isEmpty {
            s += h2("Failures (\(failures.count))", "s-failures", nav: "Failures") + "<div class=scroll><table><thead><tr><th>App</th><th>Bundle ID</th><th>Reason</th></tr></thead><tbody>"
            for a in failures {
                s += "<tr><td>\(HTML.esc(a.appStoreName))</td><td><code>\(HTML.esc(a.bundleID))</code></td><td class=dim>\(HTML.esc(a.error ?? ""))</td></tr>"
            }
            s += "</tbody></table></div>"
        }

        s += methodologyFooter()
        s += "<script id=msdata type=\"application/json\">\(compactJSON(report))</script>"
        s += "<script id=msadvice type=\"application/json\">\(adviceJSON())</script>"
        if let js = inlineECharts, !js.isEmpty {
            s += "<script>\n\(js.replacingOccurrences(of: "</script", with: "<\\/script"))\n</script>"
        }
        s += "<script>\n\(Self.chartJS)\n</script>"
        s += "<script>\n\(Self.comparatorJS)\n</script>"
        s += "<script>\n\(Self.insightToggleJS)\n</script>"
        s += "<script>\n\(Self.chromeJS)\n</script>"
        if inlineECharts?.isEmpty == false {
            s += "<script>if(window.__drawDashboard)window.__drawDashboard();</script>"
        } else {
            s += "<script>\n\(Self.loaderJS)\n</script>"
        }
        s += "</body></html>"
        return s
    }

    static func methodologyFooter() -> String {
        let psl = PublicSuffixList.version.map { " (\(HTML.esc($0)))" } ?? ""
        var s = "<footer class=method><h2 id=s-method data-nav=Method>Method &amp; limits</h2><ul>"
        s += "<li>Rules are bound to \(FrameworkCrosswalk.implementedMASWEWeaknesses.count) OWASP MASWE weaknesses and "
        s += "\(FrameworkCrosswalk.implementedMASTGTests.count) MASTG tests; severities come from CVSS v4.0 or the GDPR high-risk criteria of WP 248, never typed in.</li>"
        s += "<li>Weakness counts only include findings that evidence the weakness. A mitigation observed (App Attest in use, a backup-exclusion API) and a bare API reference are reported but never tallied as the weakness.</li>"
        s += "<li>Registrable domains come from the Public Suffix List\(psl), so tenants of shared hosting (appspot.com, blob.core.windows.net) are kept apart.</li>"
        s += "<li>A static scan shows what an app contains and can do. It does not observe traffic: an embedded SDK or endpoint is not proof of a transfer, and country is the owner's home jurisdiction, not server location.</li>"
        s += "<li>FairPlay-encrypted code hides its strings, so tracker, endpoint and secret counts are a floor, not a census.</li>"
        return s + "</ul></footer>"
    }

    static func adviceJSON() -> String {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        return HTML.scriptJSON((try? enc.encode(Vectors.userAdvice)) ?? Data("{}".utf8))
    }

    static let css = HTML.bundledText("dashboard/dashboard.css")
    static let chartJS = HTML.bundledText("dashboard/charts.js")
    static let comparatorJS = HTML.bundledText("dashboard/comparator.js")
    static let loaderJS = HTML.bundledText("dashboard/loader.js")
    static let insightToggleJS = HTML.bundledText("dashboard/insight-toggle.js")
    static let chromeJS = HTML.bundledText("dashboard/chrome.js")
}
