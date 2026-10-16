import Foundation

extension MassScanDashboardExporter {

    public static func markdown(_ report: MassScanReport) -> String {
        let run = report.run, st = report.stats
        var s = "# Mass-scan dashboard\n\n"
        s += "- **Generated:** \(ISO8601DateFormatter().string(from: run.createdAt))\n"
        s += "- **Source:** \(run.feed)"
        if run.feed != "scan-only" { s += " · country `\(run.country)`" }
        if let g = run.genre { s += " · genre `\(g)`" }
        s += "\n"
        s += "- **Apps:** \(run.scanned) scanned · \(run.failed) failed · \(run.requested) requested\n"
        s += "- **Total scan time:** \(seconds(run.totalScanSeconds))s · **Total IPA size:** \(HTML.byteSize(run.totalIPABytes))\n\n"

        s += "## Summary\n\n"
        s += "| Metric | Value |\n|---|---:|\n"
        s += "| Apps scanned | \(st.appsScanned) |\n"
        s += "| Total findings | \(st.totalFindings) |\n"
        s += "| Unique trackers | \(st.totalUniqueTrackers) |\n"
        s += "| Apps w/ ATS arbitrary loads | \(st.appsWithATSArbitraryLoads) |\n"
        s += "| Apps w/ potential secrets | \(st.appsWithSecrets) |\n\n"

        func bucketTable(_ title: String, _ items: [CountItem], unit: String) {
            guard items.contains(where: { $0.count > 0 }) else { return }
            s += "## \(title)\n\n| \(unit) | Count |\n|---|---:|\n"
            for i in items { s += "| \(i.label) | \(i.count) |\n" }
            s += "\n"
        }
        bucketTable("Findings by severity", st.severityHistogram, unit: "Severity")

        func topTable(_ title: String, _ items: [CountItem], unit: String, limit: Int = 20) {
            let top = items.prefix(limit)
            guard !top.isEmpty else { return }
            s += "## \(title)\n\n| \(unit) | Apps | Detail |\n|---|---:|---|\n"
            for i in top { s += "| \(i.label) | \(i.count) | \(i.detail ?? "") |\n" }
            s += "\n"
        }
        topTable("Top trackers (by app count)", st.topTrackers, unit: "Tracker")
        topTable("Top endpoint owners", st.topEndpointOwners, unit: "Owner")
        topTable("Top endpoint countries", st.topEndpointCountries, unit: "Country")
        topTable("Top requested permissions", st.topPermissions, unit: "Permission key")
        topTable("Most common vectors", st.topVectors, unit: "Vector")
        topTable("MASVS group frequency", st.masvsGroupFrequency, unit: "Group")
        topTable("Cluster frequency", st.clusterFrequency, unit: "Cluster", limit: 12)
        topTable("MASWE weakness classes", st.masweFrequency, unit: "Weakness")
        s += clusterProfilesMarkdown(report)

        let scanned = report.apps.filter(\.ok)
        s += "## Most findings by severity (top 20)\n\n"
        s += "| # | App | Bundle ID | Ver | Findings | Crit | High | Med | Low | Trackers | Secrets |\n"
        s += "|---:|---|---|---|---:|---:|---:|---:|---:|---:|---:|\n"
        for (i, a) in scanned.prefix(20).enumerated() {
            let sev = a.severityRank
            s += "| \(i + 1) | \(a.appStoreName) | `\(a.bundleID)` | \(a.version ?? "") | "
            s += "\(a.findingsCount ?? 0) | \(sev[0]) | \(sev[1]) | \(sev[2]) | \(sev[3]) | "
            s += "\(a.trackerCount ?? 0) | \(a.secretCount ?? 0) |\n"
        }
        s += "\nOrdered by critical, then high, then medium, then low. A tally, not a score.\n\n"

        let failures = report.apps.filter { !$0.ok }
        if !failures.isEmpty {
            s += "## Failures (\(failures.count))\n\n| App | Bundle ID | Reason |\n|---|---|---|\n"
            for a in failures {
                s += "| \(a.appStoreName) | `\(a.bundleID)` | \(a.error ?? "") |\n"
            }
            s += "\n"
        }
        return s
    }
}
