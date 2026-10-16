import Foundation

extension MassScanDashboardExporter {

    static func insightCards(_ report: MassScanReport) -> String {
        let c = InsightCorpus(report)
        guard c.n > 0 else { return "" }
        let cards: [String: [String]] = [
            "tracking": trackingInsights(c),
            "ai": aiAndChildSafetyInsights(c),
            "surveillance": surveillanceInsights(c),
            "security": securityInsights(c),
            "sovereignty": sovereigntyInsights(c),
            "footprint": footprintInsights(c),
        ]
        let groups = insightFile.groups.map { ($0.heading, cards[$0.id] ?? []) }
        return groups.map { ($0.0, $0.1.filter { !$0.isEmpty }) }
            .filter { !$0.1.isEmpty }
            .map { "<h3 class=insight-group>\($0.0)</h3><div class=insights>\($0.1.joined())</div>" }
            .joined()
    }

    static func trackingInsights(_ c: InsightCorpus) -> [String] {
        var out: [String] = []
        let withTracker = c.scanned.filter { ($0.trackerCount ?? 0) > 0 }.count
        let totalInstances = c.scanned.reduce(0) { $0 + ($1.trackerCount ?? 0) }
        out.append(insight(c.pctOf(withTracker), "tracking.any_tracker",
                           ["instances": String(totalInstances),
                            "distinct": String(c.st.totalUniqueTrackers)]))
        if withTracker > 0 {
            let worst = c.scanned.max(by: { ($0.trackerCount ?? 0) < ($1.trackerCount ?? 0) })
                .map { "\($0.appStoreName) (\($0.trackerCount ?? 0))" } ?? "\u{2014}"
            out.append(insight(String(format: "%.1f", Double(totalInstances) / Double(withTracker)),
                               "tracking.per_app", ["worst": worst]))
        }
        if let top = c.st.topTrackers.first {
            out.append(insight(c.pctOf(top.count), "tracking.most_prevalent",
                               ["name": top.label, "detail": top.detail ?? ""]))
        }
        if !c.withDetail.isEmpty {
            out.append(insight(c.pctD(c.appsWithCat("advertising")), "tracking.advertising"))
            let analytics = c.appsWithCat("analytics")
            if analytics > 0 {
                out.append(insight(c.pctD(analytics), "tracking.analytics"))
            }
            let ownersPerApp = c.withDetail.map { Set(($0.details?.trackers ?? []).map(\.owner).filter { !$0.isEmpty }) }
            let allOwners = ownersPerApp.reduce(into: Set<String>()) { $0.formUnion($1) }
            out.append(insight(String(format: "%.1f", Double(ownersPerApp.reduce(0) { $0 + $1.count }) / Double(c.dn)),
                               "tracking.owners_per_app", ["owners": String(allOwners.count)]))
        }

        let counts = c.scanned.compactMap(\.trackerCount).filter { $0 > 0 }.sorted()
        if let top = c.scanned.max(by: { ($0.trackerCount ?? 0) < ($1.trackerCount ?? 0) }),
           let n = top.trackerCount, counts.count > 2 {
            let med = counts[counts.count / 2]
            if n >= max(10, med * 4) {
                out.append(insight("\(n)", "tracking.outlier",
                                   ["app": top.appStoreName, "median": String(med)],
                                   accent: "red"))
            }
        }

        return out
    }

    static func surveillanceInsights(_ c: InsightCorpus) -> [String] {
        var out: [String] = []
        if !c.withDetail.isEmpty {
            let sr = c.withDetail.filter { a in
                c.hasCat(a, "session-replay")
                    || (a.details?.findings ?? []).contains { $0.rule == "TRK-01.session_replay_sdk" }
            }.count
            if sr > 0 {
                out.append(insight(c.pctD(sr), "surv.session_replay"))
            }
            for (code, key) in [("DCS-01", "surv.fingerprinting"), ("DCS-02", "surv.location"), ("DCS-03", "surv.content_access")] {
                let n = c.appsWithWeakness(code)
                if n > 0 { out.append(insight(c.pctD(n), key)) }
            }
            let exfil = c.appsWithWeakness("PLAT-04")
            if exfil > 0 {
                out.append(insight(c.pctD(exfil), "surv.background_exfil"))
            }
            let bio = c.appsWithWeakness("DCS-04", excluding: ["DCS-04.face_id_biometrics"])
            if bio > 0 {
                out.append(insight(c.pctD(bio), "surv.biometrics"))
            }
            let brokers = c.appsWithWeakness("TRK-02", minSeverity: .info)
            if brokers > 0 {
                out.append(insight(c.pctD(brokers), "surv.data_broker"))
            }
        }
        let sensitiveKeys = PermissionCatalog.usageDescriptionKeys.filter { $0.value.sensitive == true }.keys
        if let sens = c.st.topPermissions.filter({ sensitiveKeys.contains($0.label) }).max(by: { $0.count < $1.count }) {
            let nice = sens.label.replacingOccurrences(of: "NS", with: "")
                .replacingOccurrences(of: "UsageDescription", with: "")
                .replacingOccurrences(of: "AlwaysAndWhenInUse", with: "").replacingOccurrences(of: "WhenInUse", with: "")
            out.append(insight(c.pctOf(sens.count), "surv.top_permission",
                               ["what": nice.lowercased(), "key": sens.label,
                                "apps": String(sens.count)]))
        }
        let att = c.count(c.st.topPermissions, "NSUserTrackingUsageDescription")
        if att > 0 {
            out.append(insight(c.pctOf(att), "surv.att_prompt"))
        }
        if !c.withDetail.isEmpty {
            out.append(insight(c.pctD(c.appsWithPerm(["NSLocation"])), "surv.location_permission"))
            out.append(insight(c.pctD(c.appsWithPerm(["NSMicrophone"])), "surv.microphone_permission"))
            out.append(insight(c.pctD(c.appsWithPerm(["NSContacts"])), "surv.contacts_permission"))
            let bio = c.appsWithPerm(["NSFaceID"])
            if bio > 0 {
                out.append(insight(c.pctD(bio), "surv.face_id"))
            }
        }

        return out
    }

    static func securityInsights(_ c: InsightCorpus) -> [String] {
        var out: [String] = []
        out.append(insight(c.pctOf(c.st.appsWithATSArbitraryLoads), "security.ats_arbitrary",
                           ["oneIn": c.oneIn(c.st.appsWithATSArbitraryLoads)],
                           accent: c.st.appsWithATSArbitraryLoads * 2 >= c.n ? "red" : "yellow"))
        out.append(insight(c.pctOf(c.st.appsWithSecrets), "security.secrets"))
        let highCrit = c.scanned.filter { (($0.criticalCount ?? 0) + ($0.highCount ?? 0)) > 0 }.count
        if highCrit > 0 {
            out.append(insight(c.quantifier(highCrit), "security.high_or_critical",
                               ["critical": String(c.count(c.st.severityHistogram, "critical")),
                                "high": String(c.count(c.st.severityHistogram, "high"))]))
        }
        let bins = c.binaries
        if !bins.isEmpty {
            let arcKnown = bins.filter { $0.arc != nil }.count
            let noARC = bins.filter { $0.arc == false }.count
            if noARC > 0, arcKnown > 0 {
                out.append(insight(pctOf(noARC, arcKnown), "security.no_arc",
                                   ["binaries": String(arcKnown)],
                                   accent: noARC * 4 >= arcKnown ? "orange" : "yellow"))
            }
            let canaryKnown = bins.filter { $0.canary != nil }.count
            let noCanary = bins.filter { $0.canary == false }.count
            if noCanary > 0, canaryKnown > 0 {
                out.append(insight(pctOf(noCanary, canaryKnown), "security.no_canary",
                                   ["binaries": String(canaryKnown)],
                                   accent: noCanary * 4 >= canaryKnown ? "orange" : "yellow"))
            }
            let enc = bins.filter(\.encrypted).count
            if enc > 0 {
                let blind = c.scanned.filter { ($0.trackerCount ?? 0) == 0 }.count
                let note = blind == 0 ? ""
                    : " \(blind) app\(blind == 1 ? " shows" : "s show") no tracker at all; on encrypted code that is an absence of evidence, not evidence of absence."
                out.append(insight(pctOf(enc, bins.count), "security.encryption_coverage",
                                   ["binaries": String(bins.count), "blindNote": note],
                                   accent: "teal"))
            }
        }
        if !c.withDetail.isEmpty {
            let crypto = c.appsWithWeakness("SECH-03")
            if crypto > 0 {
                out.append(insight(c.pctD(crypto), "security.weak_crypto"))
            }
            let storage = c.appsWithWeakness("SECH-02")
            if storage > 0 {
                out.append(insight(c.pctD(storage), "security.insecure_storage"))
            }
            let webview = c.appsWithWeakness("PLAT-01")
            if webview > 0 {
                out.append(insight(c.pctD(webview), "security.webview_bridge"))
            }
        }

        return out
    }

    static func sovereigntyInsights(_ c: InsightCorpus) -> [String] {
        var out: [String] = []
        if let country = c.st.topEndpointCountries.first {
            out.append(insight(c.pctOf(country.count), "sovereignty.top_endpoint_country",
                               ["country": Regions.name(country.label)]))
        }
        if !c.withDetail.isEmpty {
            var countryApps: [String: Int] = [:]
            for a in c.withDetail {
                for c in Set((a.details?.trackers ?? []).map(\.country).filter { !$0.isEmpty }) { countryApps[c, default: 0] += 1 }
            }
            if let topCountry = countryApps.max(by: { $0.value < $1.value }) {
                out.append(insight(c.pctD(topCountry.value), "sovereignty.top_tracker_country",
                                   ["country": Regions.name(topCountry.key)]))
            }
            let home = c.home
            let foreign = c.withDetail.filter { (($0.details?.trackers ?? []).contains { !$0.country.isEmpty && $0.country != home }) }.count
            if foreign > 0 {
                out.append(insight(c.pctD(foreign), "sovereignty.foreign_owner", ["home": Regions.name(home)]))
            }
        }

        return out
    }

    static func footprintInsights(_ c: InsightCorpus) -> [String] {
        var out: [String] = []
        let policyKey = FindingCluster.applePolicy.id
        let withGap = c.scanned.filter { ($0.clusterCounts[policyKey] ?? 0) > 0 }.count
        let clean = c.n - withGap
        out.append(insight(c.pctOf(withGap), "footprint.apple_policy_gap",
                           ["cleanNote": clean == 0 ? "No app in this batch is free of them."
                                : "\(clean) of the apps scanned raise none."],
                           accent: withGap == 0 ? "green" : "orange"))
        func worstFirst(_ a: MassScanAppEntry) -> Int { (a.criticalCount ?? 0) * 1000 + (a.highCount ?? 0) }
        if let worst = c.scanned.max(by: { worstFirst($0) < worstFirst($1) }) {
            let n = (worst.criticalCount ?? 0) + (worst.highCount ?? 0)
            let floor = c.scanned.map(worstFirst).min() ?? 0
            let atFloor = c.scanned.filter { worstFirst($0) == floor }
            let cleanest = atFloor.count == 1
                ? "Fewest: \(atFloor[0].appStoreName) (\((atFloor[0].criticalCount ?? 0) + (atFloor[0].highCount ?? 0)))."
                : (floor == 0 ? "\(atFloor.count) apps have none." : "\(atFloor.count) apps tie for fewest.")
            out.append(insight("\(n)", "footprint.most_findings",
                               ["app": worst.appStoreName, "cleanest": cleanest]))
        }
        if let top = c.st.clusterFrequency.first(where: { !$0.label.hasPrefix(FindingCluster.indicators.id) }) {
            let parts = top.label.components(separatedBy: " \u{00B7} ")
            let name = parts.count == 2 ? "\(parts[1]) (\(parts[0]))" : top.label
            out.append(insight(c.pctOf(top.count), "footprint.top_cluster", ["cluster": name]))
        }
        if let top = c.st.masweFrequency.first {
            out.append(insight("\(top.count)", "footprint.top_maswe",
                               ["weakness": top.detail ?? top.label, "id": top.label,
                                "apps": String(c.n)]))
        }
        let medFindings = median(c.scanned.compactMap(\.findingsCount))
        out.append(insight("\(c.st.totalFindings)", "footprint.total_findings",
                           ["apps": String(c.n), "median": String(medFindings)]))
        if let worst = busiestCategory(c.scanned) {
            out.append(insight(String(format: "%.0f", worst.avg), "footprint.busiest_category",
                               ["name": worst.name, "count": String(worst.count),
                                "median": String(medFindings)]))
        }
        let sized = c.scanned.filter { $0.sizeBytes != nil && $0.findingsCount != nil }
        if let r = pearson(sized.map { Double($0.sizeBytes ?? 0) },
                           sized.map { Double($0.findingsCount ?? 0) }), r >= 0.25 {
            out.append(insight(String(format: "r = %.2f", r), "footprint.size_confound",
                               ["apps": String(sized.count)], accent: "yellow"))
        }
        let sizes = c.scanned.compactMap(\.sizeBytes)
        if !sizes.isEmpty {
            let avgSize = sizes.reduce(UInt64(0), +) / UInt64(sizes.count)
            out.append(insight(HTML.byteSize(avgSize), "footprint.average_size",
                               ["largest": HTML.byteSize(sizes.max() ?? 0),
                                "total": HTML.byteSize(c.totalIPABytes)]))
            if let big = c.scanned.max(by: { ($0.sizeBytes ?? 0) < ($1.sizeBytes ?? 0) }) {
                out.append(insight(HTML.byteSize(big.sizeBytes ?? 0), "footprint.largest_app",
                                   ["app": big.appStoreName]))
            }
        }
        let heavilyTracked = c.scanned.filter { ($0.trackerCount ?? 0) >= 10 }.count
        if heavilyTracked > 0 {
            let med = median(c.scanned.compactMap(\.trackerCount))
            out.append(insight(c.pctOf(heavilyTracked), "footprint.heavily_tracked",
                               ["median": "\(med) tracker\(med == 1 ? "" : "s")",
                                "apps": "\(heavilyTracked) app\(heavilyTracked == 1 ? "" : "s")"]))
        }
        if let topOwner = c.st.topEndpointOwners.first {
            out.append(insight(c.pctOf(topOwner.count), "footprint.top_endpoint_owner",
                               ["owner": topOwner.label]))
        }
        if !c.withDetail.isEmpty {
            let avgPerms = Double(c.withDetail.reduce(0) { $0 + ($1.details?.permissions.count ?? 0) }) / Double(c.dn)
            out.append(insight(String(format: "%.1f", avgPerms), "footprint.avg_permissions"))
        }

        return out
    }

    static func aiAndChildSafetyInsights(_ c: InsightCorpus) -> [String] {
        var out: [String] = []
        if !c.withDetail.isEmpty {
            let llm = c.appsWithWeakness("TRK-05", minSeverity: .info)
            if llm > 0 {
                out.append(insight(c.pctD(llm), "ai.cloud_llm",
                                   accent: llm * 3 >= c.dn ? "orange" : "purple"))
            }
            let proximity = c.appsWithWeakness("DCS-07", minSeverity: .info)
            if proximity > 0 {
                out.append(insight(c.pctD(proximity), "ai.proximity"))
            }
            let kidsApps = c.withDetail.filter { ($0.category ?? "").lowercased().contains("kid") }
            if !kidsApps.isEmpty {
                let kidsWithTrackers = kidsApps.filter { c.hasCat($0, "advertising") || c.hasCat($0, "attribution") }.count
                out.append(insight("\(Int((Double(kidsWithTrackers) / Double(kidsApps.count) * 100).rounded()))%",
                                   "ai.kids_trackers", ["kidsApps": String(kidsApps.count)]))
            }
        }
        return out
    }

    static func pearson(_ xs: [Double], _ ys: [Double]) -> Double? {
        guard xs.count == ys.count, xs.count > 2 else { return nil }
        let n = Double(xs.count)
        let mx = xs.reduce(0, +) / n, my = ys.reduce(0, +) / n
        var num = 0.0, dx = 0.0, dy = 0.0
        for (x, y) in zip(xs, ys) {
            num += (x - mx) * (y - my); dx += (x - mx) * (x - mx); dy += (y - my) * (y - my)
        }
        let den = (dx * dy).squareRoot()
        return den > 0 ? num / den : nil
    }

    private static func median(_ xs: [Int]) -> Int {
        guard !xs.isEmpty else { return 0 }
        let s = xs.sorted()
        return s.count % 2 == 1 ? s[s.count / 2] : (s[s.count / 2 - 1] + s[s.count / 2]) / 2
    }

    private static func busiestCategory(_ apps: [MassScanAppEntry]) -> (name: String, avg: Double, count: Int)? {
        var sums: [String: (sum: Int, n: Int)] = [:]
        for a in apps {
            guard let c = a.category, let s = a.findingsCount else { continue }
            let cur = sums[c] ?? (0, 0)
            sums[c] = (cur.sum + s, cur.n + 1)
        }
        return sums.filter { $0.value.n >= 5 }
            .map { (name: $0.key, avg: Double($0.value.sum) / Double($0.value.n), count: $0.value.n) }
            .max { $0.avg < $1.avg }
    }
}
