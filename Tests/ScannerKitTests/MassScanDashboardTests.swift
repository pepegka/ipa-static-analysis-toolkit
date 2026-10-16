import XCTest
@testable import ScannerKit

final class MassScanDashboardTests: XCTestCase {

    private func makeReport(bundleID: String, name: String, score: Int,
                            findings: [Finding], trackers: [DetectedSDK],
                            secrets: [SecretHit], atsLoads: Bool) -> ScanReport {
        let meta = BundleMetadata(
            bundleID: bundleID, bundleName: name, displayName: name, shortVersion: "1.0",
            bundleVersion: "100", minimumOSVersion: "15.0", executableName: name,
            supportedPlatforms: ["iPhoneOS"], urlSchemes: [], queriedURLSchemes: [],
            backgroundModes: [], allowsArbitraryLoads: atsLoads,
            permissions: [PermissionEntry(key: "NSCameraUsageDescription", value: "camera",
                                          vectorID: "DCS-05", category: "Camera")],
            privacyManifestPath: nil, privacyTrackingDomains: [], privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: [], provisioning: nil,
            signedTeamID: nil, signedIdentifier: nil)
        let summaries = Vectors.all.map { v in
            VectorSummary(vectorID: v.id,
                          uniqueArtifactCount: findings.contains { $0.vectorID == v.id } ? 1 : 0,
                          maxSeverity: findings.first { $0.vectorID == v.id }?.severity ?? .info)
        }
        return ScanReport(
            sourceIPAPath: "/tmp/\(bundleID).ipa", metadata: meta, findings: findings,
            vectorSummaries: summaries,
            scanDurationSeconds: 1.5, notes: [],
            network: NetworkInventory(endpoints: [
                ClassifiedEndpoint(host: "graph.facebook.com", registrableDomain: "facebook.com",
                                   trackerID: "facebook", owner: "Meta", country: "US",
                                   category: "analytics", isTracker: true, occurrenceCount: 3,
                                   sources: ["bin"], samplePaths: [], samplePlistKeys: [])],
                detectedSDKs: trackers),
            hardening: [BinaryHardening(relativePath: name, name: name, architectures: ["arm64"],
                                        isEncrypted: true, hasPIE: true, hasStackCanary: true, hasARC: false)],
            secrets: secrets, ats: ATSConfig(allowsArbitraryLoads: atsLoads,
                allowsArbitraryLoadsInWebContent: false, allowsArbitraryLoadsForMedia: false,
                allowsLocalNetworking: false, exceptionDomains: []),
            fileManifest: [])
    }

    private func sampleMassScan() -> MassScanReport {
        let f1 = Finding(ruleID: "TRK-01.x", vectorID: "TRK-01", title: "Telemetry",
                         explanation: "e", severity: .high, evidences: [])
        let f2 = Finding(ruleID: "SECH-01.x", vectorID: "SECH-01", title: "ATS",
                         explanation: "e", severity: .medium, evidences: [])
        let f3 = Finding(ruleID: "privacy.gap.DiskSpace", vectorID: "TGAP-01",
                         title: "Undeclared required-reason API",
                         explanation: "e", severity: .medium, evidences: [])
        let sdk = DetectedSDK(trackerID: "facebook", name: "Facebook SDK", owner: "Meta",
                              country: "US", category: "analytics", isTracker: true,
                              evidenceCount: 2, endpoints: ["graph.facebook.com"], frameworks: ["FBSDKCoreKit"])
        let secret = SecretHit(type: "API key", redactedValue: "ab…yz", entropy: 4.2,
                               severity: .medium, source: "bin", section: nil)
        let rA = makeReport(bundleID: "com.a.app", name: "Alpha", score: 80,
                            findings: [f1, f2, f3], trackers: [sdk], secrets: [secret], atsLoads: true)
        let rB = makeReport(bundleID: "com.b.app", name: "Bravo", score: 30,
                            findings: [f2], trackers: [], secrets: [], atsLoads: false)

        let eA = MassScanAppEntry(appID: 1, bundleID: "com.a.app", appStoreName: "Alpha",
                                  artist: "A Inc", category: "Games", chartRank: 1, version: "1.0")
            .withScan(rA, sizeBytes: 5_000_000, reportPaths: ["json": "apps/1_Alpha/report.json",
                                                              "html": "apps/1_Alpha/report.html"])
        let eB = MassScanAppEntry(appID: 2, bundleID: "com.b.app", appStoreName: "Bravo",
                                  artist: "B Inc", category: "Utilities", chartRank: 2, version: "2.0")
            .withScan(rB, sizeBytes: 3_000_000, reportPaths: ["json": "apps/2_Bravo/report.json"])
        let eFail = MassScanAppEntry(appID: 3, bundleID: "com.c.app", appStoreName: "Charlie",
                                     artist: nil, category: "News", chartRank: 3, version: nil)
            .withError("download failed: paid app")

        let run = MassScanRun(createdAt: Date(timeIntervalSince1970: 1_700_000_000),
                              country: "us", feed: "top-free", genre: nil, requested: 3,
                              downloaded: 2, scanned: 2, failed: 1, totalScanSeconds: 3.0,
                              totalIPABytes: 8_000_000)
        return MassScanReport.make(run: run,
            scans: [(eA, rA), (eB, rB), (eFail, nil)])
    }

    func testStatsAggregation() {
        let report = sampleMassScan()
        XCTAssertEqual(report.stats.appsScanned, 2)
        XCTAssertEqual(report.apps.count, 3)
        XCTAssertEqual(report.apps.first?.appStoreName, "Alpha")
        XCTAssertEqual(report.apps.last?.ok, false)
        XCTAssertEqual(report.stats.appsWithATSArbitraryLoads, 1)
        XCTAssertEqual(report.stats.appsWithSecrets, 1)
        XCTAssertEqual(report.stats.totalUniqueTrackers, 1)
        XCTAssertEqual(report.stats.topTrackers.first { $0.label == "Facebook SDK" }?.count, 1)
        XCTAssertEqual(report.stats.topVectors.first { $0.label.hasPrefix("SECH-01") }?.count, 2)
        XCTAssertEqual(report.stats.topPermissions.first { $0.label == "NSCameraUsageDescription" }?.count, 2)
    }

    func testMASWEChartCountsOnlyFindingsAboveInfo() {
        func finding(_ sev: Severity) -> Finding {
            Finding(ruleID: "DCS-03.contacts_access", vectorID: "DCS-03", title: "Contacts", explanation: "e",
                    severity: sev, evidences: [], maswe: ["MASWE-0066"])
        }
        let r = makeReport(bundleID: "com.c.app", name: "C", score: 0, findings: [finding(.info), finding(.medium)],
                           trackers: [], secrets: [], atsLoads: false)
        let e = MassScanAppEntry(appID: 4, bundleID: "com.c.app", appStoreName: "C", artist: nil,
                                 category: "Social", chartRank: 1, version: "1.0").withScan(r, sizeBytes: 1, reportPaths: [:])
        let run = MassScanRun(createdAt: Date(timeIntervalSince1970: 0), country: "us", feed: "top-free", genre: nil,
                              requested: 1, downloaded: 1, scanned: 1, failed: 0, totalScanSeconds: 1, totalIPABytes: 1)
        let report = MassScanReport.make(run: run, scans: [(e, r)])
        XCTAssertEqual(report.stats.masweFrequency.first { $0.label == "MASWE-0066" }?.count, 1)
        XCTAssertEqual(report.rederivedFromDetail().stats.masweFrequency.first { $0.label == "MASWE-0066" }?.count, 1)
    }

    func testJSONRoundTrips() throws {
        let report = sampleMassScan()
        let data = try MassScanDashboardExporter.jsonData(report)
        let obj = try JSONSerialization.jsonObject(with: data)
        XCTAssertTrue(obj is [String: Any])
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        let round = try dec.decode(MassScanReport.self, from: data)
        XCTAssertEqual(round.apps.count, 3)
        XCTAssertTrue(round.apps.contains { $0.appStoreName == "Alpha" })
    }

    func testHTMLContainsSections() {
        let html = MassScanDashboardExporter.html(sampleMassScan())
        for needle in ["Mass-scan dashboard", "apps scanned",
                       "Findings by severity", "Top trackers", "All apps", "Failures",
                       "Alpha", "Charlie",
                       "echarts.min.js",
                       "id=msdata",
                       "c_radar", "c_graph",
                       "c_cluster", "c_maswe", "c_clusterreach", "h2 id=s-clusters",
                       "theme-toggle", "secnav", "h2 id=s-dist"] {
            XCTAssertTrue(html.contains(needle), "HTML missing: \(needle)")
        }
        guard let start = html.range(of: "<script id=msdata type=\"application/json\">"),
              let end = html.range(of: "</script>", range: start.upperBound..<html.endIndex) else {
            return XCTFail("no data island")
        }
        let json = String(html[start.upperBound..<end.lowerBound])
            .replacingOccurrences(of: "<\\/", with: "</")
        XCTAssertNoThrow(try JSONSerialization.jsonObject(with: Data(json.utf8)))
    }

    func testChartIDsHaveDrawCode() {
        let html = MassScanDashboardExporter.html(sampleMassScan())
        let js = MassScanDashboardExporter.chartJS
        var ids = Set<String>()
        var rest = Substring(html)
        while let r = rest.range(of: "<div id=c_") {
            rest = rest[r.upperBound...]
            let id = "c_" + String(rest.prefix { $0 != " " && $0 != ">" })
            ids.insert(id)
        }
        XCTAssertFalse(ids.isEmpty, "found no chart cards in the HTML")
        for id in ids.sorted() {
            XCTAssertTrue(js.contains("'\(id)'"), "charts.js has no draw code for \(id)")
        }
    }

    private func checkedInCorpora() -> [(name: String, report: MassScanReport)] {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        return ["results-ru34", "results-us150"].compactMap { name in
            let url = root.appendingPathComponent("\(name)/dashboard.json")
            guard let d = try? Data(contentsOf: url),
                  let r = try? dec.decode(MassScanReport.self, from: d) else { return nil }
            return (name, r)
        }
    }

    func testNoInsightCardIsSilentlySuppressed() throws {
        let corpora = checkedInCorpora()
        try XCTSkipIf(corpora.isEmpty, "no checked-in dashboard.json corpora available")
        for (name, report) in corpora {
            MassScanDashboardExporter.resetSuppressedInsightIDs()
            _ = MassScanDashboardExporter.insightCards(report)
            XCTAssertEqual(MassScanDashboardExporter.suppressedInsightIDs, [],
                           "\(name): insight cards emitted but rendered empty (degenerate value)")
        }
    }

    func testInsightCardsAreWellFormed() throws {
        let corpora = checkedInCorpora()
        try XCTSkipIf(corpora.isEmpty, "no checked-in dashboard.json corpora available")
        for (name, report) in corpora {
            let html = MassScanDashboardExporter.insightCards(report)

            XCTAssertFalse(html.contains("{") && html.contains("}"),
                           "\(name): an insight carries an unsubstituted {placeholder}")

            let pcts = html.matches(of: /(\d+)%/).compactMap { Int($0.1) }
            XCTAssertFalse(pcts.isEmpty, "\(name): no percentages found")
            for p in pcts {
                XCTAssertLessThanOrEqual(p, 100, "\(name): an insight renders \(p)%")
            }

            let labels = html.matches(of: /<div class=ilab>([^<]*)<\/div>/).map { String($0.1) }
            XCTAssertEqual(Set(labels).count, labels.count,
                           "\(name): two insight cards carry the same label")
        }
    }

    func testApplePolicyKPIOnlyWhenNonZero() {
        let withGap = sampleMassScan().rederivedFromDetail()
        let key = FindingCluster.applePolicy.id
        XCTAssertTrue(withGap.apps.contains { ($0.clusterCounts[key] ?? 0) > 0 },
                      "fixture should contain an Apple-policy finding")
        XCTAssertTrue(MassScanDashboardExporter.html(withGap).contains("apps with an Apple policy gap"))

        let noGap = MassScanReport(
            run: withGap.run,
            apps: withGap.apps.filter { ($0.clusterCounts[key] ?? 0) == 0 },
            stats: withGap.stats).rederivedFromDetail()
        XCTAssertFalse(MassScanDashboardExporter.html(noGap).contains("apps with an Apple policy gap"),
                       "the Apple-policy KPI should be omitted when the count is zero")
    }

    func testAppsOrderedBySeverityTally() {
        let apps = sampleMassScan().apps.filter(\.ok)
        XCTAssertGreaterThan(apps.count, 1)
        for (a, b) in zip(apps, apps.dropFirst()) {
            XCTAssertFalse(b.severityRank.lexicographicallyPrecedes(a.severityRank, by: >),
                           "\(b.appStoreName) outranks \(a.appStoreName) but sorts after it")
        }
    }

    func testAppTableCarriesCountedColumnsAndNoScores() {
        let html = MassScanDashboardExporter.html(sampleMassScan())
        for col in ["Findings", "Severity", "Trackers", "Flags"] {
            XCTAssertTrue(html.contains(">\(col)</th>"), "all-apps table missing the \(col) column")
        }
        for gone in Construct.allCases.map(\.rawValue) {
            XCTAssertFalse(html.contains(">\(gone)</th>"),
                           "all-apps table still carries the \(gone) construct score column")
        }
        XCTAssertTrue(html.contains("id=cluster-cols"))
        XCTAssertTrue(html.contains("sum above the total"))
        XCTAssertTrue(html.contains("class=sevbar"))
    }

    func testMarkdownNonEmpty() {
        let md = MassScanDashboardExporter.markdown(sampleMassScan())
        XCTAssertTrue(md.contains("# Mass-scan dashboard"))
        XCTAssertTrue(md.contains("Most findings by severity"))
        XCTAssertTrue(md.contains("Cluster frequency"))
        XCTAssertTrue(md.contains("Failures"))
    }

    func testInterpolatedTitlesCollapseToOneRuleRowWithACount() {
        let copyA = Messages.entry("SECH-01.insecure_exception_domains", ["count": "4"])
        let copyB = Messages.entry("SECH-01.insecure_exception_domains", ["count": "1"])
        XCTAssertNotEqual(copyA.title, copyB.title)

        let a = Finding(ruleID: "SECH-01.insecure_exception_domains", vectorID: "SECH-01",
                        title: copyA.title, explanation: "e", severity: .medium,
                        evidences: []).with(metrics: copyA.values)
        let b = Finding(ruleID: "SECH-01.insecure_exception_domains", vectorID: "SECH-01",
                        title: copyB.title, explanation: "e", severity: .medium,
                        evidences: []).with(metrics: copyB.values)

        let da = AppCompareDetail.comparable(a), db = AppCompareDetail.comparable(b)
        XCTAssertEqual(da.label, db.label, "one rule, one row label")
        XCTAssertFalse(da.label.contains("("), "the count belongs in the cell, not the label")
        XCTAssertEqual(da.count, 4)
        XCTAssertEqual(db.count, 1)
    }

    func testCountryStaysInTheLabelAndEndpointsGoToTheCell() {
        let copy = Messages.entry("TRK-04.egress",
                                  ["country": "US", "count": "23", "s": "s",
                                   "ownersNote": "", "adequacyNote": ""])
        let f = Finding(ruleID: "TRK-04.egress.us", vectorID: "TRK-04", title: copy.title,
                        explanation: "e", severity: .low, evidences: []).with(metrics: copy.values)
        let d = AppCompareDetail.comparable(f)
        XCTAssertEqual(d.label, "Endpoints owned by US-based organisations")
        XCTAssertEqual(d.count, 23)
    }

    func testSetValuedTitleCollapsesAndCountsItsMembers() {
        let copy = Messages.entry("PLAT-04.background_modes",
                                  ["modes": "audio, fetch, remote-notification, voip"])
        let f = Finding(ruleID: "PLAT-04.background_modes", vectorID: "PLAT-04", title: copy.title,
                        explanation: "e", severity: .low, evidences: []).with(metrics: copy.values)
        let d = AppCompareDetail.comparable(f)
        XCTAssertEqual(d.label, "Background modes declared")
        XCTAssertEqual(d.count, 4)
        XCTAssertEqual(d.detail, "audio, fetch, remote-notification, voip")
    }

    func testRuleWithoutACompareBlockKeepsItsTitle() {
        let f = Finding(ruleID: "DCS-01.idfa_idfv", vectorID: "DCS-01",
                        title: "IDFA / IDFV / ASIdentifierManager", explanation: "e",
                        severity: .low, evidences: [])
        let d = AppCompareDetail.comparable(f)
        XCTAssertEqual(d.label, "IDFA / IDFV / ASIdentifierManager")
        XCTAssertNil(d.count)
    }

    func testFindingWithoutMetricsFallsBackToItsRenderedTitle() {
        let f = Finding(ruleID: "TRK-04.egress.us", vectorID: "TRK-04",
                        title: "Data egress to US (23 endpoints)", explanation: "e",
                        severity: .low, evidences: [])
        let d = AppCompareDetail.comparable(f)
        XCTAssertEqual(d.label, "Data egress to US (23 endpoints)")
        XCTAssertNil(d.count)
    }

    func testCompareDetailDecodesAPayloadThatPredatesTheRuleFields() throws {
        let old = Data("""
        {"findings":[{"severity":"medium","vector":"SECH-01","title":"ATS (4)","group":"MASVS-NETWORK"}],
         "vectors":[],"trackers":[],"hardening":[],"permissions":[]}
        """.utf8)
        let d = try JSONDecoder().decode(AppCompareDetail.self, from: old)
        XCTAssertEqual(d.findings.first?.label, "ATS (4)")
        XCTAssertNil(d.findings.first?.count)
    }

    func testPipelineRewritesPreserveMetrics() {
        let f = Finding(ruleID: "r", vectorID: "DCS-01", title: "t", explanation: "e",
                        severity: .low, evidences: [])
            .with(metrics: ["count": "9"])
        XCTAssertEqual(f.withSeverity(.high).metrics["count"], "9")
        XCTAssertEqual(f.annotatedWithCrosswalk().metrics["count"], "9")
    }

    func testEveryCompareLabelResolvesForItsRule() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "findings", withExtension: "json",
                                                  subdirectory: "Rules/messages"))
        let file = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        let rules = try XCTUnwrap(file?["rules"] as? [String: Any])
        var annotated = 0
        for (ruleID, body) in rules {
            guard let body = body as? [String: Any], body["compare"] != nil else { continue }
            annotated += 1
            XCTAssertNotNil(Messages.compare(forRuleID: ruleID), "no compare for \(ruleID)")
        }
        XCTAssertGreaterThan(annotated, 15, "the interpolating rules should carry a compare block")
    }

}
