import XCTest
@testable import ScannerKit

final class DashboardInsightTests: XCTestCase {

    private func f(_ rule: String, _ vector: String, _ sev: Severity, _ p: Polarity = .offensive) -> Finding {
        Finding(ruleID: rule, vectorID: vector, title: rule, explanation: "e", severity: sev,
                evidences: []).withPolarity(p)
    }

    private func app(_ id: String, _ findings: [Finding], trackers: [DetectedSDK] = []) -> (MassScanAppEntry, ScanReport) {
        let meta = NetworkAttributionTests.metadata()
        let r = ScanReport(sourceIPAPath: "/tmp/\(id).ipa", metadata: meta, findings: findings,
                           vectorSummaries: [], scanDurationSeconds: 1, notes: [],
                           network: NetworkInventory(endpoints: [], detectedSDKs: trackers),
                           hardening: [], secrets: [],
                           ats: ATSConfig(allowsArbitraryLoads: false, allowsArbitraryLoadsInWebContent: false,
                                          allowsArbitraryLoadsForMedia: false, allowsLocalNetworking: false,
                                          exceptionDomains: []),
                           fileManifest: [])
        let e = MassScanAppEntry(appID: 0, bundleID: id, appStoreName: id, artist: nil, category: nil,
                                 chartRank: nil, version: "1").withScan(r, sizeBytes: 1, reportPaths: [:])
        return (e, r)
    }

    private func corpus(country: String = "ru") -> MassScanReport {
        let ru = DetectedSDK(trackerID: "yandex.appmetrica", name: "AppMetrica", owner: "Yandex", country: "RU",
                             category: "analytics", isTracker: true, evidenceCount: 1, endpoints: ["x.yandex.net"], frameworks: [])
        let us = DetectedSDK(trackerID: "adjust", name: "Adjust", owner: "Adjust", country: "DE",
                             category: "attribution", isTracker: true, evidenceCount: 1, endpoints: ["app.adjust.com"], frameworks: [])
        let apps = [
            app("a", [f("TRK-05.on_device_ml", "TRK-05", .info, .neutral),
                      f("SECH-02.backup_exclusion_marker", "SECH-02", .info, .defensive),
                      f("DCS-04.face_id_biometrics", "DCS-04", .low)], trackers: [ru]),
            app("b", [f("TRK-05.on_device_ml", "TRK-05", .info, .neutral),
                      f("DCS-04.face_id_biometrics", "DCS-04", .low)], trackers: [ru, us]),
            app("c", [f("TRK-05.llm_sdk_symbols", "TRK-05", .medium),
                      f("SECH-02.file_protection_none", "SECH-02", .medium),
                      f("DCS-04.coremotion", "DCS-04", .low)], trackers: [ru]),
        ]
        let run = MassScanRun(createdAt: Date(timeIntervalSince1970: 0), country: country, feed: "scan-only",
                              genre: nil, requested: 3, downloaded: 0, scanned: 3, failed: 0,
                              totalScanSeconds: 3, totalIPABytes: 3)
        return MassScanReport.make(run: run, scans: apps.map { ($0.0, $0.1) })
    }

    private func card(_ html: String, containing label: String) -> String? {
        guard let r = html.range(of: label) else { return nil }
        let start = html[..<r.lowerBound].range(of: "<div class=ival>", options: .backwards)!.upperBound
        return String(html[start...].prefix { $0 != "<" })
    }

    func testCloudLLMCardDoesNotCountOnDeviceML() {
        let html = MassScanDashboardExporter.insightCards(corpus())
        XCTAssertEqual(card(html, containing: "cloud LLM"), "33%", "only app c ships a cloud LLM client")
    }

    func testMitigationsAndInventoryAreNotBehaviour() {
        let html = MassScanDashboardExporter.insightCards(corpus())
        XCTAssertEqual(card(html, containing: "weak data-at-rest setting"), "33%",
                       "backup exclusion is a mitigation; only c has file protection off")
        XCTAssertEqual(card(html, containing: "behavioural-biometric inputs"), "33%",
                       "Face ID is not behavioural biometrics")
    }

    func testForeignIsRelativeToTheStorefront() {
        let ru = MassScanDashboardExporter.insightCards(corpus(country: "ru"))
        XCTAssertTrue(ru.contains("outside Russia") || ru.contains("outside RU"), "home is the storefront")
        XCTAssertEqual(card(ru, containing: "whose owner is based outside"), "33%", "only b embeds a non-RU tracker")
    }

    func testHTMLHasNoToolMetadataKPIAndHasTheMethodFooter() {
        let html = MassScanDashboardExporter.html(corpus())
        XCTAssertFalse(html.contains("MASWE / MASTG bound"))
        XCTAssertTrue(html.contains("id=s-method"))
        XCTAssertFalse(html.contains("c_masvspie"))
        XCTAssertTrue(html.contains("storefront <code>RU</code>"))
    }

    func testMitigationsStayOutOfClusterCounts() {
        let a = corpus().apps.first { $0.bundleID == "a" }!
        XCTAssertNil(a.clusterCounts["MASVS-STORAGE"], "a's only storage finding is a mitigation")
    }
}
