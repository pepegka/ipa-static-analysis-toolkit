import XCTest
@testable import ScannerKit

final class ClusterProfileTests: XCTestCase {

    private func finding(_ rule: String, _ vector: String, _ label: String, _ sev: String,
                         polarity: String? = nil, maswe: [String]? = nil) -> AppCompareDetail.DFinding {
        AppCompareDetail.DFinding(severity: sev, vector: vector, title: label, group: "", framework: nil,
                                  label: label, maswe: maswe, mastg: nil, cluster: nil, rule: rule,
                                  polarity: polarity)
    }

    private func app(_ id: String, _ findings: [AppCompareDetail.DFinding]) -> MassScanAppEntry {
        var e = MassScanAppEntry(appID: 1, bundleID: id, appStoreName: id, artist: nil, category: nil,
                                 chartRank: nil, version: "1", findingsCount: findings.count)
        e.details = AppCompareDetail(findings: findings, vectors: [], trackers: [], hardening: [], permissions: [])
        return e
    }

    private func report(_ apps: [MassScanAppEntry]) -> MassScanReport {
        let run = MassScanRun(createdAt: Date(timeIntervalSince1970: 0), country: "us", feed: "scan-only",
                              genre: nil, requested: apps.count, downloaded: apps.count, scanned: apps.count,
                              failed: 0, totalScanSeconds: 0, totalIPABytes: 0)
        return MassScanReport(run: run, apps: apps, stats: .empty)
    }

    private let gapDisk = "Privacy manifest gap: Disk space used but undeclared"
    private let gapDefaults = "Privacy manifest gap: User defaults used but undeclared"

    private func fixture() -> MassScanReport {
        report([
            app("a", [
                finding("SECH-01.allows_arbitrary_loads", "SECH-01", "ATS disabled", "high", maswe: ["MASWE-0026"]),
                finding("privacy.gap.NSPrivacyAccessedAPICategoryDiskSpace", "TGAP-01", gapDisk, "medium"),
                finding("privacy.gap.NSPrivacyAccessedAPICategoryUserDefaults", "TGAP-01", gapDefaults, "medium"),
                finding("SECH-07.app_attest", "SECH-07", "App Attest in use", "info", polarity: "defensive"),
            ]),
            app("b", [
                finding("SECH-01.allows_arbitrary_loads", "SECH-01", "ATS disabled", "high", maswe: ["MASWE-0026"]),
                finding("SECH-01.hardcoded_http_urls", "SECH-01", "Hard-coded http:// URLs", "info"),
                finding("privacy.gap.NSPrivacyAccessedAPICategoryDiskSpace", "TGAP-01", gapDisk, "medium"),
            ]),
            app("c", [
                finding("SECH-01.cfstream_tls_relaxation_referenced", "SECH-01", "TLS keys referenced", "info",
                        polarity: "neutral"),
            ]),
        ])
    }

    func testMintedRuleIDsResolveToTheirCheck() {
        XCTAssertEqual(Messages.familyKey("privacy.gap.NSPrivacyAccessedAPICategoryDiskSpace"), "privacy.gap")
        XCTAssertEqual(Messages.familyKey("perm.NSCameraUsageDescription"), "perm.*")
        XCTAssertEqual(Messages.familyKey("TRK-04.egress.us"), "TRK-04.egress")
        XCTAssertEqual(Messages.familyKey("SECH-05.generic_credential.generic_credential"), "SECH-05.*")
        XCTAssertEqual(Messages.familyKey("DCS-05.video_capture"), "DCS-05.video_capture")
        XCTAssertEqual(Messages.familyKey("SECH-01.allows_arbitrary_loads"), "SECH-01.allows_arbitrary_loads")
    }

    func testFamilyLabelSplitsSharedWordingFromMembers() {
        let gap = MassScanDashboardExporter.familyLabel([gapDisk, gapDefaults])
        XCTAssertEqual(gap.label, "Privacy manifest gap")
        XCTAssertEqual(gap.members, ["Disk space", "User defaults"])

        let perm = MassScanDashboardExporter.familyLabel([
            "Requests permission: HealthKit read", "Requests permission: HealthKit write"])
        XCTAssertEqual(perm.label, "Requests permission", "the cut falls on the colon, not on a shared word")
        XCTAssertEqual(perm.members, ["HealthKit read", "HealthKit write"])

        let secret = MassScanDashboardExporter.familyLabel([
            "Possible hardcoded secret (Generic Credential)", "Possible hardcoded secret (JSON Web Token)"])
        XCTAssertEqual(secret.label, "Possible hardcoded secret")
        XCTAssertEqual(secret.members, ["Generic Credential", "JSON Web Token"])

        let one = MassScanDashboardExporter.familyLabel(["Camera capture API"])
        XCTAssertEqual(one.label, "Camera capture API")
    }

    func testProfilesCountAppsNotFindingsAndFoldFamilies() throws {
        let profiles = MassScanDashboardExporter.clusterProfiles(fixture())
        let network = try XCTUnwrap(profiles.first { $0.id == "MASVS-NETWORK" })
        XCTAssertEqual(network.reach, 2)
        XCTAssertEqual(network.top.map(\.label), ["ATS disabled"])
        XCTAssertEqual(network.top.first?.apps, 2)
        XCTAssertEqual(network.weaknesses.map(\.id), ["MASWE-0026"])
        XCTAssertEqual(Set(network.inventory.map(\.label)), ["Hard-coded http:// URLs", "TLS keys referenced"])

        let policy = try XCTUnwrap(profiles.first { $0.id == "APPLE-POLICY" })
        let gap = try XCTUnwrap(policy.top.first)
        XCTAssertEqual(gap.label, "Privacy manifest gap")
        XCTAssertEqual(gap.apps, 2, "a family counts each app once, however many members it trips")
        XCTAssertEqual(gap.members.map(\.label), ["Disk space", "User defaults"])
        XCTAssertEqual(gap.members.map(\.apps), [2, 1])

        let mitigations = try XCTUnwrap(profiles.last)
        XCTAssertEqual(mitigations.id, MassScanDashboardExporter.mitigationsProfileID)
        XCTAssertEqual(mitigations.top.map(\.label), ["App Attest in use"])
        XCTAssertFalse(profiles.contains { $0.id != mitigations.id && $0.top.contains { $0.label == "App Attest in use" } })
    }

    func testProfilesRenderIntoThePageAndTheSummary() {
        let r = fixture()
        let html = MassScanDashboardExporter.html(r)
        XCTAssertTrue(html.contains("h2 id=s-profiles"))
        XCTAssertTrue(html.contains("id=\"p-MASVS-NETWORK\""))
        let md = MassScanDashboardExporter.markdown(r)
        XCTAssertTrue(md.contains("## Cluster profiles"))
        XCTAssertTrue(md.contains("| Privacy manifest gap (Disk space 2, User defaults 1) | 2 | medium |"))
    }

    func testReachMatchesClusterFrequencyOnCheckedInCorpora() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        let corpora = ["results-ru34", "results-us150"].compactMap { name -> MassScanReport? in
            guard let d = try? Data(contentsOf: root.appendingPathComponent("\(name)/dashboard.json")) else { return nil }
            return (try? dec.decode(MassScanReport.self, from: d))?.rederivedFromDetail()
        }
        try XCTSkipIf(corpora.isEmpty, "no checked-in dashboard.json corpora available")
        for report in corpora {
            let reach = Dictionary(uniqueKeysWithValues: report.stats.clusterFrequency.map {
                (String($0.label.split(separator: " ").first ?? ""), $0.count)
            })
            for p in MassScanDashboardExporter.clusterProfiles(report)
            where p.id != MassScanDashboardExporter.mitigationsProfileID {
                XCTAssertEqual(p.reach, reach[p.id] ?? 0, "\(report.run.country) \(p.id)")
            }
        }
    }
}
