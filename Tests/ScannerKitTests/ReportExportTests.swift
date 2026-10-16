import XCTest
@testable import ScannerKit

final class ReportExportTests: XCTestCase {

    private func meta(_ bundleID: String = "com.test.app", version: String = "1.0") -> BundleMetadata {
        BundleMetadata(bundleID: bundleID, bundleName: "Test", displayName: "Test", shortVersion: version,
            bundleVersion: "1", minimumOSVersion: "16.0", executableName: "Test", supportedPlatforms: ["iPhoneOS"],
            urlSchemes: [], queriedURLSchemes: [], backgroundModes: [], allowsArbitraryLoads: false,
            permissions: [], privacyManifestPath: nil, privacyTrackingDomains: [], privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: ["Alamofire"], provisioning: nil, signedTeamID: nil, signedIdentifier: nil)
    }
    private func finding(_ ruleID: String, _ vectorID: String, _ sev: Severity) -> Finding {
        Finding(ruleID: ruleID, vectorID: vectorID, title: ruleID, explanation: "x",
                severity: sev, evidences: []).annotatedWithCrosswalk()
    }
    private func report(bundleID: String = "com.test.app", version: String = "1.0",
                        findings: [Finding], sdks: [DetectedSDK] = []) -> ScanReport {
        ScanReport(sourceIPAPath: "/tmp/x.ipa", metadata: meta(bundleID, version: version),
                   findings: findings, vectorSummaries: [],
                   scanDurationSeconds: 1, notes: [],
                   network: NetworkInventory(endpoints: [], detectedSDKs: sdks))
    }
    private func sdk(_ name: String, owner: String, category: String) -> DetectedSDK {
        DetectedSDK(trackerID: name, name: name, owner: owner, country: "US", category: category,
                    isTracker: true, evidenceCount: 1, endpoints: ["\(name).example.com"], frameworks: ["\(name).framework"])
    }

    private func manifest(_ n: Int, flagged: Int = 0) -> [FileManifestEntry] {
        (0..<n).map { i in
            FileManifestEntry(relativePath: "Payload/Test.app/f\(i).bin", name: "f\(i).bin",
                              sizeBytes: UInt64(i), kind: "data",
                              sha256: String(repeating: "a", count: 64),
                              isSuspicious: i < flagged,
                              suspicionReason: i < flagged ? "unsigned" : nil)
        }
    }

    func testHTMLRendersEveryTaxonomyOnAFinding() {
        var f = finding("SECH-01.x", "SECH-01", .high)
        f.cvss = "CVSS:4.0/AV:N/AC:L"
        f.cwe = ["CWE-319"]
        f.linddun = ["Detecting"]
        f.solove = ["Surveillance"]
        f.gdpr = ["Art. 5(1)(f)"]
        let html = ReportExporter.html(report(findings: [f]))
        for needle in ["CVSS:4.0/AV:N/AC:L", "CWE-319", "Detecting", "Surveillance", "Art. 5(1)(f)"] {
            XCTAssertTrue(html.contains(needle), "HTML is missing \(needle)")
        }
        XCTAssertTrue(html.contains("<dt>MASTG</dt>") || f.mastg.isEmpty)
        XCTAssertTrue(html.contains("<dt>MASWE</dt>") || f.maswe.isEmpty)
    }

    func testAnnotatedFindingRendersItsRationaleAndItsOwnVector() throws {
        let f = Finding(ruleID: "SECH-01.allows_arbitrary_loads", vectorID: "SECH-01", title: "t",
                        explanation: "e", severity: .medium, evidences: [])
            .annotatedWithCrosswalk()
        let anchor = try XCTUnwrap(SeverityDerivation.entry(ruleID: "SECH-01.allows_arbitrary_loads", vectorID: "SECH-01"))
        let why = try XCTUnwrap(anchor.why)
        let cvss = try XCTUnwrap(anchor.cvss)

        let md = ReportExporter.markdown(report(findings: [f]))
        XCTAssertTrue(md.contains("**Why this severity:** \(why)"), "Markdown dropped the rationale")
        XCTAssertTrue(md.contains(cvss), "Markdown is citing something other than the rule's anchor")

        let html = ReportExporter.html(report(findings: [f]))
        XCTAssertTrue(html.contains("Why this severity"), "HTML dropped the rationale")
        XCTAssertTrue(html.contains(cvss), "HTML is citing something other than the rule's anchor")

        let vectorCVSS = try XCTUnwrap(FrameworkCrosswalk.for(vectorID: "SECH-01").cvss)
        XCTAssertNotEqual(cvss, vectorCVSS, "the fixture stopped exercising the disagreement")
        XCTAssertFalse(md.contains(vectorCVSS), "the vector's CVSS is back in the report")
    }

    func testBothReportsDescribeTheSameAppDetailSections() {
        let r = report(findings: [finding("SECH-01.x", "SECH-01", .high)])
        let sections = AppDetailSection.all(r.metadata)
        XCTAssertFalse(sections.isEmpty, "fixture has no app detail to render")

        var toc = ReportExporter.Outline()
        let md = ReportExporter.appDetailsMarkdown(r)
        let html = ReportExporter.appDetailsHTML(r, &toc)

        for section in sections {
            let needle: String
            switch section {
            case .summary(let rows):        needle = rows.first?.value ?? ""
            case .permissions:              needle = "Permissions ("
            case .identifiers(let t, _):    needle = t
            case .entitlements:             needle = "Entitlements ("
            case .privacyManifest:          needle = "Privacy manifest"
            case .binaries:                 needle = "Embedded binaries ("
            case .frameworks:               needle = "Embedded frameworks ("
            }
            guard !needle.isEmpty else { continue }
            XCTAssertTrue(md.contains(needle), "Markdown is missing \(needle)")
            XCTAssertTrue(html.contains(needle), "HTML is missing \(needle)")
        }

        let exe = try? XCTUnwrap(r.metadata.executableName)
        XCTAssertTrue(md.contains(exe ?? "\u{0}"), "Markdown dropped the executable name again")
        XCTAssertTrue(html.contains(exe ?? "\u{0}"), "HTML dropped the executable name")
    }

    func testMarkdownCarriesTheSameTaxonomies() {
        var f = finding("SECH-01.x", "SECH-01", .high)
        f.cvss = "CVSS:4.0/AV:N/AC:L"
        f.gdpr = ["Art. 5(1)(f)"]
        let md = ReportExporter.markdown(report(findings: [f]))
        XCTAssertTrue(md.contains("**CVSS:**"))
        XCTAssertTrue(md.contains("**GDPR:** Art. 5(1)(f)"))
    }

    func testReferencesBecomeLinksOnlyWhenTheyAreURLs() {
        let f = Finding(ruleID: "SECH-01.x", vectorID: "SECH-01", title: "t", explanation: "x",
                        severity: .high, evidences: [],
                        references: ["https://example.com/a", "See the MASTG chapter on transport"])
        let html = ReportExporter.html(report(findings: [f]))
        XCTAssertTrue(html.contains("<a href=\"https://example.com/a\" rel=noreferrer>"))
        XCTAssertFalse(html.contains("<a href=\"See the MASTG"))
        XCTAssertTrue(html.contains("See the MASTG chapter on transport"))
    }

    func testFindingsAreSortedWorstFirst() {
        let r = report(findings: [finding("a", "SECH-01", .low),
                                  finding("b", "SECH-01", .critical),
                                  finding("c", "SECH-01", .medium)])
        let html = ReportExporter.html(r)
        let order = ["CRITICAL", "MEDIUM", "LOW"].map { html.range(of: "sevtag sev-\($0.lowercased())\">\($0)")! }
        XCTAssertTrue(order[0].lowerBound < order[1].lowerBound)
        XCTAssertTrue(order[1].lowerBound < order[2].lowerBound)
    }

    func testBackLinkOnlyAppearsWhenAPathIsGiven() {
        let r = report(findings: [])
        XCTAssertFalse(ReportExporter.html(r).contains("All apps"))
        XCTAssertTrue(ReportExporter.html(r, dashboardPath: "../../dashboard.html")
            .contains("href=\"../../dashboard.html\""))
    }

    func testManifestTravelsAsJSONNotTableRows() throws {
        let r = ScanReport(sourceIPAPath: "/tmp/x.ipa", metadata: meta(), findings: [],
                           vectorSummaries: [],
                           scanDurationSeconds: 1, notes: [], fileManifest: manifest(40))
        let html = ReportExporter.html(r)
        XCTAssertTrue(html.contains("id=manifest-data"))
        XCTAssertFalse(html.contains("Payload/Test.app/f39.bin</code></td>"),
                       "manifest rows should not be inlined as table markup")
        let json = try XCTUnwrap(html.components(separatedBy: "id=manifest-data>").last?
            .components(separatedBy: "</script>").first)
        let obj = try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
        XCTAssertEqual(obj["total"] as? Int, 40)
        XCTAssertEqual((obj["rows"] as! [[Any]]).count, 40)
    }

    func testOversizeManifestKeepsFlaggedFilesAndSaysSo() throws {
        let n = ReportExporter.manifestEmbedLimit + 500
        let r = ScanReport(sourceIPAPath: "/tmp/x.ipa", metadata: meta(), findings: [],
                           vectorSummaries: [],
                           scanDurationSeconds: 1, notes: [], fileManifest: manifest(n, flagged: 3))
        let (rows, total) = ReportExporter.manifestRows(manifest(n, flagged: 3))
        XCTAssertEqual(total, n)
        XCTAssertEqual(rows.count, ReportExporter.manifestEmbedLimit)
        XCTAssertEqual(rows.filter(\.isSuspicious).count, 3, "flagged files must survive the cap")
        let html = ReportExporter.html(r)
        XCTAssertTrue(html.contains("full list of \(n) is in"))
        XCTAssertTrue(html.contains("href=\"report.json\""))
    }

    func testManifestJSONCannotCloseTheScriptElement() throws {
        let hostile = FileManifestEntry(relativePath: "a</script><script>alert(1)</script>",
                                        name: "a", sizeBytes: 1, kind: "data", sha256: nil,
                                        isSuspicious: false, suspicionReason: nil)
        let r = ScanReport(sourceIPAPath: "/tmp/x.ipa", metadata: meta(), findings: [],
                           vectorSummaries: [],
                           scanDurationSeconds: 1, notes: [], fileManifest: [hostile])
        let html = ReportExporter.html(r)
        let block = try XCTUnwrap(html.components(separatedBy: "id=manifest-data>").last?
            .components(separatedBy: "</script>").first)
        XCTAssertFalse(block.contains("<"), "a file name must not carry a raw < into the JSON block")
        XCTAssertTrue(block.contains("\\u003c"))
        let obj = try JSONSerialization.jsonObject(with: Data(block.utf8)) as! [String: Any]
        XCTAssertEqual((obj["rows"] as! [[Any]])[0][0] as? String,
                       "a</script><script>alert(1)</script>")
    }

    func testSarifEmitsTaxonomiesAndRelationships() throws {
        let r = report(findings: [finding("SECH-01.allows_arbitrary_loads", "SECH-01", .high)])
        let data = try ReportExporter.sarifData(r)
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let run = (obj["runs"] as! [[String: Any]])[0]
        let taxonomies = run["taxonomies"] as! [[String: Any]]
        let names = Set(taxonomies.map { $0["name"] as! String })
        XCTAssertTrue(names.isSuperset(of: ["MASWE", "MASTG", "CWE"]), "missing taxonomies: \(names)")
        let maswe = taxonomies.first { $0["name"] as! String == "MASWE" }!
        XCTAssertFalse((maswe["taxa"] as! [[String: Any]]).isEmpty)
        let rules = ((run["tool"] as! [String: Any])["driver"] as! [String: Any])["rules"] as! [[String: Any]]
        let sech1 = rules.first { $0["id"] as! String == "SECH-01" }!
        let rels = sech1["relationships"] as! [[String: Any]]
        XCTAssertTrue(rels.contains { (($0["target"] as! [String: Any])["id"] as! String) == "MASWE-0026" })
    }

    func testSarifResultCarriesCVSSv4() throws {
        let r = report(findings: [finding("SECH-01.allows_arbitrary_loads", "SECH-01", .high)])
        let obj = try JSONSerialization.jsonObject(with: try ReportExporter.sarifData(r)) as! [String: Any]
        let results = ((obj["runs"] as! [[String: Any]])[0])["results"] as! [[String: Any]]
        let props = results[0]["properties"] as! [String: Any]
        XCTAssertEqual((props["cvssV4"] as? String)?.hasPrefix("CVSS:4.0/"), true)
    }

    func testCycloneDXSBOMComponents() throws {
        let r = report(findings: [], sdks: [sdk("AppsFlyer", owner: "AppsFlyer", category: "attribution"),
                                            sdk("OpenAI", owner: "OpenAI", category: "ai")])
        let data = try CycloneDXExporter.data(r)
        let obj = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(obj["bomFormat"] as? String, "CycloneDX")
        XCTAssertEqual(obj["specVersion"] as? String, "1.5")
        let comps = obj["components"] as! [[String: Any]]
        let names = Set(comps.map { $0["name"] as! String })
        XCTAssertTrue(names.contains("AppsFlyer"))
        XCTAssertTrue(names.contains("OpenAI"))
        XCTAssertTrue(names.contains("Alamofire"), "embedded framework not represented")
        let openai = comps.first { $0["name"] as! String == "OpenAI" }!
        XCTAssertEqual(openai["publisher"] as? String, "OpenAI")
    }

    func testSBOMSerialIsDeterministic() throws {
        let a = try CycloneDXExporter.data(report(findings: []))
        let b = try CycloneDXExporter.data(report(findings: []))
        func serial(_ d: Data) throws -> String {
            ((try JSONSerialization.jsonObject(with: d)) as! [String: Any])["serialNumber"] as! String
        }
        XCTAssertEqual(try serial(a), try serial(b))
    }

    func testReportDiffDetectsChanges() {
        let old = report(version: "1.0",
                         findings: [finding("SECH-01.a", "SECH-01", .high),
                                    finding("DCS-02.b", "DCS-02", .medium)],
                         sdks: [sdk("AppsFlyer", owner: "AppsFlyer", category: "attribution")])
        let new = report(version: "1.1",
                         findings: [finding("SECH-01.a", "SECH-01", .high),
                                    finding("TRK-05.llm_api_endpoints", "TRK-05", .medium)],
                         sdks: [sdk("OpenAI", owner: "OpenAI", category: "ai")])
        let d = ReportDiff.compute(old: old, new: new)
        XCTAssertEqual(d.newVersion, "1.1")
        XCTAssertTrue(d.addedFindings.contains("TRK-05.llm_api_endpoints"))
        XCTAssertTrue(d.removedFindings.contains("DCS-02.b"))
        XCTAssertTrue(d.addedOwners.contains("OpenAI"))
        XCTAssertTrue(d.removedOwners.contains("AppsFlyer"))
        XCTAssertTrue(ReportDiff.render(d).contains("com.test.app"))
    }
}
