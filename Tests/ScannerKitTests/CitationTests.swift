import XCTest
@testable import ScannerKit

final class CitationTests: XCTestCase {

    private var pack: [Rule] { RuleLoader.loadBundled().rules }

    func testEveryYAMLRuleCitesSomething() {
        let uncited = pack.filter { $0.citations.isEmpty }.map(\.id).sorted()
        XCTAssertTrue(uncited.isEmpty, "\(uncited.count) rules cite nothing: \(uncited.prefix(10))")
    }

    func testEveryAnalyzerRuleCitesSomething() {
        let uncited = Messages.knownRuleIDs
            .filter { Messages.citations(forRuleID: $0).isEmpty }
            .sorted()
        XCTAssertTrue(uncited.isEmpty, "analyzer rules citing nothing: \(uncited)")
    }

    func testEveryCitationComesFromARegisteredSource() {
        var offenders: [String] = []
        for rule in pack {
            for url in rule.citations where !SourceRegistry.isRegistered(url) {
                offenders.append("\(rule.id) -> \(url)")
            }
        }
        for id in Messages.knownRuleIDs.sorted() {
            for url in Messages.citations(forRuleID: id) where !SourceRegistry.isRegistered(url) {
                offenders.append("\(id) -> \(url)")
            }
        }
        XCTAssertTrue(offenders.isEmpty,
                      "citations outside taxonomy/sources.json:\n" + offenders.joined(separator: "\n"))
    }

    func testNoCitationPointsAtAnAndroidMASTGTest() {
        var offenders: [String] = []
        func check(_ id: String, _ urls: [String]) {
            for u in urls where u.contains("/android/") { offenders.append("\(id) -> \(u)") }
        }
        for rule in pack { check(rule.id, rule.citations) }
        for id in Messages.knownRuleIDs.sorted() { check(id, Messages.citations(forRuleID: id)) }
        XCTAssertTrue(offenders.isEmpty, "Android citations on an iOS scanner:\n"
                      + offenders.joined(separator: "\n"))
    }

    func testEveryRegisteredSourceIsActuallyUsed() {
        let used = Set(SourceRegistry.citations(in: pack).map(\.source.key))
        let analyzerUsed = Set(Messages.knownRuleIDs.flatMap { id in
            Messages.citations(forRuleID: id).compactMap { SourceRegistry.source(forURL: $0)?.key }
        })
        let mustBeCited = Set(SourceRegistry.all.filter { $0.role == "rule-citation" }.map(\.key))
        let unused = mustBeCited.subtracting(used).subtracting(analyzerUsed)
        XCTAssertTrue(unused.isEmpty, "registered but uncited sources: \(unused.sorted())")
    }

    func testCitationsAreHTTPSAndWellFormed() {
        var offenders: [String] = []
        func check(_ id: String, _ urls: [String]) {
            for u in urls {
                if !u.hasPrefix("https://") || URL(string: u) == nil { offenders.append("\(id) -> \(u)") }
            }
        }
        for rule in pack { check(rule.id, rule.citations) }
        for id in Messages.knownRuleIDs.sorted() { check(id, Messages.citations(forRuleID: id)) }
        XCTAssertTrue(offenders.isEmpty, "malformed citations: \(offenders)")
    }

    func testDataMintedRuleIDsResolveCitations() {
        for id in ["tracker.xai", "tracker.appsflyer",
                   "perm.NSCameraUsageDescription", "perm.NSSpeechRecognitionUsageDescription",
                   "privacy.NSPrivacyAccessedAPICategoryUserDefaults",
                   "privacy.NSPrivacyAccessedAPICategoryDiskSpace"] {
            let refs = Messages.citations(forRuleID: id)
            XCTAssertFalse(refs.isEmpty, "\(id) resolves no citations")
            XCTAssertTrue(refs.allSatisfy { SourceRegistry.isRegistered($0) }, "\(id) cites an unregistered source")
        }
        for id in ["SECH-05.Private_Key_(PEM).Frameworks/DocumentReaderCore.framework/DocumentReaderCore",
                   "SECH-05.JSON_Web_Token.Frameworks/HyBid.framework/AdResponse.json",
                   "SECH-05.Generic_Credential.calendar-superapp/index.html",
                   "SECH-05.cloud_credential.private_key_pem",
                   "SECH-05.bearer_token.json_web_token",
                   "SECH-05.public_client_identifier.google_api_key"] {
            let refs = Messages.citations(forRuleID: id)
            XCTAssertFalse(refs.isEmpty, "\(id) resolves no citations")
            XCTAssertTrue(refs.allSatisfy { SourceRegistry.isRegistered($0) })
        }

        XCTAssertEqual(Messages.references(forRuleID: "privacy.gap.DiskSpace"),
                       Messages.references(forRuleID: "privacy.gap"))
    }

    func testTHIRDPARTYSourcesTableIsUpToDate() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let file = root.appendingPathComponent("THIRD_PARTY.md")
        guard let text = try? String(contentsOf: file, encoding: .utf8) else {
            throw XCTSkip("THIRD_PARTY.md not reachable from \(file.path)")
        }
        let begin = "<!-- BEGIN GENERATED SOURCES -->"
        let end = "<!-- END GENERATED SOURCES -->"
        let b = try XCTUnwrap(text.range(of: begin), "no generated-sources block")
        let e = try XCTUnwrap(text.range(of: end), "no generated-sources block")
        let committed = String(text[b.lowerBound..<e.upperBound]) + "\n"
        XCTAssertEqual(committed, SourceRegistry.bundledMarkdownReport(),
                       "THIRD_PARTY.md is stale; run `ISAT --sources-report`")
    }

    func testAnalyzerFindingCarriesReferencesAfterAnnotation() {
        let f = Finding(ruleID: "privacy.gap.DiskSpace", vectorID: "TGAP-01", title: "t",
                        explanation: "e", severity: .medium, evidences: [])
            .annotatedWithCrosswalk()
        XCTAssertFalse(f.references.isEmpty, "parameterised analyzer id lost its citations")
        XCTAssertTrue(f.references.allSatisfy { SourceRegistry.isRegistered($0) })
    }
}
