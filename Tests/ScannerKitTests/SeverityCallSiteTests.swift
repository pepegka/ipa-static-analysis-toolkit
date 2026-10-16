import XCTest
@testable import ScannerKit

final class SeverityCallSiteTests: XCTestCase {

    private func assertAnchoredAtRuleLevel(_ ruleID: String, _ vectorID: String,
                                           _ source: String,
                                           file: StaticString = #filePath, line: UInt = #line) {
        guard let key = SeverityDerivation.anchorKey(ruleID: ruleID, vectorID: vectorID) else {
            return XCTFail("\(ruleID) (from \(source)) has no anchor at all", file: file, line: line)
        }
        XCTAssertTrue(SeverityDerivation.anchoredRuleIDs.contains(key),
                      "\(ruleID) (from \(source)) fell through to the \(vectorID) vector anchor; "
                      + "it needs a rule-level entry, even a generic one",
                      file: file, line: line)
    }

    private func assertAnchored(_ ruleID: String, _ vectorID: String,
                                _ source: String,
                                file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNotNil(SeverityDerivation.anchorKey(ruleID: ruleID, vectorID: vectorID),
                        "\(ruleID) (from \(source)) has no anchor", file: file, line: line)
    }

    func testEveryPermissionKeyIsAnchored() {
        let keys = PermissionCatalog.usageDescriptionKeys
        XCTAssertFalse(keys.isEmpty, "no permission keys loaded")
        for (key, entry) in keys {
            assertAnchoredAtRuleLevel("perm.\(key)", entry.vector, "taxonomy/permissions.json")
        }
    }

    func testEveryRequiredReasonAPIIsAnchored() {
        let apis = PermissionCatalog.requiredReasonAPIs
        XCTAssertFalse(apis.isEmpty, "no required-reason APIs loaded")
        for (api, entry) in apis {
            assertAnchoredAtRuleLevel("privacy.\(api)", entry.vector, "taxonomy/permissions.json")
        }
    }

    func testEveryPrivacyManifestProbeIsAnchored() {
        let probes = PrivacyManifestGapAnalyzer.probes
        XCTAssertFalse(probes.isEmpty, "no privacy-manifest probes loaded")
        for probe in probes {
            assertAnchoredAtRuleLevel("privacy.gap.\(probe.category)", "TGAP-01", "privacy/required-reason-apis.json")
        }
    }

    func testEveryCredentialClassIsAnchored() {
        let classes = SecretScanner.credentialClasses
        XCTAssertFalse(classes.isEmpty, "no credential classes loaded")
        for c in classes {
            assertAnchoredAtRuleLevel("SECH-05.\(c)", "SECH-05", "secrets/patterns.json")
        }
    }

    func testEveryLiteralDerivedCallSiteIsAnchored() throws {
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/ScannerKit")
        guard let walk = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil) else {
            throw XCTSkip("sources not reachable from \(sources.path)")
        }
        let re = try NSRegularExpression(pattern: #"\.derived\("([^"\\]+)",\s*"([^"\\]+)""#)
        var checked = 0
        for case let url as URL in walk where url.pathExtension == "swift" {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            let ns = text as NSString
            for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                let ruleID = ns.substring(with: m.range(at: 1))
                let vectorID = ns.substring(with: m.range(at: 2))
                assertAnchored(ruleID, vectorID, url.lastPathComponent)
                checked += 1
            }
        }
        XCTAssertGreaterThan(checked, 25, "found almost no .derived call sites")
    }

    func testNoHandTypedSeverities() throws {
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/ScannerKit")
        guard let walk = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil) else {
            throw XCTSkip("sources not reachable from \(sources.path)")
        }
        let re = try NSRegularExpression(pattern:
            #"severity:\s*\.(info|low|medium|high|critical)\b|:\s*Severity\s*=[^\n]*\?\s*\.(info|low|medium|high|critical)\b"#)
        var offenders: [String] = []
        for case let url as URL in walk where url.pathExtension == "swift" {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            let ns = text as NSString
            for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                offenders.append("\(url.lastPathComponent): \(ns.substring(with: m.range))")
            }
        }
        XCTAssertTrue(offenders.isEmpty, "hand-typed severities:\n" + offenders.joined(separator: "\n"))
    }
}
