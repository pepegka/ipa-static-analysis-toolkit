import XCTest
@testable import ScannerKit

final class PolarityTests: XCTestCase {

    func testEveryCapabilityRuleDeclaresItsPolarity() {
        let weaknessAtInfo: Set<String> = ["SECH-01.missing_pinning", "SECH-04.debug_symbols",
                                           "SECH-01.hardcoded_http_urls"]
        let yaml = Dictionary(uniqueKeysWithValues: RuleLoader.loadBundled().rules.map { ($0.id, $0.polarity) })
        for (id, e) in SeverityDerivation.file.rules where e.method == "capability" {
            if weaknessAtInfo.contains(id) { continue }
            let anchors = SeverityDerivation.file.rules.keys
            func decidedHere(_ rid: String) -> Bool {
                guard rid == id || rid.hasPrefix(id + ".") else { return false }
                return !anchors.contains { $0 != id && $0.hasPrefix(id + ".") && (rid == $0 || rid.hasPrefix($0 + ".")) }
            }
            let covered = yaml.keys.filter(decidedHere).map { yaml[$0]! }
                + Messages.ruleIDs.filter(decidedHere).map { Messages.polarity(forRuleID: $0) ?? .offensive }
            XCTAssertFalse(covered.isEmpty, "\(id) is a capability anchor with no rule under it")
            XCTAssertFalse(covered.contains(.offensive), "\(id) is a capability anchor covering an offensive rule")
        }
    }

    func testPositiveSignalTitlesAreDefensive() {
        for r in RuleLoader.loadBundled().rules where r.title.lowercased().contains("positive signal") {
            XCTAssertEqual(r.polarity, .defensive, r.id)
        }
    }

    func testYAMLRulePolarityReachesTheFinding() {
        let m = NetworkAttributionTests.metadata()
        let input = RuleInput(metadata: m, indices: [:], provisioningEntitlements: [],
                              codesignEntitlements: ["com.apple.developer.devicecheck.appattest-environment"])
        let f = RuleEngine(rules: RuleLoader.loadBundled().rules).evaluate(input)
            .first { $0.ruleID == "SECH-07.app_attest" }
        XCTAssertEqual(f?.polarity, .defensive)
    }

    func testAnalyzerRulePolarityComesFromMessages() {
        let f = Finding(ruleID: "TRK-05.on_device_ml", vectorID: "TRK-05", title: "t", explanation: "e",
                        severity: .info, evidences: []).annotatedWithCrosswalk()
        XCTAssertEqual(f.polarity, .neutral)
        let gap = Finding(ruleID: "privacy.gap.location", vectorID: "TGAP-01", title: "t", explanation: "e",
                          severity: .medium, evidences: []).annotatedWithCrosswalk()
        XCTAssertEqual(gap.polarity, .offensive, "privacy.gap resolves before the neutral privacy.* wildcard")
    }

    func testRollupsKeepMitigationsOutOfWeaknessCounts() {
        func f(_ id: String, _ p: Polarity, _ maswe: String) -> Finding {
            Finding(ruleID: id, vectorID: "SECH-07", title: id, explanation: "", severity: .info,
                    evidences: [], maswe: [maswe]).withPolarity(p)
        }
        let fs = [f("attest", .defensive, "MASWE-0056"),
                  f("keychain_in_use", .neutral, "MASWE-0016"),
                  f("weak", .offensive, "MASWE-0016")]
        let rollup = fs.clusterRollup()
        let weaknesses = rollup.flatMap(\.children)
        XCTAssertFalse(weaknesses.contains { $0.id == "MASWE-0056" })
        XCTAssertEqual(weaknesses.first { $0.id == "MASWE-0016" }?.findingCount, 1)
        XCTAssertEqual(rollup.reduce(0) { $0 + $1.findingCount }, 2, "neutral counts as a finding, defensive does not")
        XCTAssertEqual(fs.mitigationRollup().map(\.id), ["MASWE-0056"])
    }
}
