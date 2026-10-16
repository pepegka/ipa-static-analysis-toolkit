import XCTest
@testable import ScannerKit

final class TaxonomyAuditTests: XCTestCase {

    func testEveryVectorIsConstructAnchored() {
        for v in Vectors.all {
            XCTAssertTrue(v.id.contains("-"), "\(v.id) is not a construct-anchored code")
            XCTAssertEqual(v.id.split(separator: "-").first.map(String.init), v.construct.rawValue,
                           "\(v.id) prefix must match construct \(v.construct.rawValue)")
        }
    }

    func testTaxonomyFileLoadsCompletely() {
        XCTAssertEqual(Vectors.all.count, 32, "vectors.json did not load the full taxonomy")
        for v in Vectors.all {
            XCTAssertFalse(v.title.isEmpty, "\(v.id) has no title")
            XCTAssertFalse(v.description.isEmpty, "\(v.id) has no description")
            XCTAssertFalse(v.userAdvice.isEmpty, "\(v.id) has no user advice")
        }
        XCTAssertEqual(FrameworkVersions.current.masvs, "2.1.0",
                       "crosswalk.json did not load the pinned framework versions")
    }

    func testAnalyzerCopyIsWellFormed() {
        let vectorIDs = Set(Vectors.all.map(\.id))
        XCTAssertFalse(Messages.knownRuleIDs.isEmpty)
        for id in Messages.knownRuleIDs {
            let entry = Messages.entry(id)
            XCTAssertFalse(entry.title.isEmpty, "\(id) has an empty title")
            XCTAssertFalse(entry.explanation.isEmpty, "\(id) has an empty explanation")

            let prefix = String(id.prefix(while: { $0 != "." }))
            if prefix.contains("-") {
                XCTAssertTrue(vectorIDs.contains(prefix),
                              "\(id) is namespaced to \(prefix), which is not a vector")
            }
        }
    }

    func testSeverityDerivationCoversEveryVector() {
        for v in Vectors.all {
            XCTAssertNotNil(SeverityDerivation.entry(ruleID: "\(v.id).probe", vectorID: v.id),
                            "\(v.id) has no anchor in taxonomy/severity-derivation.json")
        }
    }

    func testVectorIDsAreUnique() {
        XCTAssertEqual(Set(Vectors.all.map(\.id)).count, Vectors.all.count, "duplicate vector IDs")
    }

    func testVectorsResolveByConstructCode() {
        XCTAssertEqual(Vectors.byID["SURV-01"]?.id, "SURV-01")
        XCTAssertEqual(Vectors.byID["PLAT-04"]?.construct, .PLAT)
        XCTAssertEqual(Vectors.group(forVectorID: "PLAT-04"), .platform)
    }

    func testEveryBundledRuleUsesConstructAnchoredIDs() {
        let pack = RuleLoader.loadBundled()
        XCTAssertFalse(pack.rules.isEmpty)
        for r in pack.rules {
            XCTAssertTrue(r.id.contains("."), "rule \(r.id) is not `<vector>.<name>`")
            XCTAssertEqual(String(r.id.split(separator: ".", maxSplits: 1).first ?? ""), r.vector,
                           "rule \(r.id) prefix must match its vector \(r.vector)")
            XCTAssertNotNil(Vectors.byID[r.vector], "rule \(r.id) has unknown vector \(r.vector)")
        }
    }

    func testEveryVectorHasMASWEorMASTGBinding() {
        for v in Vectors.all {
            let cw = FrameworkCrosswalk.for(vectorID: v.id)
            XCTAssertFalse(cw.maswe.isEmpty && cw.mastg.isEmpty,
                           "\(v.id) has neither a MASWE nor a MASTG binding")
        }
    }

    func testEveryBundledRuleDeclaresItsBinding() {
        let undeclared = RuleLoader.loadBundled().rules.filter { $0.maswe == nil || $0.mastg == nil }.map(\.id)
        XCTAssertTrue(undeclared.isEmpty, "rules without maswe:/mastg: keys: \(undeclared)")
        let analyzers = Messages.knownRuleIDs.filter { Messages.binding(forRuleID: $0) == nil }.sorted()
        XCTAssertTrue(analyzers.isEmpty, "analyzer entries without maswe/mastg: \(analyzers)")
    }

    func testMASWEIDsAreWellFormed() {
        let all = Vectors.all.flatMap { FrameworkCrosswalk.for(vectorID: $0.id).maswe }
        XCTAssertFalse(all.isEmpty)
        for id in all {
            XCTAssertTrue(id.range(of: #"^MASWE-\d{4}$"#, options: .regularExpression) != nil,
                          "malformed MASWE id \(id)")
        }
    }

    func testReportPinsFrameworkVersions() {
        let fw = FrameworkVersions.current
        XCTAssertEqual(fw.masvs, "2.1.0")
        XCTAssertFalse(fw.maswe.isEmpty)
        XCTAssertFalse(fw.attackMobile.isEmpty)
    }
}

extension TaxonomyAuditTests {
    func testRuleMASVSTagAgreesWithItsVector() {
        var offenders: [String] = []
        for rule in RuleLoader.loadBundled().rules where !rule.masvs.isEmpty {
            guard let group = Vectors.byID[rule.vector]?.group else { continue }
            if !rule.masvs.contains(group.rawValue) {
                offenders.append("\(rule.id): vector \(rule.vector) is \(group.rawValue), rule tags \(rule.masvs)")
            }
        }
        XCTAssertTrue(offenders.isEmpty,
                      "rule MASVS tags disagreeing with their vector:\n" + offenders.joined(separator: "\n"))
    }
}
