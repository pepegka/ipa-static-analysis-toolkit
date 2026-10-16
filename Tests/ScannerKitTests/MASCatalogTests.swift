import XCTest
@testable import ScannerKit

final class MASCatalogTests: XCTestCase {

    private var pack: [Rule] { RuleLoader.loadBundled().rules }

    private var allCitations: [(id: String, url: String)] {
        pack.flatMap { r in r.references.map { (r.id, $0) } }
            + Messages.knownRuleIDs.sorted().flatMap { id in
                Messages.references(forRuleID: id).map { (id, $0) }
            }
    }

    func testPinnedVersionsMatchTheCatalogues() {
        let fw = FrameworkVersions.current
        XCTAssertEqual(fw.mastg, MASTGCatalog.version)
        XCTAssertEqual(fw.maswe, MASWECatalog.version)
        XCTAssertEqual(fw.masvs, MASVSCatalog.version)
    }

    func testCataloguesLoaded() {
        XCTAssertEqual(MASVSCatalog.allIDs.count, 24)
        XCTAssertGreaterThanOrEqual(MASWECatalog.allIDs.count, 78)
        XCTAssertFalse(MASTGCatalog.allTestIDs.isEmpty)
        XCTAssertFalse(MASTGCatalog.deprecatedIDs.isEmpty)
    }

    func testCrosswalkBindsOnlyCurrentStaticTests() {
        for v in Vectors.all {
            for id in FrameworkCrosswalk.for(vectorID: v.id).mastg {
                XCTAssertFalse(MASTGCatalog.deprecatedIDs.contains(id), "\(v.id) binds deprecated \(id)")
                guard let test = MASTGCatalog.test(id) else {
                    XCTFail("\(v.id) binds \(id), which is not an iOS test in MASTG \(MASTGCatalog.version)")
                    continue
                }
                XCTAssertTrue(test.isStatic, "\(v.id) binds \(id), which MASTG does not mark static")
            }
        }
    }

    func testCitedMASTGPagesAreCurrent() {
        var offenders: [String] = []
        for (id, url) in allCitations {
            if let test = url.firstMatch(of: /MASTG-TEST-\d{4}/).map({ String($0.output) }) {
                if MASTGCatalog.test(test)?.url != url { offenders.append("\(id) -> \(url)") }
            }
            if let bp = url.firstMatch(of: /MASTG-BEST-\d{4}/).map({ String($0.output) }) {
                if MASTGCatalog.bestPractice(bp) == nil { offenders.append("\(id) -> \(url)") }
            }
            if url.hasPrefix("https://mas.owasp.org/MASTG/0x") { offenders.append("\(id) -> \(url)") }
        }
        XCTAssertTrue(offenders.isEmpty,
                      "citations to deprecated, non-iOS or unknown MASTG pages:\n" + offenders.joined(separator: "\n"))
    }

    func testRuleDescriptionsCarryNoTestIDs() {
        let offenders = pack.filter { $0.description.contains("MASTG-TEST-") }.map(\.id)
        XCTAssertTrue(offenders.isEmpty, "test ids in rule descriptions: \(offenders)")
    }

    func testMASWEMappingsResolve() {
        for id in MASWECatalog.allIDs.sorted() {
            guard let e = MASWECatalog.entry(id) else { continue }
            for control in e.masvsControls {
                XCTAssertNotNil(MASVSCatalog.control(control), "\(id) maps to unknown control \(control)")
            }
            for cwe in e.cwe {
                XCTAssertNotNil(cwe.wholeMatch(of: /CWE-[1-9]\d*/), "\(id) has malformed \(cwe)")
            }
        }
    }

    func testFindingsCarryControlsAndCWEFromMASWE() {
        let f = Finding(ruleID: "SECH-01.probe", vectorID: "SECH-01", title: "t", explanation: "e",
                        severity: .low, evidences: []).annotatedWithCrosswalk()
        XCTAssertTrue(f.masvsControls.contains("MASVS-NETWORK-1"))
        XCTAssertTrue(f.cwe.contains("CWE-319"))
        XCTAssertTrue(f.mastg.allSatisfy { MASTGCatalog.test($0) != nil })
    }

    func testLINDDUNUsesCurrentThreatTypes() {
        let current: Set<String> = ["Linking", "Identifying", "Non-repudiation", "Detecting",
                                    "Data Disclosure", "Unawareness & Unintervenability", "Non-compliance"]
        var used: Set<String> = []
        for v in Vectors.all { used.formUnion(FrameworkCrosswalk.for(vectorID: v.id).linddun) }
        for rule in pack {
            used.formUnion(SeverityDerivation.entry(ruleID: rule.id, vectorID: rule.vector)?.linddun ?? [])
        }
        XCTAssertTrue(used.isSubset(of: current), "outdated LINDDUN names: \(used.subtracting(current))")
    }

    private var bindings: [(id: String, vector: String, maswe: [String], mastg: [String])] {
        pack.map { ($0.id, $0.vector, $0.maswe ?? [], $0.mastg ?? []) }
            + Messages.knownRuleIDs.sorted().compactMap { id in
                Messages.binding(forRuleID: id).map {
                    (id, String(id.prefix(while: { $0 != "." })), $0.maswe, $0.mastg)
                }
            }
    }

    func testBoundWeaknessesExistForIOS() {
        var offenders: [String] = []
        for b in bindings {
            for w in b.maswe {
                guard let e = MASWECatalog.entry(w) else { offenders.append("\(b.id): unknown \(w)"); continue }
                if !e.platforms.contains("ios") { offenders.append("\(b.id): \(w) is not an iOS weakness") }
            }
        }
        XCTAssertTrue(offenders.isEmpty, offenders.joined(separator: "\n"))
    }

    func testBoundTestsMatchTheRuleWeakness() {
        var offenders: [String] = []
        for b in bindings {
            for t in b.mastg {
                guard let test = MASTGCatalog.test(t) else { offenders.append("\(b.id): \(t) not current"); continue }
                if !test.isStatic { offenders.append("\(b.id): \(t) is not static") }
                if Set(test.maswe).isDisjoint(with: b.maswe) {
                    offenders.append("\(b.id): \(t) tests \(test.maswe), rule is bound to \(b.maswe)")
                }
            }
        }
        XCTAssertTrue(offenders.isEmpty, offenders.joined(separator: "\n"))
    }

    func testAnchorCWEComesFromTheBoundWeakness() {
        var offenders: [String] = []
        for b in bindings {
            guard let cwe = SeverityDerivation.entry(ruleID: b.id, vectorID: b.vector)?.cwe else { continue }
            let published = Set(b.maswe.compactMap(MASWECatalog.entry).flatMap(\.cwe))
            for c in cwe where !published.contains(c) {
                offenders.append("\(b.id): \(c) not in \(b.maswe) mapping \(published.sorted())")
            }
        }
        XCTAssertTrue(offenders.isEmpty, offenders.joined(separator: "\n"))
    }

    func testXcodeVersionDecoding() {
        XCTAssertEqual(PlatformVersionAnalyzer.xcodeVersion("1640"), "16.4")
        XCTAssertEqual(PlatformVersionAnalyzer.xcodeVersion("2600"), "26.0")
        XCTAssertEqual(PlatformVersionAnalyzer.xcodeVersion("x"), "x")
    }

    func testVectorGroupsAgreeWithMASWE() {
        for v in Vectors.all {
            let groups = Set(FrameworkCrosswalk.for(vectorID: v.id).maswe.compactMap(MASWECatalog.group))
            XCTAssertTrue(groups.contains(v.group), "\(v.id) is \(v.group.rawValue); its MASWE weaknesses are in \(groups.map(\.rawValue).sorted())")
        }
    }
}
