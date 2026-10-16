import XCTest
@testable import ScannerKit

final class RulePackTests: XCTestCase {

    func testBundledPackLoadsWithoutErrors() {
        let pack = RuleLoader.loadBundled()
        XCTAssertTrue(pack.loadErrors.isEmpty, "Rule pack load errors: \(pack.loadErrors)")
        XCTAssertFalse(pack.rules.isEmpty)
        let known = Set(Vectors.all.map(\.id))
        for r in pack.rules {
            XCTAssertTrue(known.contains(r.vector), "Unknown vector \(r.vector) in rule \(r.id)")
        }
    }

    func testVectorsAreUnique() {
        let ids = Set(Vectors.all.map(\.id))
        XCTAssertEqual(ids.count, Vectors.all.count)
    }

    func testVectorGroupMappingIsTotal() {
        for v in Vectors.all {
            XCTAssertTrue(MASVSGroup.allCases.contains(v.group), "\(v.id) has no group")
        }
        let grouped = Vectors.byGroup.values.reduce(0) { $0 + $1.count }
        XCTAssertEqual(grouped, Vectors.all.count)
        XCTAssertEqual(Set(MASVSGroup.allOrdered), Set(MASVSGroup.allCases))
        XCTAssertEqual(MASVSGroup.allOrdered.count, MASVSGroup.allCases.count)
    }

    func testSecurityVectorsExist() {
        for id in ["SECH-04", "SECH-02",
                   "SECH-01", "SECH-05"] {
            XCTAssertNotNil(Vectors.byID[id], "Missing security vector \(id)")
        }
    }

    func testSeverityIsComparable() {
        XCTAssertLessThan(Severity.low, Severity.high)
        XCTAssertEqual([Severity.high, .info, .medium].max(), .high)
    }
}
