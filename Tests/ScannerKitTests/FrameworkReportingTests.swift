import XCTest
@testable import ScannerKit

final class FrameworkReportingTests: XCTestCase {

    private func finding(_ id: String, _ vector: String, _ sev: Severity) -> Finding {
        Finding(ruleID: id, vectorID: vector, title: "t", explanation: "e",
                severity: sev, evidences: []).annotatedWithCrosswalk()
    }

    func testControlRollupFollowsMASVSOrder() {
        let fs = [finding("SECH-01.x", "SECH-01", .high), finding("SECH-02.x", "SECH-02", .low)]
        let ids = fs.controlRollup().map(\.id)
        XCTAssertFalse(ids.isEmpty)
        XCTAssertEqual(ids.first?.hasPrefix("MASVS-STORAGE"), true, "\(ids)")
        XCTAssertTrue(ids.allSatisfy { MASVSCatalog.control($0) != nil })
    }

    func testProfilesComeFromMASWE() {
        XCTAssertEqual(FrameworkLinks.profiles(maswe: ["MASWE-0061"]), ["R"])
        XCTAssertEqual(FrameworkLinks.profiles(maswe: ["MASWE-0026"]), ["L1", "L2"])
    }

    func testLinkFormats() {
        XCTAssertEqual(FrameworkLinks.attack(["T1636.003"]).first?.url,
                       "https://attack.mitre.org/techniques/T1636/003/")
        XCTAssertEqual(FrameworkLinks.cwe(["CWE-319"]).first?.url,
                       "https://cwe.mitre.org/data/definitions/319.html")
        XCTAssertNil(FrameworkLinks.cwe(["n/a"]).first?.url)
        XCTAssertTrue(FrameworkLinks.cvss("CVSS:4.0/AV:N").url?.hasSuffix("#CVSS:4.0/AV:N") ?? false)
    }
}
