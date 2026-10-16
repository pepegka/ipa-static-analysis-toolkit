import XCTest
@testable import ScannerKit

final class ObfuscationRuleTests: XCTestCase {

    func testOrdinarySwiftManglingIsNotObfuscation() throws {
        let r = try XCTUnwrap(bundledRule("SURV-04.tampered_classnames"))
        let pattern = try XCTUnwrap(r.search.first).pattern
        let re = try NSRegularExpression(pattern: pattern)
        let benign = [
            "_TtC10FoundationP33_12768CA107A31EF2DCE034FD75B541C913__JSONEncoder",
            "_TtC10FoundationP33_6DA0945A07226B3278459E9368612FF427__KVOKeyPathBridgeMachinery",
            "_TtC12TUXSwiftBaseP33_A220A1F90B3C47A33E134BFEBF17124723TUXBreakPointWeakObject",
            "_TtC9SwiftKnit36SwiftKnitGlobalComponentDebugManager",
        ]
        for name in benign {
            let range = NSRange(name.startIndex..<name.endIndex, in: name)
            XCTAssertNil(re.firstMatch(in: name, options: [], range: range),
                         "Ordinary Swift mangling must not be flagged as obfuscation: \(name)")
        }
    }

    func testGeneratedNumericObjCClassesMatch() throws {
        let r = try XCTUnwrap(bundledRule("SURV-04.tampered_classnames"))
        let pattern = try XCTUnwrap(r.search.first).pattern
        let re = try NSRegularExpression(pattern: pattern)
        let name = "_OBJC_CLASS_$_AB12345"
        let range = NSRange(name.startIndex..<name.endIndex, in: name)
        XCTAssertNotNil(re.firstMatch(in: name, options: [], range: range))
    }
}
