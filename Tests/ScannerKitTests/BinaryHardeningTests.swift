import XCTest
@testable import ScannerKit

final class BinaryHardeningTests: XCTestCase {

    func testCanaryIsUnknownForPureSwift() {
        XCTAssertNil(BinaryHardeningAnalyzer.canaryVerdict(symbols: []),
                     "0 visible symbols cannot establish the absence of a canary")
        XCTAssertNil(BinaryHardeningAnalyzer.canaryVerdict(
            symbols: ["_$s10MyWatchApp11ContentViewV4bodyQrvp", "_swift_allocObject"]),
                     "Pure-Swift symbol tables cannot establish the absence of a canary")
    }

    func testCanaryNeedsDefinedObjC() {
        XCTAssertEqual(BinaryHardeningAnalyzer.canaryVerdict(
            symbols: ["_objc_msgSend"], definedSymbols: ["_OBJC_CLASS_$_MYThing"]), false)
        let objcSection = MachOSection(segment: "__DATA", section: "__objc_classlist",
                                       fileOffset: 0, size: 8, isInEncryptedRange: false)
        XCTAssertEqual(BinaryHardeningAnalyzer.canaryVerdict(
            symbols: [], sections: [objcSection]), false)
        XCTAssertNil(BinaryHardeningAnalyzer.canaryVerdict(symbols: ["_objc_msgSend"]),
                     "An imported objc_msgSend must not open the gate")
        XCTAssertEqual(BinaryHardeningAnalyzer.canaryVerdict(
            symbols: ["_objc_msgSend", "___stack_chk_fail"]), true)
    }

    func testWatchKitStubIsExcluded() {
        XCTAssertTrue(BinaryHardeningAnalyzer.isAppleSuppliedStub(
            relativePath: "Watch/MyApp.app/PlugIns/MyApp.appex/_WatchKitStub/WK"))
        XCTAssertFalse(BinaryHardeningAnalyzer.isAppleSuppliedStub(
            relativePath: "Frameworks/MyKit.framework/MyKit"))
    }

    func testNoCanaryFindingWithoutAnExecutable() {
        let bin = EmbeddedBinary(relativePath: "MyApp", name: "MyApp", architectures: ["arm64"],
                                 isFairPlayEncrypted: false, sizeBytes: 1024, linkedDylibs: [])
        let index = makeIndex(rel: "MyApp", imported: ["_objc_msgSend"], defined: ["_OBJC_CLASS_$_X"])
        let result = BinaryHardeningAnalyzer.analyze(embeddedBinaries: [bin],
                                                     machoByRel: [:],
                                                     indices: ["MyApp": index])
        let canaryFindings = result.findings.filter { $0.ruleID.contains("no_stack_canary") }
        XCTAssertTrue(canaryFindings.isEmpty)
        XCTAssertEqual(result.hardening.first?.hasStackCanary, false)
    }

    func testSwiftOnlyBinaryRecordsUnknownCanary() {
        let bin = EmbeddedBinary(relativePath: "W", name: "W", architectures: ["arm64"],
                                 isFairPlayEncrypted: false, sizeBytes: 16, linkedDylibs: [])
        let index = makeIndex(rel: "W", imported: ["_swift_allocObject"], defined: [])
        let result = BinaryHardeningAnalyzer.analyze(embeddedBinaries: [bin],
                                                     machoByRel: [:], indices: ["W": index])
        XCTAssertNil(result.hardening.first?.hasStackCanary,
                     "Swift-only composition must record `unknown`, not `false`")
    }
}
