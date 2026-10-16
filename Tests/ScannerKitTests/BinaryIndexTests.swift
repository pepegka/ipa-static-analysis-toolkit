import XCTest
@testable import ScannerKit

final class BinaryIndexTests: XCTestCase {

    private func index(strings: [String] = [], imported: [String] = [], defined: [String] = []) -> BinaryIndex {
        let sec = MachOSection(segment: "__TEXT", section: "__cstring", fileOffset: 0, size: 0, isInEncryptedRange: false)
        let ss = BinaryIndex.SectionStrings(section: sec,
            strings: strings.enumerated().map { ExtractedString(value: $1, offset: UInt64($0), isUTF16: false) })
        return BinaryIndex(relativePath: "Payload/Test.app/Test", absolutePath: "/tmp/Test",
                           architectures: ["arm64"], isMainExecutable: true, linkedDylibs: [], rpaths: [],
                           sections: [sec], perSectionStrings: [ss], importedSymbols: imported,
                           definedSymbols: defined, encryptedSectionsSkipped: [], stringCountCapped: false)
    }

    private func meta() -> BundleMetadata {
        BundleMetadata(bundleID: "com.test.app", bundleName: "Test", displayName: "Test", shortVersion: "1.0",
            bundleVersion: "1", minimumOSVersion: "16.0", executableName: "Test", supportedPlatforms: ["iPhoneOS"],
            urlSchemes: [], queriedURLSchemes: [], backgroundModes: [], allowsArbitraryLoads: false,
            permissions: [], privacyManifestPath: nil, privacyTrackingDomains: [], privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: [], provisioning: nil, signedTeamID: nil, signedIdentifier: nil)
    }

    private func fire(strings: [String] = [], imported: [String] = [], defined: [String] = []) -> [Finding] {
        let pack = RuleLoader.loadBundled()
        let input = RuleInput(metadata: meta(),
            indices: ["Payload/Test.app/Test": index(strings: strings, imported: imported, defined: defined)],
            provisioningEntitlements: [], codesignEntitlements: [])
        return RuleEngine(rules: pack.rules).evaluate(input)
    }

    func testKeychainFiresFromImportedSymbol() {
        let f = fire(imported: ["_SecItemAdd", "_SecItemCopyMatching"])
        XCTAssertTrue(f.contains { $0.ruleID == "SECH-07.keychain_in_use" },
                      "keychain rule did not fire, symbol-union prefilter recall bug is back")
    }

    func testAnchoredAlternationMatches() {
        let f = fire(imported: ["_SecItemUpdate"])
        XCTAssertTrue(f.contains { $0.vectorID == "SECH-07" })
    }

    func testSwiftModuleTokenRecovery() {
        XCTAssertEqual(SwiftDemangler.moduleTokens(fromMangled: "_$s12AppsFlyerLib8SDKClassC").first, "AppsFlyerLib")
        XCTAssertEqual(SwiftDemangler.moduleTokens(fromMangled: "$s12FBSDKCoreKit9AppEventsC").first, "FBSDKCoreKit")
        XCTAssertTrue(SwiftDemangler.moduleTokens(fromMangled: "_SecItemAdd").isEmpty)
        XCTAssertTrue(SwiftDemangler.moduleTokens(fromMangled: "plainname").isEmpty)
    }

    func testSwiftOnlySDKMatchesRecoveredToken() {
        let f = fire(defined: ["AppsFlyerLib"])
        XCTAssertTrue(f.contains { $0.ruleID == "TRK-01.appsflyer" }, "Swift-only AppsFlyer not matched via recovered token")
    }

    func testNestedExecutablesAreIndexed() {
        let pack = RuleLoader.loadBundled()
        let nested = index(imported: ["_SecItemAdd"])
        let input = RuleInput(metadata: meta(),
            indices: ["Payload/Test.app/PlugIns/Share.appex/Share": nested],
            provisioningEntitlements: [], codesignEntitlements: [])
        let f = RuleEngine(rules: pack.rules).evaluate(input)
        XCTAssertTrue(f.contains { $0.ruleID == "SECH-07.keychain_in_use" },
                      "rule did not fire from a nested appex target")
    }
}
