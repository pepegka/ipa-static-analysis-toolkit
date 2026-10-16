import XCTest
@testable import ScannerKit

final class SpywareRuleTests: XCTestCase {

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

    func testSeededPegasusIOCIsCritical() {
        let f = fire(strings: ["/private/var/db/com.apple.xpc.roleaccountd.staging/loader"])
        XCTAssertTrue(f.contains { $0.vectorID == "SURV-05" && $0.severity == .critical },
                      "seeded Pegasus IOC not detected")
    }

    func testSeededStalkerwareIsHighTier() {
        let f = fire(strings: ["https://api.mspyonline.com/upload", "FlexiSPY agent build"])
        let spyware = f.filter { $0.vectorID == "SURV-05" }
        XCTAssertFalse(spyware.isEmpty, "seeded stalkerware not detected")
        XCTAssertTrue(spyware.contains { $0.severity == .high })
        XCTAssertFalse(spyware.contains { $0.severity == .critical }, "stalkerware must not be critical-tier")
    }

    func testCriticalIsAlwaysAnchored() {
        let pack = RuleLoader.loadBundled()
        let critical = pack.rules.filter { $0.severity == .critical }
        XCTAssertFalse(critical.isEmpty)
        for r in critical {
            guard let e = SeverityDerivation.entry(ruleID: r.id, vectorID: r.vector) else {
                return XCTFail("critical rule \(r.id) has no anchor")
            }
            switch e.method {
            case "malware":
                XCTAssertEqual(e.kind, "commercial_spyware", "\(r.id) is critical as \(e.kind ?? "?")")
            case "cvss":
                XCTAssertGreaterThanOrEqual(e.cvssScore ?? 0, 9.0,
                    "\(r.id) is critical but its CVSS score is \(e.cvssScore ?? 0)")
            default:
                XCTFail("\(r.id) reaches critical through method \(e.method)")
            }
        }
    }
}
