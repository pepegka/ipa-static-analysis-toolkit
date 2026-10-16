import XCTest
@testable import ScannerKit

final class VectorDetectorTests: XCTestCase {

    private func index(strings: [String] = [], imported: [String] = [], defined: [String] = []) -> BinaryIndex {
        let sec = MachOSection(segment: "__TEXT", section: "__cstring", fileOffset: 0, size: 0, isInEncryptedRange: false)
        let ss = BinaryIndex.SectionStrings(section: sec,
            strings: strings.enumerated().map { ExtractedString(value: $1, offset: UInt64($0), isUTF16: false) })
        return BinaryIndex(relativePath: "Payload/Test.app/Test", absolutePath: "/tmp/Test",
                           architectures: ["arm64"], isMainExecutable: true, linkedDylibs: [], rpaths: [],
                           sections: [sec], perSectionStrings: [ss], importedSymbols: imported,
                           definedSymbols: defined, encryptedSectionsSkipped: [], stringCountCapped: false)
    }
    private func meta(genre: String? = nil, rating: String? = nil) -> BundleMetadata {
        var m = BundleMetadata(bundleID: "com.test.app", bundleName: "Test", displayName: "Test", shortVersion: "1.0",
            bundleVersion: "1", minimumOSVersion: "16.0", executableName: "Test", supportedPlatforms: ["iPhoneOS"],
            urlSchemes: [], queriedURLSchemes: [], backgroundModes: [], allowsArbitraryLoads: false,
            permissions: [], privacyManifestPath: nil, privacyTrackingDomains: [], privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: [], provisioning: nil, signedTeamID: nil, signedIdentifier: nil)
        m.storeGenre = genre; m.contentRating = rating
        return m
    }
    private func sdk(_ name: String, category: String) -> DetectedSDK {
        DetectedSDK(trackerID: name, name: name, owner: name, country: "US",
                    category: category, isTracker: true, evidenceCount: 1, endpoints: [], frameworks: ["\(name).framework"])
    }

    func testVectorsAreRegistered() {
        for code in ["DCS-07", "TRK-05", "TGAP-03"] {
            XCTAssertNotNil(Vectors.byID[code], "\(code) not registered")
            let v = Vectors.byID[code]!
            let cw = FrameworkCrosswalk.for(vectorID: v.id)
            XCTAssertFalse(cw.maswe.isEmpty, "\(code) has no MASWE binding")
        }
        XCTAssertEqual(Vectors.byID["TRK-05"]?.construct, .TRK)
        XCTAssertEqual(Vectors.byID["DCS-07"]?.construct, .DCS)
    }

    func testLLMEndpointDetected() {
        let f = AIEgressAnalyzer.analyze(indices: ["b": index(strings: ["https://api.anthropic.com/v1/messages"])])
        XCTAssertTrue(f.contains { $0.ruleID == "TRK-05.llm_api_endpoints"
            && $0.severity == .derived("TRK-05.llm_api_endpoints", "TRK-05") })
    }
    func testScreenContextToLLMIsLikelyHighRisk() {
        let f = AIEgressAnalyzer.analyze(indices: ["b": index(strings: ["api.openai.com"], defined: ["UIGraphicsImageRenderer"])])
        XCTAssertTrue(f.contains { $0.ruleID == "TRK-05.screen_context_to_llm" && $0.severity == .medium })
    }
    func testOnDeviceMLIsPositiveInfoWithoutCloud() {
        let f = AIEgressAnalyzer.analyze(indices: ["b": index(defined: ["VNCoreMLModel"])])
        XCTAssertTrue(f.contains { $0.ruleID == "TRK-05.on_device_ml" && $0.severity == .info })
        let f2 = AIEgressAnalyzer.analyze(indices: ["b": index(strings: ["api.openai.com"], defined: ["VNCoreMLModel"])])
        XCTAssertFalse(f2.contains { $0.ruleID == "TRK-05.on_device_ml" })
    }

    func testKidsGenreWithAdTrackersIsLikelyHighRisk() {
        let net = NetworkInventory(endpoints: [], detectedSDKs: [sdk("Facebook Ads", category: "advertising")])
        let f = ChildSafetyAnalyzer.analyze(metadata: meta(genre: "Kids", rating: "4+"), network: net, indices: [:])
        XCTAssertTrue(f.contains { $0.ruleID == "TGAP-03.kids_category_trackers" && $0.severity == .medium })
    }
    func testNonKidsGenreDoesNotFireChildSafety() {
        let net = NetworkInventory(endpoints: [], detectedSDKs: [sdk("Facebook Ads", category: "advertising")])
        let f = ChildSafetyAnalyzer.analyze(metadata: meta(genre: "Games"), network: net, indices: [:])
        XCTAssertFalse(f.contains { $0.ruleID == "TGAP-03.kids_category_trackers" })
    }
    func testDeclaredAgeRangeIsPositiveSignal() {
        let f = ChildSafetyAnalyzer.analyze(metadata: meta(), network: .empty,
                                            indices: ["b": index(defined: ["DeclaredAgeRange"])])
        XCTAssertTrue(f.contains { $0.ruleID == "TGAP-03.declared_age_range_api" && $0.severity == .info })
    }

    func testTrackerDBHasAIOwnerClass() {
        let db = TrackerDBLoader.loadBundled()
        let ai = db.trackers.filter { $0.category == "ai" }
        XCTAssertGreaterThanOrEqual(ai.count, 5, "AI owner-class not populated")
        XCTAssertTrue(ai.contains { $0.owner == "OpenAI" })
    }
}
