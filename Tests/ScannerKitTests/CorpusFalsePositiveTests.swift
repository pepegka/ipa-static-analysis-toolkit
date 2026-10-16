import XCTest
@testable import ScannerKit

final class CorpusFalsePositiveTests: XCTestCase {

    private func meta(bundleID: String = "com.test.app", frameworks: [String] = []) -> BundleMetadata {
        BundleMetadata(
            bundleID: bundleID, bundleName: "T", displayName: "T", shortVersion: "1.0",
            bundleVersion: "1", minimumOSVersion: "17.0", executableName: "T",
            supportedPlatforms: ["iPhoneOS"], urlSchemes: [], queriedURLSchemes: [],
            backgroundModes: [], allowsArbitraryLoads: false, permissions: [],
            privacyManifestPath: nil, privacyTrackingDomains: [], privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: frameworks, provisioning: nil,
            signedTeamID: nil, signedIdentifier: nil)
    }

    private func index(strings: [String]) -> BinaryIndex {
        let sec = MachOSection(segment: "__TEXT", section: "__cstring", fileOffset: 0, size: 0, isInEncryptedRange: false)
        let ss = BinaryIndex.SectionStrings(section: sec,
            strings: strings.enumerated().map { ExtractedString(value: $1, offset: UInt64($0), isUTF16: false) })
        return BinaryIndex(relativePath: "Payload/T.app/T", absolutePath: "/tmp/T",
                           architectures: ["arm64"], isMainExecutable: true, linkedDylibs: [], rpaths: [],
                           sections: [sec], perSectionStrings: [ss], importedSymbols: [],
                           definedSymbols: [], encryptedSectionsSkipped: [], stringCountCapped: false)
    }

    private func fires(_ ruleID: String, frameworks: [String] = [], strings: [String] = []) -> Bool {
        let input = RuleInput(metadata: meta(frameworks: frameworks),
                              indices: strings.isEmpty ? [:] : ["Payload/T.app/T": index(strings: strings)],
                              provisioningEntitlements: [], codesignEntitlements: [])
        let rules = RuleLoader.loadBundled().rules.filter { $0.id == ruleID }
        XCTAssertEqual(rules.count, 1, "\(ruleID) missing from the pack")
        return RuleEngine(rules: rules).evaluate(input).contains { $0.ruleID == ruleID }
    }

    func testPilgrimDoesNotMatchNetflixSqlStore() {
        XCTAssertFalse(fires("TRK-02.foursquare_pilgrim",
                             frameworks: ["NFSqlStore_-13933365C3D73F25_PackageProduct"]))
        XCTAssertFalse(fires("TRK-02.foursquare_pilgrim", frameworks: ["pilgrim", "PilgrimTours", "FSQKit"]))
    }

    func testPilgrimMatchesFoursquareFrameworks() {
        XCTAssertTrue(fires("TRK-02.foursquare_pilgrim", frameworks: ["Pilgrim"]))
        XCTAssertTrue(fires("TRK-02.foursquare_pilgrim", frameworks: ["MovementSdk"]))
    }

    func testVPNInterfaceRuleIgnoresOpenSSLCurvesAndUppercaseNoise() {
        XCTAssertFalse(fires("SURV-01.utun_interface_string", strings: ["ipsec3", "ipsec4"]))
        XCTAssertFalse(fires("SURV-01.utun_interface_string", strings: ["TUN3|", "UTUN4"]))
    }

    func testVPNInterfaceRuleMatchesTunnelInterfaceLists() {
        XCTAssertTrue(fires("SURV-01.utun_interface_string", strings: ["utun4"]))
        XCTAssertTrue(fires("SURV-01.utun_interface_string", strings: ["ipsec0"]))
        XCTAssertTrue(fires("SURV-01.utun_interface_string", strings: ["utun0/ipv4"]))
    }

    func testSessionReplayRuleMatchesVendorModules() {
        for fw in ["FullStory", "QuantumMetric_SDK", "LogRocket", "AmplitudeSessionReplay",
                   "MixpanelSessionReplay", "DynatraceSessionReplay", "SmartlookAnalytics"] {
            XCTAssertTrue(fires("TRK-01.session_replay_sdk", frameworks: [fw]), fw)
        }
        for fw in ["AmplitudeCore", "Mixpanel", "Dynatrace", "Sentry", "HeapModule"] {
            XCTAssertFalse(fires("TRK-01.session_replay_sdk", frameworks: [fw]), fw)
        }
    }

    private let partners = #"""
    {
        "dataPartners": [
          { "key": "cuebiq", "display": "Cuebiq", "privacyPolicy": "https://www.cuebiq.com/privacypolicy/" },
          { "key": "safegraph", "display": "SafeGraph", "privacyPolicy" : "https://www.safegraph.com/privacy-policy" },
          { "key": "onspot", "display": "OnSpot Data", "privacyPolicy": "https://www.onspotdata.com" },
          { "key": "roq_ad", "display": "Roq.ad", "privacyPolicy": "https://www.roq.ad/privacy-policy" }
        ]
    }
    """#

    func testPrivacyPolicyListIsAReferenceDocument() {
        XCTAssertEqual(ReferenceDocuments.match(fileName: "dataPartners.json", text: partners),
                       "Privacy-policy link list")
    }

    func testPrivacyPolicyListIsNotMinedForEndpoints() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("dataPartners.json")
        try partners.write(to: file, atomically: true, encoding: .utf8)
        let r = ResourceScanner.scan(appDirectory: dir, files: [file])
        XCTAssertEqual(r.endpoints.map(\.host), [])
    }

    func testDocumentsWithOtherLinksAreStillMined() {
        func match(_ s: String) -> String? { ReferenceDocuments.match(fileName: "config.json", text: s) }
        XCTAssertNil(match(#"{"privacyPolicy":"https://app.example/privacy"}"#))
        XCTAssertNil(match(#"""
            {"partners":[{"privacyPolicy":"https://a.example/p","endpoint":"https://collect.a.example/v1"},
                         {"privacyPolicy":"https://b.example/p"}]}
            """#))
        XCTAssertNil(match(#"""
            {"apiHost":"api.acme.com",
             "partners":[{"privacyPolicy":"https://a.example/p"},{"privacyPolicy":"https://b.example/p"}]}
            """#))
        XCTAssertNil(match(#"[{"url":"https://a.example/p"},{"url":"https://b.example/p"}]"#))
    }

    private let db = TrackerDB(trackers: [
        Tracker(id: "anthropic", name: "Anthropic", owner: "Anthropic", country: "US",
                category: "ai", domains: ["api.anthropic.com", "anthropic.com"], is_tracker: true),
        Tracker(id: "facebook.core", name: "Meta / Facebook", owner: "Meta", country: "US",
                category: "advertising", domains: ["facebook.com", "fbcdn.net"], is_tracker: true),
    ])

    private func sdk(_ name: String, owner: String, category: String) -> DetectedSDK {
        DetectedSDK(trackerID: name, name: name, owner: owner, country: "US", category: category,
                    isTracker: true, evidenceCount: 1, endpoints: [], frameworks: ["(main)"])
    }

    private func tgap02(bundleID: String, sdks: [DetectedSDK], idfa: Bool = false) -> Bool {
        let indices = idfa ? ["Payload/T.app/T": makeIndex(rel: "Payload/T.app/T", imported: ["_OBJC_CLASS_$_ASIdentifierManager"])] : [:]
        return ConsentProvenanceAnalyzer.consentIntegrity(
            metadata: meta(bundleID: bundleID), network: NetworkInventory(endpoints: [], detectedSDKs: sdks),
            indices: indices, trackerDB: db)
            .contains { $0.ruleID == "TGAP-02.tracking_without_att" }
    }

    func testPublisherOwnedEndpointsAreNotTrackingCapability() {
        XCTAssertFalse(tgap02(bundleID: "com.anthropic.claude",
                              sdks: [sdk("Anthropic", owner: "Anthropic", category: "ai")]))
        XCTAssertFalse(tgap02(bundleID: "com.test.app", sdks: [], idfa: true),
                       "without ATT permission the advertising identifier is all zeros")
        XCTAssertFalse(tgap02(bundleID: "com.test.app",
                              sdks: [sdk("Anthropic", owner: "Anthropic", category: "ai")]),
                       "a model API is not advertising or attribution")
        XCTAssertTrue(tgap02(bundleID: "com.test.app",
                             sdks: [sdk("Meta / Facebook", owner: "Meta", category: "advertising")]))
    }

    func testAdvertisingOwnersAndParentCompaniesStillCount() {
        XCTAssertTrue(tgap02(bundleID: "com.facebook.Facebook",
                             sdks: [sdk("Meta / Facebook", owner: "Meta", category: "advertising")]))
        XCTAssertTrue(tgap02(bundleID: "net.whatsapp.WhatsApp",
                             sdks: [sdk("Meta / Facebook", owner: "Meta", category: "advertising")]))
    }

    func testPublisherIsResolvedFromTheBundleIdentifier() {
        XCTAssertEqual(ConsentProvenanceAnalyzer.publisherOwner(bundleID: "com.anthropic.claude", trackerDB: db), "Anthropic")
        XCTAssertEqual(ConsentProvenanceAnalyzer.publisherOwner(bundleID: "com.facebook.Facebook", trackerDB: db), "Meta")
        XCTAssertNil(ConsentProvenanceAnalyzer.publisherOwner(bundleID: "net.whatsapp.WhatsApp", trackerDB: db))
        XCTAssertNil(ConsentProvenanceAnalyzer.publisherOwner(bundleID: "Station.Six7", trackerDB: db))
        XCTAssertNil(ConsentProvenanceAnalyzer.publisherOwner(bundleID: "anthropic", trackerDB: db))
    }
}
