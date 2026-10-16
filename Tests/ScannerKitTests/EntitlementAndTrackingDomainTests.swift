import XCTest
@testable import ScannerKit

final class EntitlementAndTrackingDomainTests: XCTestCase {

    private func fires(_ ruleID: String, entitlements: [String]) -> Bool {
        let m = BundleMetadata(
            bundleID: "com.test.app", bundleName: "T", displayName: "T", shortVersion: "1.0",
            bundleVersion: "1", minimumOSVersion: "17.0", executableName: "T",
            supportedPlatforms: ["iPhoneOS"], urlSchemes: [], queriedURLSchemes: [],
            backgroundModes: [], allowsArbitraryLoads: false, permissions: [],
            privacyManifestPath: nil, privacyTrackingDomains: [], privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: [], provisioning: nil,
            signedTeamID: nil, signedIdentifier: nil)
        let input = RuleInput(metadata: m, indices: [:],
                              provisioningEntitlements: [], codesignEntitlements: entitlements)
        let engine = RuleEngine(rules: RuleLoader.loadBundled().rules)
        return engine.evaluate(input).contains { $0.ruleID == ruleID }
    }

    func testDataProtectionEntitlementFires() {
        XCTAssertTrue(fires("SECH-02.data_protection_entitlement",
                            entitlements: ["com.apple.developer.default-data-protection"]))
        XCTAssertFalse(fires("SECH-02.data_protection_entitlement",
                             entitlements: ["com.apple.developer.associated-domains"]))
    }

    func testAppAttestEntitlementFires() {
        XCTAssertTrue(fires("SECH-07.app_attest",
                            entitlements: ["com.apple.developer.devicecheck.appattest-environment"]))
        XCTAssertFalse(fires("SECH-07.app_attest", entitlements: ["com.apple.developer.devicecheck"]))
    }

    func testFamilyControlsMatchesBothProductionAndDevelopment() {
        XCTAssertTrue(fires("TGAP-03.family_controls",
                            entitlements: ["com.apple.developer.family-controls"]))
        XCTAssertTrue(fires("TGAP-03.family_controls",
                            entitlements: ["com.apple.developer.family-controls.development"]))
        XCTAssertFalse(fires("TGAP-03.family_controls",
                             entitlements: ["com.apple.developer.family-controls.extra"]))
    }

    func testDeclaredAgeRangeEntitlementFires() {
        XCTAssertTrue(fires("TGAP-03.declared_age_range_entitlement",
                            entitlements: ["com.apple.developer.declared-age-range"]))
    }

    func testDynamicLoaderMatchesExactSymbolsOnly() throws {
        let rule = try XCTUnwrap(bundledRule("SECH-06.dynamic_loader_imports"))
        let re = try NSRegularExpression(pattern: try XCTUnwrap(rule.search.first?.pattern))
        func hit(_ s: String) -> Bool {
            re.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
        }
        XCTAssertTrue(hit("_dlopen"))
        XCTAssertTrue(hit("_dlsym"))
        XCTAssertFalse(hit("_dlopen_preflight"))
        XCTAssertFalse(hit("_my_dlopen"))
        XCTAssertFalse(hit("_dladdr"))
        XCTAssertEqual(rule.severity, .info, "dynamic loading is ubiquitous; it is inventory, not a weakness")
    }

    private func meta(manifest: String?, declared: [String]) -> BundleMetadata {
        BundleMetadata(
            bundleID: "com.test.app", bundleName: "T", displayName: "T", shortVersion: "1.0",
            bundleVersion: "1", minimumOSVersion: "17.0", executableName: "T",
            supportedPlatforms: ["iPhoneOS"], urlSchemes: [], queriedURLSchemes: [],
            backgroundModes: [], allowsArbitraryLoads: false, permissions: [],
            privacyManifestPath: manifest, privacyTrackingDomains: declared, privacyAccessedAPIs: [],
            embeddedBinaries: [], embeddedFrameworks: [], provisioning: nil,
            signedTeamID: nil, signedIdentifier: nil)
    }

    private func net(_ hosts: [(String, Bool)]) -> NetworkInventory {
        NetworkInventory(endpoints: hosts.map { host, isTracker in
            ClassifiedEndpoint(host: host, registrableDomain: host, trackerID: isTracker ? "t" : nil,
                               owner: isTracker ? "Tracker Inc" : nil, country: "US",
                               category: isTracker ? "advertising" : nil, isTracker: isTracker,
                               occurrenceCount: 1, sources: ["bin"], samplePaths: [], samplePlistKeys: [])
        }, detectedSDKs: [])
    }

    func testUndeclaredTrackerDomainIsReported() {
        let f = ConsentProvenanceAnalyzer.trackingDomainCoverage(
            metadata: meta(manifest: "PrivacyInfo.xcprivacy", declared: ["declared.example"]),
            network: net([("declared.example", true), ("sneaky.tracker.io", true)]))
        XCTAssertEqual(f.count, 1)
        XCTAssertEqual(f.first?.ruleID, "TGAP-01.undeclared_tracking_domains")
        XCTAssertEqual(f.first?.severity, .info)
        XCTAssertEqual(f.first?.evidences.map(\.value), ["sneaky.tracker.io"])
    }

    func testAnalyticsHostsAreNotTrackingDomains() {
        let endpoint = ClassifiedEndpoint(host: "stats.example.io", registrableDomain: "example.io", trackerID: "t",
                                          owner: "Tracker Inc", country: "US", category: "analytics", isTracker: true,
                                          occurrenceCount: 1, sources: ["bin"], samplePaths: [], samplePlistKeys: [])
        let f = ConsentProvenanceAnalyzer.trackingDomainCoverage(
            metadata: meta(manifest: "PrivacyInfo.xcprivacy", declared: ["declared.example"]),
            network: NetworkInventory(endpoints: [endpoint], detectedSDKs: []))
        XCTAssertTrue(f.isEmpty)
    }

    func testSubdomainOfADeclaredDomainCounts() {
        let f = ConsentProvenanceAnalyzer.trackingDomainCoverage(
            metadata: meta(manifest: "PrivacyInfo.xcprivacy", declared: ["example.com"]),
            network: net([("metrics.example.com", true)]))
        XCTAssertTrue(f.isEmpty, "a subdomain of a declared domain is covered, as it is at runtime")
    }

    func testNonTrackerHostsAreIgnored() {
        let f = ConsentProvenanceAnalyzer.trackingDomainCoverage(
            metadata: meta(manifest: "PrivacyInfo.xcprivacy", declared: ["example.com"]),
            network: net([("cdn.apple.com", false)]))
        XCTAssertTrue(f.isEmpty)
    }

    func testSilentWhenThereIsNoManifestOrNoDeclaration() {
        XCTAssertTrue(ConsentProvenanceAnalyzer.trackingDomainCoverage(
            metadata: meta(manifest: nil, declared: []),
            network: net([("sneaky.tracker.io", true)])).isEmpty)
        XCTAssertTrue(ConsentProvenanceAnalyzer.trackingDomainCoverage(
            metadata: meta(manifest: "PrivacyInfo.xcprivacy", declared: []),
            network: net([("sneaky.tracker.io", true)])).isEmpty)
    }
}
