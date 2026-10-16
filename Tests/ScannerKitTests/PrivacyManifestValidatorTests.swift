import XCTest
@testable import ScannerKit

final class PrivacyManifestValidatorTests: XCTestCase {

    private var app: URL!

    override func setUpWithError() throws {
        app = FileManager.default.temporaryDirectory
            .appendingPathComponent("pmv-\(UUID().uuidString)/X.app", isDirectory: true)
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: app.deletingLastPathComponent())
    }

    @discardableResult
    private func manifest(at relative: String, _ apis: [[String: Any]]) throws -> URL {
        let url = app.appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(fromPropertyList: ["NSPrivacyAccessedAPITypes": apis],
                                                      format: .xml, options: 0)
        try data.write(to: url)
        return url
    }

    private func api(_ category: String, _ reasons: [String]) -> [String: Any] {
        ["NSPrivacyAccessedAPIType": category, "NSPrivacyAccessedAPITypeReasons": reasons]
    }

    private func run(_ manifests: [URL], frameworks: [String] = []) -> [String: Finding] {
        let fs = PrivacyManifestValidator.analyze(appDirectory: app, privacyManifests: manifests,
                                                  embeddedFrameworks: frameworks)
        return Dictionary(uniqueKeysWithValues: fs.map { ($0.ruleID, $0) })
    }

    func testApprovedReasonsPass() throws {
        let m = try manifest(at: "PrivacyInfo.xcprivacy", [
            api("NSPrivacyAccessedAPICategoryUserDefaults", ["CA92.1"]),
            api("NSPrivacyAccessedAPICategoryFileTimestamp", ["C617.1"]),
        ])
        XCTAssertTrue(run([m]).isEmpty)
    }

    func testReasonFromAnotherCategoryIsInvalid() throws {
        let m = try manifest(at: "PrivacyInfo.xcprivacy", [
            api("NSPrivacyAccessedAPICategoryDiskSpace", ["CA92.1"]),
        ])
        let f = try XCTUnwrap(run([m])["TGAP-01.manifest_reason_invalid"])
        XCTAssertEqual(f.evidences.map(\.value), ["CA92.1"])
        XCTAssertEqual(f.maswe, [])
        XCTAssertEqual(f.annotatedWithCrosswalk().maswe, ["MASWE-0073"])
    }

    func testCategoryWithoutReasonIsReported() throws {
        let m = try manifest(at: "PrivacyInfo.xcprivacy", [
            api("NSPrivacyAccessedAPICategorySystemBootTime", []),
        ])
        XCTAssertNotNil(run([m])["TGAP-01.manifest_reason_missing"])
    }

    func testSDKOnlyReasonOnlyCountsInTheAppManifest() throws {
        let appManifest = try manifest(at: "PrivacyInfo.xcprivacy", [
            api("NSPrivacyAccessedAPICategoryUserDefaults", ["C56D.1"]),
        ])
        XCTAssertNotNil(run([appManifest])["TGAP-01.manifest_sdk_only_reason"])

        try FileManager.default.removeItem(at: appManifest)
        let sdkManifest = try manifest(at: "Frameworks/Kit.framework/PrivacyInfo.xcprivacy", [
            api("NSPrivacyAccessedAPICategoryUserDefaults", ["C56D.1"]),
        ])
        XCTAssertNil(run([sdkManifest])["TGAP-01.manifest_sdk_only_reason"])
    }

    func testListedSDKWithoutItsOwnManifest() throws {
        let withManifest = try manifest(at: "Frameworks/Alamofire.framework/PrivacyInfo.xcprivacy", [])
        let found = run([withManifest], frameworks: ["Alamofire", "Kingfisher", "NotOnTheList"])
        let f = try XCTUnwrap(found["TGAP-01.listed_sdk_without_manifest"])
        XCTAssertEqual(f.evidences.map(\.value), ["Kingfisher.framework"])
    }

    func testAppleListLoaded() {
        XCTAssertTrue(PrivacyManifestValidator.listedSDKs.contains("FirebaseCore"))
        XCTAssertTrue(PrivacyManifestValidator.listedSDKs.contains("openssl_grpc"))
        XCTAssertEqual(PrivacyManifestGapAnalyzer.probes.flatMap(\.reasons).count, 17)
    }

    private func rawManifest(at relative: String, _ dict: [String: Any]) throws -> URL {
        let url = app.appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0).write(to: url)
        return url
    }

    func testTrackingFlagAndDomainsMustAgree() throws {
        let noDomains = try rawManifest(at: "PrivacyInfo.xcprivacy", ["NSPrivacyTracking": true])
        XCTAssertNotNil(run([noDomains])["TGAP-01.manifest_tracking_mismatch"])
        let consistent = try rawManifest(at: "PrivacyInfo.xcprivacy",
                                         ["NSPrivacyTracking": true, "NSPrivacyTrackingDomains": ["t.example"]])
        XCTAssertNil(run([consistent])["TGAP-01.manifest_tracking_mismatch"])
        let domainsOnly = try rawManifest(at: "PrivacyInfo.xcprivacy", ["NSPrivacyTrackingDomains": ["t.example"]])
        XCTAssertNotNil(run([domainsOnly])["TGAP-01.manifest_tracking_mismatch"])
    }

    func testCollectedDataTypesAreInventoriedAndValidated() throws {
        let m = try rawManifest(at: "PrivacyInfo.xcprivacy", ["NSPrivacyCollectedDataTypes": [
            ["NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeDeviceID",
             "NSPrivacyCollectedDataTypeLinked": false, "NSPrivacyCollectedDataTypeTracking": true],
            ["NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeFavouriteColour"],
        ]])
        let found = run([m])
        XCTAssertEqual(found["TGAP-01.manifest_data_type_invalid"]?.evidences.map(\.value),
                       ["NSPrivacyCollectedDataTypeFavouriteColour"])
        let inventory = try XCTUnwrap(found["TGAP-01.declared_data_collection"])
        XCTAssertEqual(inventory.metrics["tracking"], "1")
        XCTAssertEqual(inventory.evidences.map(\.value), ["DeviceID"])
    }
}
