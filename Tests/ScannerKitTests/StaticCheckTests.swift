import XCTest
@testable import ScannerKit

final class StaticCheckTests: XCTestCase {

    func testCodeSignatureFormatThresholdIsApples() {
        let old = CodeSignInfo(signedIdentifier: nil, signedTeamID: nil, entitlementsXML: nil,
                               codeDirectoryVersion: 0x20200)
        XCTAssertEqual(CodeSignReader.findings(old).map(\.ruleID), ["SECH-06.outdated_signature_format"])
        let current = CodeSignInfo(signedIdentifier: nil, signedTeamID: nil, entitlementsXML: nil,
                                   codeDirectoryVersion: 0x20400)
        XCTAssertTrue(CodeSignReader.findings(current).isEmpty)
    }

    func testNamespaceHostsAreNotEndpoints() {
        XCTAssertFalse(CleartextURLAnalyzer.isEndpoint("www.w3.org"))
        XCTAssertFalse(CleartextURLAnalyzer.isEndpoint("localhost"))
        XCTAssertTrue(CleartextURLAnalyzer.isEndpoint("api.example.com"))
    }

    func testDebugStabsAreClassifiedApart() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let src = dir.appendingPathComponent("m.c"), bin = dir.appendingPathComponent("m")
        try "int main(void) { return 0; }\n".write(to: src, atomically: true, encoding: .utf8)
        guard (try? Shell.run("/usr/bin/xcrun", ["clang", "-g", "-o", bin.path, src.path]))?.exitCode == 0 else {
            throw XCTSkip("clang unavailable")
        }
        func index() throws -> BinaryIndex {
            try XCTUnwrap(BinaryIndexer.build(forBinary: bin, relativePath: "m", isMainExecutable: true))
        }
        let withDebug = try index()
        XCTAssertGreaterThan(withDebug.debugStabCount, 0)
        XCTAssertFalse(withDebug.definedSymbols.contains { $0.hasSuffix("m.c") || $0.hasPrefix("/") },
                       "stab names leaked into the symbol index")
        _ = try Shell.run("/usr/bin/xcrun", ["strip", "-S", bin.path])
        XCTAssertEqual(try index().debugStabCount, 0)
    }
}

final class BundleInputTests: XCTestCase {

    func testSymlinksOutOfTheBundleAreNotFollowed() throws {
        let root = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: root) }
        let app = root.appendingPathComponent("X.app", isDirectory: true)
        try FileManager.default.createDirectory(at: app, withIntermediateDirectories: true)
        let secret = root.appendingPathComponent("outside.txt")
        try "not part of the app".write(to: secret, atomically: true, encoding: .utf8)
        try "inside".write(to: app.appendingPathComponent("real.txt"), atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(at: app.appendingPathComponent("leak.txt"),
                                                   withDestinationURL: secret)
        try FileManager.default.createSymbolicLink(at: app.appendingPathComponent("Info.plist"),
                                                   withDestinationURL: secret)

        let (files, outside) = Scanner.bundleFiles(in: app)
        XCTAssertEqual(files.map(\.lastPathComponent).sorted(), ["real.txt"])
        XCTAssertEqual(outside, ["Info.plist", "leak.txt"])
        XCTAssertNil(PlistUtil.load(at: app.appendingPathComponent("Info.plist")))
    }
}

final class ShellTests: XCTestCase {
    func testLargeStderrDoesNotDeadlock() throws {
        let r = try Shell.run("/bin/sh", ["-c", "head -c 300000 /dev/zero >&2; echo done"])
        XCTAssertEqual(r.stderr.count, 300_000)
        XCTAssertEqual(r.stdoutString.trimmingCharacters(in: .whitespacesAndNewlines), "done")
    }
}

final class PermissionGateTests: XCTestCase {
    func testScreenCaptureDetectionNeedsNoPermission() {
        XCTAssertEqual(PermissionGate.defaultPermissions(forVector: "DCS-05", ruleID: "DCS-05.screen_capture_detect"), [])
        XCTAssertEqual(PermissionGate.defaultPermissions(forVector: "DCS-05", ruleID: "DCS-05.video_capture"),
                       ["NSCameraUsageDescription"])
    }

    func testProximityRulesAreGated() {
        XCTAssertTrue(PermissionGate.defaultPermissions(forVector: "DCS-07", ruleID: "DCS-07.ble_scanning")
            .contains("NSBluetoothAlwaysUsageDescription"))
        XCTAssertEqual(PermissionGate.defaultPermissions(forVector: "DCS-07", ruleID: "DCS-07.local_network"),
                       ["NSLocalNetworkUsageDescription"])
        XCTAssertEqual(PermissionGate.defaultPermissions(forVector: "DCS-07", ruleID: "DCS-07.uwb_ranging"),
                       ["NSNearbyInteractionUsageDescription"])
    }

    func testEveryDefaultNamesARealVector() {
        let ids = Set(Vectors.all.map(\.id))
        for row in PermissionCatalog.defaultPermissions {
            XCTAssertTrue(ids.contains(row.vector), "permissions.json names unknown vector \(row.vector)")
        }
    }
}
