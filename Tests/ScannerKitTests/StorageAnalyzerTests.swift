import XCTest
@testable import ScannerKit

final class StorageAnalyzerTests: XCTestCase {

    func testPlaintextSQLiteNeedsADatabase() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let linked = ["/usr/lib/libsqlite3.dylib"]

        let none = StorageAnalyzer.analyze(appDirectory: dir, files: [],
                                           linkedDylibs: linked, indices: [:])
        XCTAssertTrue(none.isEmpty, "Linking libsqlite3 alone must not raise a storage finding")

        let db = dir.appendingPathComponent("cache.sqlite")
        try (Data("SQLite format 3\u{0}".utf8) + Data(repeating: 0, count: 64)).write(to: db)
        let found = StorageAnalyzer.analyze(appDirectory: dir, files: [db],
                                            linkedDylibs: linked, indices: [:])
        XCTAssertEqual(found.count, 1)
        let f = try XCTUnwrap(found.first)
        XCTAssertEqual(f.ruleID, "SECH-02.plaintext_sqlite")
        XCTAssertEqual(f.severity, .info)
        XCTAssertTrue(f.evidences.contains { $0.value.contains("cache.sqlite") })
    }

    func testSQLCipherSuppressesPlaintextSQLite() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = dir.appendingPathComponent("cache.sqlite")
        try (Data("SQLite format 3\u{0}".utf8) + Data(repeating: 0, count: 64)).write(to: db)
        let index = makeIndex(rel: "MyApp", imported: ["_sqlite3_key_v2"], defined: [])
        let findings = StorageAnalyzer.analyze(appDirectory: dir, files: [db],
                                               linkedDylibs: ["/usr/lib/libsqlite3.dylib"],
                                               indices: ["MyApp": index])
        XCTAssertTrue(findings.isEmpty, "SQLCipher key API present, the store is not plaintext")
    }

    func testEncryptedDatabaseIsNotFlagged() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let db = dir.appendingPathComponent("secure.sqlite")
        try Data(repeating: 0xA7, count: 80).write(to: db)
        let findings = StorageAnalyzer.analyze(appDirectory: dir, files: [db],
                                               linkedDylibs: ["/usr/lib/libsqlite3.dylib"],
                                               indices: [:])
        XCTAssertTrue(findings.isEmpty, "A file without the SQLite magic is not a plaintext store")
    }
}
