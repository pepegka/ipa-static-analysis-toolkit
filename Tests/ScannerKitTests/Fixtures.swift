import Foundation
@testable import ScannerKit

func bundledRule(_ id: String) -> Rule? {
    RuleLoader.loadBundled().rules.first { $0.id == id }
}

func makeTempDir() throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("isat-tests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

func makeIndex(rel: String, imported: [String] = [], defined: [String] = []) -> BinaryIndex {
    BinaryIndex(relativePath: rel, absolutePath: "/tmp/\(rel)", architectures: ["arm64"],
                isMainExecutable: true, linkedDylibs: [], rpaths: [], sections: [],
                perSectionStrings: [], importedSymbols: imported, definedSymbols: defined,
                encryptedSectionsSkipped: [], stringCountCapped: false)
}
