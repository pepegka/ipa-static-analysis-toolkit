import Foundation

enum SecurityIndicators {
    struct Pinning: Decodable {
        let strong: [String]
        let weak: [String]
        let anchorCertificateExtensions: Set<String>
    }
    struct Storage: Decodable {
        let encryptionMarkers: [String]
        let databaseExtensions: Set<String>
    }
    struct ResourceScan: Decodable {
        let textExtensions: Set<String>
        let maxFileBytes: Int
        let maxLinesPerFile: Int
    }
    private struct File: Decodable {
        let pinning: Pinning
        let storage: Storage
        let resourceScan: ResourceScan
    }

    private static let file = RuleData.decode(File.self, "security/indicators.json")

    static var pinning: Pinning { file.pinning }
    static var storage: Storage { file.storage }
    static var resourceScan: ResourceScan { file.resourceScan }
}
