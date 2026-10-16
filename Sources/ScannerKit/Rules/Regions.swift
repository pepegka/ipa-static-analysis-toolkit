import Foundation

enum Regions {
    private struct Region: Decodable {
        let code: String
        let name: String?
        let gdprAdequate: Bool
    }
    private struct File: Decodable { let regions: [Region] }

    private static let all = RuleData.decode(File.self, "taxonomy/regions.json").regions

    static let gdprAdequateOrEEA: Set<String> = Set(all.filter(\.gdprAdequate).map(\.code))

    private static let names: [String: String] = Dictionary(
        uniqueKeysWithValues: all.compactMap { r in r.name.map { (r.code, $0) } })

    static func name(_ code: String) -> String { names[code] ?? code }
}
