import Foundation

enum TaxonomyLoader {

    struct VectorRow: Decodable {
        let id: String
        let construct: Construct
        let title: String
        let description: String
        let group: MASVSGroup
        let mitre: [String]
        let userAdvice: String
    }

    private struct TaxonomyFile: Decodable { let vectors: [VectorRow] }

    private struct CrosswalkFile: Decodable {
        let frameworkVersions: FrameworkVersions
        let byConstruct: [String: FrameworkCrosswalk]
        let byVector: [String: FrameworkCrosswalk]
    }

    static let vectors: [VectorRow] = RuleData.decode(TaxonomyFile.self, "taxonomy/vectors.json").vectors

    static let crosswalk: (versions: FrameworkVersions,
                           byConstruct: [Construct: FrameworkCrosswalk],
                           byVector: [String: FrameworkCrosswalk]) = {
        let file = RuleData.decode(CrosswalkFile.self, "taxonomy/crosswalk.json")
        var byConstruct: [Construct: FrameworkCrosswalk] = [:]
        for (key, value) in file.byConstruct {
            guard let c = Construct(rawValue: key) else {
                fatalError("crosswalk.json names unknown construct \(key)")
            }
            byConstruct[c] = value
        }
        return (file.frameworkVersions, byConstruct, file.byVector)
    }()
}
