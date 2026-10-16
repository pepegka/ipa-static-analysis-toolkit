import Foundation

public struct FrameworkVersions: Codable, Sendable, Hashable {
    public var masvs: String
    public var mastg: String
    public var maswe: String
    public var attackMobile: String
    public var cvss: String

    public init(masvs: String, mastg: String, maswe: String, attackMobile: String, cvss: String) {
        self.masvs = masvs; self.mastg = mastg; self.maswe = maswe
        self.attackMobile = attackMobile; self.cvss = cvss
    }

    public static let current = TaxonomyLoader.crosswalk.versions
}

public struct FrameworkCrosswalk: Codable, Sendable, Hashable {
    public var mastg: [String] = []
    public var maswe: [String] = []
    public var linddun: [String] = []
    public var solove: [String] = []
    public var gdpr: [String] = []
    public var cvss: String? = nil

    static let byConstruct: [Construct: FrameworkCrosswalk] = TaxonomyLoader.crosswalk.byConstruct

    static let byVector: [String: FrameworkCrosswalk] = TaxonomyLoader.crosswalk.byVector

    public init(mastg: [String] = [], maswe: [String] = [], linddun: [String] = [],
                solove: [String] = [], gdpr: [String] = [], cvss: String? = nil) {
        self.mastg = mastg; self.maswe = maswe; self.linddun = linddun
        self.solove = solove; self.gdpr = gdpr; self.cvss = cvss
    }

    public static func `for`(vectorID: String) -> FrameworkCrosswalk {
        let vec = byVector[vectorID] ?? FrameworkCrosswalk()
        let construct = Vectors.construct(forVectorID: vectorID)
        let con = construct.flatMap { byConstruct[$0] } ?? FrameworkCrosswalk()
        return FrameworkCrosswalk(
            mastg: vec.mastg, maswe: vec.maswe,
            linddun: con.linddun, solove: con.solove,
            gdpr: Array(Set(vec.gdpr + con.gdpr)).sorted(), cvss: vec.cvss)
    }

    public static var implementedMASTGTests: Set<String> {
        Set(Vectors.all.flatMap { byVector[$0.id]?.mastg ?? [] })
    }

    public static var implementedMASWEWeaknesses: Set<String> {
        Set(Vectors.all.flatMap { byVector[$0.id]?.maswe ?? [] })
    }
}
