import Foundation

struct SarifLog: Codable, Sendable {
    let version = "2.1.0"
    let schema = "https://json.schemastore.org/sarif-2.1.0.json"
    let runs: [SarifRun]
    enum CodingKeys: String, CodingKey {
        case version, runs
        case schema = "$schema"
    }
}

struct SarifRun: Codable, Sendable {
    let tool: SarifTool
    var taxonomies: [SarifToolComponent]? = nil
    let results: [SarifResult]
    var properties: SarifPropertyBag? = nil
    init(tool: SarifTool, taxonomies: [SarifToolComponent]? = nil,
                results: [SarifResult], properties: SarifPropertyBag? = nil) {
        self.tool = tool; self.taxonomies = taxonomies
        self.results = results; self.properties = properties
    }
}

struct SarifToolComponent: Codable, Sendable {
    let name: String
    let guid: String?
    var version: String? = nil
    let informationUri: String?
    let isComprehensive: Bool?
    let taxa: [SarifTaxon]
    init(name: String, guid: String? = nil, version: String? = nil, informationUri: String? = nil,
                isComprehensive: Bool? = nil, taxa: [SarifTaxon]) {
        self.name = name; self.guid = guid; self.version = version; self.informationUri = informationUri
        self.isComprehensive = isComprehensive; self.taxa = taxa
    }
}

struct SarifTaxon: Codable, Sendable {
    let id: String
    var name: String? = nil
    let shortDescription: SarifMessage?
    var helpUri: String? = nil
    init(id: String, name: String? = nil, shortDescription: SarifMessage? = nil, helpUri: String? = nil) {
        self.id = id; self.name = name; self.shortDescription = shortDescription; self.helpUri = helpUri
    }
}

struct SarifRelationship: Codable, Sendable {
    let target: SarifDescriptorReference
    let kinds: [String]
    init(target: SarifDescriptorReference, kinds: [String]) { self.target = target; self.kinds = kinds }
}

struct SarifDescriptorReference: Codable, Sendable {
    let id: String
    let toolComponent: SarifToolComponentReference
    init(id: String, toolComponent: SarifToolComponentReference) {
        self.id = id; self.toolComponent = toolComponent
    }
}

struct SarifToolComponentReference: Codable, Sendable {
    let name: String
    let guid: String?
    init(name: String, guid: String? = nil) { self.name = name; self.guid = guid }
}

struct SarifTool: Codable, Sendable {
    let driver: SarifDriver
}

struct SarifDriver: Codable, Sendable {
    let name: String
    var informationUri: String? = nil
    let semanticVersion: String
    let rules: [SarifReportingDescriptor]
}

struct SarifReportingDescriptor: Codable, Sendable {
    let id: String
    let name: String
    let shortDescription: SarifMessage
    let fullDescription: SarifMessage
    var relationships: [SarifRelationship]? = nil
    let properties: SarifPropertyBag?
    init(id: String, name: String, shortDescription: SarifMessage, fullDescription: SarifMessage,
                relationships: [SarifRelationship]? = nil, properties: SarifPropertyBag?) {
        self.id = id; self.name = name; self.shortDescription = shortDescription
        self.fullDescription = fullDescription; self.relationships = relationships
        self.properties = properties
    }
}

struct SarifResult: Codable, Sendable {
    let ruleId: String
    let level: String
    let message: SarifMessage
    let locations: [SarifLocation]?
    let partialFingerprints: [String: String]?
    var taxa: [SarifDescriptorReference]? = nil
    let properties: SarifPropertyBag?
}

struct SarifMessage: Codable, Sendable {
    let text: String
}

struct SarifLocation: Codable, Sendable {
    let physicalLocation: SarifPhysicalLocation
}

struct SarifPhysicalLocation: Codable, Sendable {
    let artifactLocation: SarifArtifactLocation
}

struct SarifArtifactLocation: Codable, Sendable {
    let uri: String
}

struct SarifPropertyBag: Codable, Sendable {
    let tags: [String]?
    let additional: [String: String]

    init(tags: [String]?, additional: [String: String]) {
        self.tags = tags; self.additional = additional
    }

    private struct DynKey: CodingKey {
        var stringValue: String; var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
        init(_ s: String) { self.stringValue = s }
    }

    func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: DynKey.self)
        if let tags { try c.encode(tags, forKey: DynKey("tags")) }
        for (k, v) in additional where k != "tags" {
            try c.encode(v, forKey: DynKey(k))
        }
    }

    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: DynKey.self)
        var tags: [String]? = nil
        var extra: [String: String] = [:]
        for key in c.allKeys {
            if key.stringValue == "tags" {
                tags = try? c.decode([String].self, forKey: key)
            } else if let v = try? c.decode(String.self, forKey: key) {
                extra[key.stringValue] = v
            }
        }
        self.tags = tags; self.additional = extra
    }
}
