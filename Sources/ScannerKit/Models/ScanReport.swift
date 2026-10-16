import Foundation

public struct VectorSummary: Codable, Sendable, Identifiable, Hashable {
    public var id: String { vectorID }
    public let vectorID: String
    public let uniqueArtifactCount: Int
    public let maxSeverity: Severity
    public init(vectorID: String, uniqueArtifactCount: Int, maxSeverity: Severity) {
        self.vectorID = vectorID; self.uniqueArtifactCount = uniqueArtifactCount
        self.maxSeverity = maxSeverity
    }
    enum CodingKeys: String, CodingKey { case vectorID, uniqueArtifactCount, maxSeverity }
    public init(from d: any Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        vectorID = try c.decode(String.self, forKey: .vectorID)
        uniqueArtifactCount = try c.decode(Int.self, forKey: .uniqueArtifactCount)
        maxSeverity = try c.decode(Severity.self, forKey: .maxSeverity)
    }
}

public struct ScanCoverage: Codable, Sendable, Hashable {
    public let binaries: Int
    public let binariesWithReadableText: Int
    public let stringOnlyRules: [String]
    public init(binaries: Int, binariesWithReadableText: Int, stringOnlyRules: [String]) {
        self.binaries = binaries; self.binariesWithReadableText = binariesWithReadableText
        self.stringOnlyRules = stringOnlyRules
    }
}

public struct ScanReport: Codable, Sendable, Identifiable, Hashable {
    public let id: UUID
    public let createdAt: Date
    public let sourceIPAPath: String
    public let metadata: BundleMetadata
    public let findings: [Finding]
    public let vectorSummaries: [VectorSummary]
    public let scanDurationSeconds: Double
    public let notes: [String]
    public var network: NetworkInventory
    public var hardening: [BinaryHardening]
    public var secrets: [SecretHit]
    public var ats: ATSConfig
    public var fileManifest: [FileManifestEntry]
    public var frameworks: FrameworkVersions = .current
    public var coverage: ScanCoverage? = nil

    public init(id: UUID = UUID(), createdAt: Date = .now, sourceIPAPath: String,
                metadata: BundleMetadata, findings: [Finding], vectorSummaries: [VectorSummary],
                scanDurationSeconds: Double, notes: [String],
                network: NetworkInventory = .empty,
                hardening: [BinaryHardening] = [], secrets: [SecretHit] = [],
                ats: ATSConfig = .empty, fileManifest: [FileManifestEntry] = [],
                frameworks: FrameworkVersions = .current,
                coverage: ScanCoverage? = nil) {
        self.id = id; self.createdAt = createdAt; self.sourceIPAPath = sourceIPAPath
        self.metadata = metadata; self.findings = findings
        self.vectorSummaries = vectorSummaries
        self.scanDurationSeconds = scanDurationSeconds; self.notes = notes
        self.network = network
        self.hardening = hardening; self.secrets = secrets
        self.ats = ats; self.fileManifest = fileManifest
        self.frameworks = frameworks
        self.coverage = coverage
    }

    enum CodingKeys: String, CodingKey {
        case id, createdAt, sourceIPAPath, metadata, findings, vectorSummaries
        case scanDurationSeconds, notes, network
        case hardening, secrets, ats, fileManifest, frameworks, coverage
    }
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.id = try c.decode(UUID.self, forKey: .id)
        self.createdAt = try c.decode(Date.self, forKey: .createdAt)
        self.sourceIPAPath = try c.decode(String.self, forKey: .sourceIPAPath)
        self.metadata = try c.decode(BundleMetadata.self, forKey: .metadata)
        self.findings = try c.decode([Finding].self, forKey: .findings)
        self.vectorSummaries = try c.decode([VectorSummary].self, forKey: .vectorSummaries)
        self.scanDurationSeconds = try c.decode(Double.self, forKey: .scanDurationSeconds)
        self.notes = try c.decode([String].self, forKey: .notes)
        self.network = try c.decodeIfPresent(NetworkInventory.self, forKey: .network) ?? .empty
        self.hardening = try c.decodeIfPresent([BinaryHardening].self, forKey: .hardening) ?? []
        self.secrets = try c.decodeIfPresent([SecretHit].self, forKey: .secrets) ?? []
        self.ats = try c.decodeIfPresent(ATSConfig.self, forKey: .ats) ?? .empty
        self.fileManifest = try c.decodeIfPresent([FileManifestEntry].self, forKey: .fileManifest) ?? []
        self.frameworks = try c.decodeIfPresent(FrameworkVersions.self, forKey: .frameworks) ?? .current
        self.coverage = try c.decodeIfPresent(ScanCoverage.self, forKey: .coverage)
    }
}

public struct GroupSummary: Sendable, Identifiable, Hashable {
    public var id: String { group.rawValue }
    public let group: MASVSGroup
    public let hitCount: Int
    public let maxSeverity: Severity
}

public extension ScanReport {
    func masvsRollup() -> [GroupSummary] {
        var hits: [MASVSGroup: Int] = [:]
        var sev: [MASVSGroup: Severity] = [:]
        for f in findings where f.polarity != .defensive {
            guard case .masvs(let g)? = FindingCluster.of(f) else { continue }
            hits[g, default: 0] += 1
            sev[g] = max(sev[g] ?? .info, f.severity)
        }
        return MASVSGroup.allOrdered.compactMap { g in
            guard let c = hits[g], c > 0 else { return nil }
            return GroupSummary(group: g, hitCount: c, maxSeverity: sev[g] ?? .info)
        }
    }
}
