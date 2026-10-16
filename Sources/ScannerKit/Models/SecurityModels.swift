import Foundation

public struct BinaryHardening: Codable, Sendable, Hashable, Identifiable {
    public var id: String { relativePath }
    public let relativePath: String
    public let name: String
    public let architectures: [String]
    public let isEncrypted: Bool
    public let hasPIE: Bool
    public let hasStackCanary: Bool?
    public let hasARC: Bool?

    public init(relativePath: String, name: String, architectures: [String],
                isEncrypted: Bool, hasPIE: Bool, hasStackCanary: Bool?, hasARC: Bool?) {
        self.relativePath = relativePath; self.name = name
        self.architectures = architectures; self.isEncrypted = isEncrypted
        self.hasPIE = hasPIE; self.hasStackCanary = hasStackCanary; self.hasARC = hasARC
    }

    public var isAnalysable: Bool {
        hasStackCanary != nil || hasARC != nil || isEncrypted || hasPIE
    }
}

public struct ATSDomain: Codable, Sendable, Hashable, Identifiable {
    public var id: String { domain }
    public let domain: String
    public let includesSubdomains: Bool
    public let allowsInsecureHTTPLoads: Bool
    public let minimumTLSVersion: String?
    public let requiresForwardSecrecy: Bool?
    public init(domain: String, includesSubdomains: Bool, allowsInsecureHTTPLoads: Bool,
                minimumTLSVersion: String?, requiresForwardSecrecy: Bool?) {
        self.domain = domain; self.includesSubdomains = includesSubdomains
        self.allowsInsecureHTTPLoads = allowsInsecureHTTPLoads
        self.minimumTLSVersion = minimumTLSVersion
        self.requiresForwardSecrecy = requiresForwardSecrecy
    }
}

public struct ATSConfig: Codable, Sendable, Hashable {
    public let allowsArbitraryLoads: Bool
    public let allowsArbitraryLoadsInWebContent: Bool
    public let allowsArbitraryLoadsForMedia: Bool
    public let allowsLocalNetworking: Bool
    public let exceptionDomains: [ATSDomain]
    public static let empty = ATSConfig(allowsArbitraryLoads: false,
                                        allowsArbitraryLoadsInWebContent: false,
                                        allowsArbitraryLoadsForMedia: false,
                                        allowsLocalNetworking: false,
                                        exceptionDomains: [])
    public init(allowsArbitraryLoads: Bool, allowsArbitraryLoadsInWebContent: Bool,
                allowsArbitraryLoadsForMedia: Bool, allowsLocalNetworking: Bool,
                exceptionDomains: [ATSDomain]) {
        self.allowsArbitraryLoads = allowsArbitraryLoads
        self.allowsArbitraryLoadsInWebContent = allowsArbitraryLoadsInWebContent
        self.allowsArbitraryLoadsForMedia = allowsArbitraryLoadsForMedia
        self.allowsLocalNetworking = allowsLocalNetworking
        self.exceptionDomains = exceptionDomains
    }
}

public struct SecretHit: Codable, Sendable, Hashable, Identifiable {
    public var id: String { "\(type)|\(source)|\(redactedValue)" }
    public let type: String
    public let redactedValue: String
    public let entropy: Double
    public let severity: Severity
    public let source: String
    public let section: String?
    public var credentialClass: String? = nil
    public var publicIdentifier: Bool? = nil
    public var publicReason: String? = nil
    public var isCredential: Bool { publicIdentifier != true && severity > .info }
    public init(type: String, redactedValue: String, entropy: Double, severity: Severity,
                source: String, section: String?) {
        self.type = type; self.redactedValue = redactedValue; self.entropy = entropy
        self.severity = severity; self.source = source; self.section = section
    }
}

public struct FileManifestEntry: Codable, Sendable, Hashable, Identifiable {
    public var id: String { relativePath }
    public let relativePath: String
    public let name: String
    public let sizeBytes: UInt64
    public let kind: String
    public let sha256: String?
    public let isSuspicious: Bool
    public let suspicionReason: String?
    public init(relativePath: String, name: String, sizeBytes: UInt64, kind: String,
                sha256: String?, isSuspicious: Bool, suspicionReason: String?) {
        self.relativePath = relativePath; self.name = name; self.sizeBytes = sizeBytes
        self.kind = kind; self.sha256 = sha256
        self.isSuspicious = isSuspicious; self.suspicionReason = suspicionReason
    }
}
