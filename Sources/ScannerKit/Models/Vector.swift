import Foundation

public enum MASVSGroup: String, Codable, Sendable, Hashable, CaseIterable, Identifiable {
    case storage    = "MASVS-STORAGE"
    case crypto     = "MASVS-CRYPTO"
    case auth       = "MASVS-AUTH"
    case network    = "MASVS-NETWORK"
    case platform   = "MASVS-PLATFORM"
    case code       = "MASVS-CODE"
    case resilience = "MASVS-RESILIENCE"
    case privacy    = "MASVS-PRIVACY"

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .storage:    return "Storage"
        case .crypto:     return "Cryptography"
        case .auth:       return "Authentication"
        case .network:    return "Network"
        case .platform:   return "Platform"
        case .code:       return "Code quality"
        case .resilience: return "Resilience"
        case .privacy:    return "Privacy"
        }
    }

    public var blurb: String {
        switch self {
        case .storage:    return "Local data at rest: files, databases, Keychain."
        case .crypto:     return "Cryptographic primitives, modes and key handling."
        case .auth:       return "Authentication and authorization mechanisms."
        case .network:    return "Transport security and server communication."
        case .platform:   return "Platform APIs, IPC, WebViews and background execution."
        case .code:       return "Build settings, hardening and embedded secrets."
        case .resilience: return "Anti-tampering, anti-analysis and malware indicators."
        case .privacy:    return "Data collection, tracking, fingerprinting and exfiltration."
        }
    }

    public static let allOrdered: [MASVSGroup] =
        [.privacy, .network, .storage, .crypto, .platform, .code, .resilience, .auth]
}

public struct Vector: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let construct: Construct
    public let title: String
    public let description: String
    public let group: MASVSGroup
    public let mitre: [String]

    public init(id: String, construct: Construct, title: String, description: String,
                group: MASVSGroup, mitre: [String] = []) {
        self.id = id; self.construct = construct; self.title = title; self.description = description
        self.group = group; self.mitre = mitre
    }

    public var userAdvice: String { Vectors.userAdvice[id] ?? "" }
}

public enum Vectors {
    public static let all: [Vector] = TaxonomyLoader.vectors.map {
        Vector(id: $0.id, construct: $0.construct, title: $0.title,
               description: $0.description, group: $0.group, mitre: $0.mitre)
    }

    public static let userAdvice: [String: String] = Dictionary(
        uniqueKeysWithValues: TaxonomyLoader.vectors.map { ($0.id, $0.userAdvice) })

    public static let byID: [String: Vector] = Dictionary(uniqueKeysWithValues: all.map { ($0.id, $0) })

    public static let byGroup: [MASVSGroup: [Vector]] =
        Dictionary(grouping: all, by: \.group)

    public static let byConstruct: [Construct: [Vector]] =
        Dictionary(grouping: all, by: \.construct)

    public static func group(forVectorID id: String) -> MASVSGroup? { byID[id]?.group }

    public static func construct(forVectorID id: String) -> Construct? { byID[id]?.construct }
}
