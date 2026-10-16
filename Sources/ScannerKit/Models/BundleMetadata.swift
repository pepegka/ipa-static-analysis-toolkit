import Foundation

public struct PermissionEntry: Codable, Sendable, Hashable, Identifiable {
    public var id: String { key }
    public let key: String
    public let value: String
    public let vectorID: String?
    public let category: String?
    public init(key: String, value: String, vectorID: String?, category: String?) {
        self.key = key; self.value = value; self.vectorID = vectorID; self.category = category
    }
}

public struct EmbeddedBinary: Codable, Sendable, Hashable, Identifiable {
    public var id: String { relativePath }
    public let relativePath: String
    public let name: String
    public let architectures: [String]
    public let isFairPlayEncrypted: Bool
    public let sizeBytes: UInt64
    public let linkedDylibs: [String]
    public init(relativePath: String, name: String, architectures: [String], isFairPlayEncrypted: Bool,
                sizeBytes: UInt64, linkedDylibs: [String]) {
        self.relativePath = relativePath; self.name = name
        self.architectures = architectures; self.isFairPlayEncrypted = isFairPlayEncrypted
        self.sizeBytes = sizeBytes; self.linkedDylibs = linkedDylibs
    }
}

public struct ProvisioningInfo: Codable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable {
        case appStore, enterprise, adHoc, development, unknown
    }
    public let kind: Kind
    public let teamName: String?
    public let teamIDs: [String]
    public let appIDName: String?
    public let creationDate: Date?
    public let expirationDate: Date?
    public let entitlements: [String: String]
    public let provisionedDevicesCount: Int?
    public init(kind: Kind, teamName: String?, teamIDs: [String], appIDName: String?,
                creationDate: Date?, expirationDate: Date?, entitlements: [String: String],
                provisionedDevicesCount: Int?) {
        self.kind = kind; self.teamName = teamName; self.teamIDs = teamIDs
        self.appIDName = appIDName; self.creationDate = creationDate
        self.expirationDate = expirationDate; self.entitlements = entitlements
        self.provisionedDevicesCount = provisionedDevicesCount
    }
}

public struct BundleMetadata: Codable, Sendable, Hashable {
    public let bundleID: String
    public let bundleName: String
    public let displayName: String?
    public let shortVersion: String?
    public let bundleVersion: String?
    public let minimumOSVersion: String?
    public let executableName: String?
    public let supportedPlatforms: [String]
    public let urlSchemes: [String]
    public let queriedURLSchemes: [String]
    public let backgroundModes: [String]
    public let allowsArbitraryLoads: Bool
    public let permissions: [PermissionEntry]
    public let privacyManifestPath: String?
    public let privacyTrackingDomains: [String]
    public let privacyAccessedAPIs: [String]
    public let embeddedBinaries: [EmbeddedBinary]
    public let embeddedFrameworks: [String]
    public let provisioning: ProvisioningInfo?
    public let signedTeamID: String?
    public let signedIdentifier: String?
    public var storeGenre: String? = nil
    public var contentRating: String? = nil
    public var associatedDomains: [String]? = nil
    public var privacyAccessedAPIReasons: [String]? = nil
    public var infoPlistKeys: [String]? = nil
    public init(bundleID: String, bundleName: String, displayName: String?, shortVersion: String?,
                bundleVersion: String?, minimumOSVersion: String?, executableName: String?,
                supportedPlatforms: [String], urlSchemes: [String], queriedURLSchemes: [String],
                backgroundModes: [String], allowsArbitraryLoads: Bool, permissions: [PermissionEntry],
                privacyManifestPath: String?, privacyTrackingDomains: [String],
                privacyAccessedAPIs: [String], embeddedBinaries: [EmbeddedBinary],
                embeddedFrameworks: [String], provisioning: ProvisioningInfo?,
                signedTeamID: String?, signedIdentifier: String?) {
        self.bundleID = bundleID; self.bundleName = bundleName; self.displayName = displayName
        self.shortVersion = shortVersion; self.bundleVersion = bundleVersion
        self.minimumOSVersion = minimumOSVersion; self.executableName = executableName
        self.supportedPlatforms = supportedPlatforms; self.urlSchemes = urlSchemes
        self.queriedURLSchemes = queriedURLSchemes; self.backgroundModes = backgroundModes
        self.allowsArbitraryLoads = allowsArbitraryLoads; self.permissions = permissions
        self.privacyManifestPath = privacyManifestPath
        self.privacyTrackingDomains = privacyTrackingDomains
        self.privacyAccessedAPIs = privacyAccessedAPIs
        self.embeddedBinaries = embeddedBinaries
        self.embeddedFrameworks = embeddedFrameworks
        self.provisioning = provisioning
        self.signedTeamID = signedTeamID; self.signedIdentifier = signedIdentifier
    }
}
