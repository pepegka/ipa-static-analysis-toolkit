import Foundation

public struct ClassifiedEndpoint: Codable, Sendable, Hashable, Identifiable {
    public var id: String { host }
    public let host: String
    public let registrableDomain: String
    public let trackerID: String?
    public let owner: String?
    public let country: String?
    public let category: String?
    public let isTracker: Bool
    public let occurrenceCount: Int
    public let sources: [String]
    public let samplePaths: [String]
    public let samplePlistKeys: [String]
    public var cleartext: Bool?
    public var firstParty: Bool?

    public init(host: String, registrableDomain: String,
                trackerID: String?, owner: String?, country: String?, category: String?,
                isTracker: Bool, occurrenceCount: Int,
                sources: [String], samplePaths: [String], samplePlistKeys: [String],
                cleartext: Bool? = nil, firstParty: Bool? = nil) {
        self.host = host; self.registrableDomain = registrableDomain
        self.trackerID = trackerID; self.owner = owner; self.country = country
        self.category = category; self.isTracker = isTracker
        self.occurrenceCount = occurrenceCount
        self.sources = sources; self.samplePaths = samplePaths
        self.samplePlistKeys = samplePlistKeys
        self.firstParty = firstParty
        self.cleartext = cleartext
    }
}

public struct DetectedSDK: Codable, Sendable, Hashable, Identifiable {
    public var id: String { trackerID }
    public let trackerID: String
    public let name: String
    public let owner: String
    public let country: String
    public let category: String
    public let isTracker: Bool
    public let evidenceCount: Int
    public let endpoints: [String]
    public let frameworks: [String]
    public var plistKeys: [String]? = nil
    public init(trackerID: String, name: String, owner: String, country: String,
                category: String, isTracker: Bool, evidenceCount: Int,
                endpoints: [String], frameworks: [String], plistKeys: [String]? = nil) {
        self.trackerID = trackerID; self.name = name; self.owner = owner
        self.country = country; self.category = category; self.isTracker = isTracker
        self.evidenceCount = evidenceCount; self.endpoints = endpoints
        self.frameworks = frameworks
        self.plistKeys = plistKeys
    }
}

public struct NetworkInventory: Codable, Sendable, Hashable {
    public let endpoints: [ClassifiedEndpoint]
    public let detectedSDKs: [DetectedSDK]
    public var hostsBeforeCap: Int? = nil
    public init(endpoints: [ClassifiedEndpoint], detectedSDKs: [DetectedSDK]) {
        self.endpoints = endpoints
        self.detectedSDKs = detectedSDKs
    }
    public static let empty = NetworkInventory(endpoints: [], detectedSDKs: [])
}
