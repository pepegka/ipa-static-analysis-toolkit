import Foundation

public enum CycloneDXExporter {

    public static func data(_ report: ScanReport) throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        enc.dateEncodingStrategy = .iso8601
        return try enc.encode(bom(report))
    }

    static func bom(_ report: ScanReport) -> CycloneDXBOM {
        let m = report.metadata
        let appRef = "app:\(m.bundleID)"
        let appComponent = CDXComponent(
            type: "application", bomRef: appRef, name: m.bundleID,
            version: m.shortVersion, group: nil, publisher: m.signedTeamID, purl: nil,
            properties: [CDXProperty(name: "isat:bundleName", value: m.bundleName)]
                + (m.storeGenre.map { [CDXProperty(name: "isat:storeGenre", value: $0)] } ?? []))

        var components: [CDXComponent] = []
        for sdk in report.network.detectedSDKs.sorted(by: { $0.name < $1.name }) {
            var props: [CDXProperty] = [
                CDXProperty(name: "isat:category", value: sdk.category),
                CDXProperty(name: "isat:isTracker", value: String(sdk.isTracker)),
            ]
            if !sdk.country.isEmpty { props.append(CDXProperty(name: "isat:country", value: sdk.country)) }
            for host in sdk.endpoints.prefix(6) { props.append(CDXProperty(name: "isat:endpoint", value: host)) }
            for fw in sdk.frameworks.prefix(4) { props.append(CDXProperty(name: "isat:framework", value: fw)) }
            components.append(CDXComponent(
                type: "library", bomRef: "sdk:\(sdk.trackerID)", name: sdk.name,
                version: nil, group: sdk.owner.isEmpty ? nil : sdk.owner,
                publisher: sdk.owner.isEmpty ? nil : sdk.owner, purl: nil, properties: props))
        }
        let sdkFrameworkNames = Set(report.network.detectedSDKs.flatMap { $0.frameworks.map { $0.replacingOccurrences(of: ".framework", with: "") } })
        for fw in m.embeddedFrameworks.sorted() where !sdkFrameworkNames.contains(fw) {
            components.append(CDXComponent(
                type: "framework", bomRef: "fw:\(fw)", name: fw,
                version: nil, group: nil, publisher: nil, purl: nil,
                properties: [CDXProperty(name: "isat:embeddedFramework", value: "true")]))
        }

        let dependsOn = components.map(\.bomRef)
        return CycloneDXBOM(
            serialNumber: "urn:uuid:\(deterministicUUID(for: m.bundleID + (m.shortVersion ?? "")))",
            metadata: CDXMetadata(timestamp: report.createdAt, component: appComponent,
                                  tools: [CDXTool(vendor: "ISAT", name: "ISAT", version: "1.0.0")]),
            components: components,
            dependencies: [CDXDependency(ref: appRef, dependsOn: dependsOn)])
    }

    static func deterministicUUID(for seed: String) -> String {
        var h: UInt64 = 1469598103934665603
        for b in seed.utf8 { h = (h ^ UInt64(b)) &* 1099511628211 }
        let hi = String(format: "%016x", h)
        let h2 = h &* 1099511628211 ^ 0xdeadbeef
        let lo = String(format: "%016x", h2)
        let s = hi + lo
        let i = s.index(s.startIndex, offsetBy: 8)
        let j = s.index(s.startIndex, offsetBy: 12)
        let k = s.index(s.startIndex, offsetBy: 16)
        let l = s.index(s.startIndex, offsetBy: 20)
        return "\(s[..<i])-\(s[i..<j])-\(s[j..<k])-\(s[k..<l])-\(s[l...])"
    }
}

struct CycloneDXBOM: Codable, Sendable {
    let bomFormat = "CycloneDX"
    let specVersion = "1.5"
    let serialNumber: String
    let version = 1
    let metadata: CDXMetadata
    let components: [CDXComponent]
    let dependencies: [CDXDependency]
    enum CodingKeys: String, CodingKey { case bomFormat, specVersion, serialNumber, version, metadata, components, dependencies }
}

struct CDXMetadata: Codable, Sendable {
    let timestamp: Date
    let component: CDXComponent
    let tools: [CDXTool]
}

struct CDXTool: Codable, Sendable {
    let vendor: String; public let name: String; public let version: String
}

struct CDXComponent: Codable, Sendable {
    let type: String
    let bomRef: String
    let name: String
    let version: String?
    let group: String?
    let publisher: String?
    let purl: String?
    let properties: [CDXProperty]
    enum CodingKeys: String, CodingKey {
        case type, name, version, group, publisher, purl, properties
        case bomRef = "bom-ref"
    }
}

struct CDXProperty: Codable, Sendable {
    let name: String; public let value: String
}

struct CDXDependency: Codable, Sendable {
    let ref: String
    let dependsOn: [String]
}
