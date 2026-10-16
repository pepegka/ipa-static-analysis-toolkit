import Foundation

enum AppDetailSection {
    case summary([(label: String, value: String, code: Bool)])
    case permissions([PermissionEntry])
    case identifiers(title: String, values: [String])
    case entitlements([String: String])
    case privacyManifest(path: String?, accessedAPIs: [String], trackingDomains: [String])
    case binaries([EmbeddedBinary])
    case frameworks([String])

    static func all(_ m: BundleMetadata) -> [AppDetailSection] {
        var out: [AppDetailSection] = []

        var summary: [(label: String, value: String, code: Bool)] = []
        if !m.supportedPlatforms.isEmpty {
            summary.append(("Platforms", m.supportedPlatforms.joined(separator: ", "), false))
        }
        if let e = m.executableName { summary.append(("Executable", e, true)) }
        if let t = m.signedTeamID { summary.append(("Signed team ID", t, true)) }
        if let id = m.signedIdentifier { summary.append(("Signed identifier", id, true)) }
        if let p = m.provisioning {
            var line = p.kind.rawValue
            if let tn = p.teamName { line += " · \(tn)" }
            if let exp = p.expirationDate { line += " · expires \(ISO8601DateFormatter().string(from: exp))" }
            if let dc = p.provisionedDevicesCount { line += " · \(dc) devices" }
            summary.append(("Provisioning", line, false))
        }
        if !summary.isEmpty { out.append(.summary(summary)) }

        if !m.permissions.isEmpty { out.append(.permissions(m.permissions)) }
        for (title, values) in [("Registered URL schemes", m.urlSchemes),
                                ("Queried URL schemes", m.queriedURLSchemes),
                                ("Background modes", m.backgroundModes)] where !values.isEmpty {
            out.append(.identifiers(title: title, values: values))
        }
        if let ents = m.provisioning?.entitlements, !ents.isEmpty { out.append(.entitlements(ents)) }
        if m.privacyManifestPath != nil || !m.privacyAccessedAPIs.isEmpty || !m.privacyTrackingDomains.isEmpty {
            out.append(.privacyManifest(path: m.privacyManifestPath,
                                        accessedAPIs: m.privacyAccessedAPIs,
                                        trackingDomains: m.privacyTrackingDomains))
        }
        if !m.embeddedBinaries.isEmpty { out.append(.binaries(m.embeddedBinaries)) }
        if !m.embeddedFrameworks.isEmpty { out.append(.frameworks(m.embeddedFrameworks)) }
        return out
    }
}
