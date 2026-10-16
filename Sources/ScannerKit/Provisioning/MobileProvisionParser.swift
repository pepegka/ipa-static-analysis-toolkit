import Foundation

enum MobileProvisionParser {

    public static func parse(at url: URL) -> ProvisioningInfo? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let result = (try? Shell.run("/usr/bin/security", ["cms", "-D", "-i", url.path]))
        guard let result, result.exitCode == 0, !result.stdout.isEmpty else { return nil }

        guard let plist = try? PropertyListSerialization.propertyList(from: result.stdout, options: [], format: nil),
              let dict = plist as? [String: Any] else { return nil }

        let teamName = dict["TeamName"] as? String
        let teamIDs  = dict["TeamIdentifier"] as? [String] ?? []
        let appIDName = dict["AppIDName"] as? String
        let creation = dict["CreationDate"] as? Date
        let expiration = dict["ExpirationDate"] as? Date
        let provisioned = (dict["ProvisionedDevices"] as? [String])?.count
        let provisionsAllDevices = (dict["ProvisionsAllDevices"] as? Bool) ?? false
        let hasDevices = (provisioned ?? 0) > 0

        let kind: ProvisioningInfo.Kind
        if provisionsAllDevices {
            kind = .enterprise
        } else if hasDevices {
            let ents = dict["Entitlements"] as? [String: Any] ?? [:]
            let getTaskAllow = (ents["get-task-allow"] as? Bool) ?? false
            kind = getTaskAllow ? .development : .adHoc
        } else {
            kind = .appStore
        }

        var flatEnts: [String: String] = [:]
        if let ents = dict["Entitlements"] {
            PlistUtil.flatten(ents, prefix: "", into: &flatEnts)
        }

        return ProvisioningInfo(
            kind: kind, teamName: teamName, teamIDs: teamIDs,
            appIDName: appIDName, creationDate: creation, expirationDate: expiration,
            entitlements: flatEnts, provisionedDevicesCount: provisioned
        )
    }
}
