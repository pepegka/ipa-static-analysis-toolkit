import Foundation

public enum ConsentProvenanceAnalyzer {

    public static func analyze(metadata: BundleMetadata,
                               network: NetworkInventory,
                               indices: [String: BinaryIndex],
                               trackerDB: TrackerDB? = nil) -> [Finding] {
        var out: [Finding] = []
        out += consentIntegrity(metadata: metadata, network: network, indices: indices, trackerDB: trackerDB)
        out += trackingDomainCoverage(metadata: metadata, network: network)
        out += sdkProvenance(network: network)
        out += serverRegion(network: network)
        return out
    }

    static let advertisingCategories: Set<String> = ["advertising", "attribution"]
    static let trackingCategories: Set<String> = ["advertising", "attribution", "data_broker"]

    static func publisherOwner(bundleID: String, trackerDB: TrackerDB) -> String? {
        let labels = bundleID.lowercased().split(separator: ".")
        guard labels.count >= 2 else { return nil }
        let host = labels.reversed().joined(separator: ".")
        let domain = PublicSuffixList.registrableDomain(for: host)
        guard domain != PublicSuffixList.publicSuffix(of: host) else { return nil }
        return trackerDB.owner(host: domain)?.owner
    }

    static func consentIntegrity(metadata: BundleMetadata,
                                 network: NetworkInventory,
                                 indices: [String: BinaryIndex],
                                 trackerDB: TrackerDB? = nil) -> [Finding] {
        let publisher = trackerDB.flatMap { publisherOwner(bundleID: metadata.bundleID, trackerDB: $0) }
        let trackers = network.detectedSDKs.filter {
            $0.isTracker && trackingCategories.contains($0.category.lowercased())
                && !($0.owner == publisher && !advertisingCategories.contains($0.category.lowercased()))
        }
        guard !trackers.isEmpty else { return [] }

        let hasATTPrompt = metadata.permissions.contains { $0.key == "NSUserTrackingUsageDescription" }
            || anySymbol(indices, contains: ["ATTrackingManager", "requestTrackingAuthorization"])

        guard !hasATTPrompt else { return [] }

        let names = trackers.map(\.name).prefix(6).joined(separator: ", ")
        let ev = trackers.prefix(8).map { Evidence(kind: .symbol, value: $0.name, source: $0.frameworks.first ?? "(main)") }
        let copy = Messages.entry("TGAP-02.tracking_without_att", [
            "capability": "\(trackers.count) advertising or attribution SDK(s): \(names)",
        ])
        return [Finding(
            ruleID: "TGAP-02.tracking_without_att",
            vectorID: "TGAP-02",
            title: copy.title,
            explanation: copy.explanation,
            severity: .derived("TGAP-02.tracking_without_att", "TGAP-02"), evidences: Array(ev)).with(metrics: copy.values)]
    }

    static func trackingDomainCoverage(metadata: BundleMetadata,
                                       network: NetworkInventory) -> [Finding] {
        let declared = metadata.privacyTrackingDomains
            .map { $0.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) }
        guard metadata.privacyManifestPath != nil, !declared.isEmpty else { return [] }

        func isDeclared(_ host: String) -> Bool {
            let h = host.lowercased()
            return declared.contains { h == $0 || h.hasSuffix("." + $0) }
        }

        let undeclared = network.endpoints
            .filter { $0.isTracker && trackingCategories.contains(($0.category ?? "").lowercased()) && !isDeclared($0.host) }
            .sorted { $0.occurrenceCount > $1.occurrenceCount }
        guard !undeclared.isEmpty else { return [] }

        let owners = Set(undeclared.compactMap(\.owner)).sorted()
        let copy = Messages.entry("TGAP-01.undeclared_tracking_domains", [
            "count": String(undeclared.count),
            "s": undeclared.count == 1 ? "" : "s",
            "declared": String(declared.count),
            "owners": owners.isEmpty ? "unattributed hosts" : owners.prefix(5).joined(separator: ", "),
        ])
        return [Finding(
            ruleID: "TGAP-01.undeclared_tracking_domains",
            vectorID: "TGAP-01",
            title: copy.title,
            explanation: copy.explanation,
            severity: .derived("TGAP-01.undeclared_tracking_domains", "TGAP-01"),
            evidences: undeclared.prefix(25).map {
                Evidence(kind: .url, value: $0.host,
                         source: $0.owner.map { o in "tracker: \(o)" } ?? "tracker endpoint")
            },
            remediation: copy.remediation).with(metrics: copy.values)]
    }

    static func sdkProvenance(network: NetworkInventory) -> [Finding] {
        let trackers = network.detectedSDKs.filter(\.isTracker)
        guard !trackers.isEmpty else { return [] }
        let byOwner = Dictionary(grouping: trackers) { $0.owner.isEmpty ? $0.name : $0.owner }
        return byOwner.sorted { $0.key < $1.key }.map { owner, sdks in
            let names = sdks.map(\.name).joined(separator: ", ")
            let country = sdks.first(where: { !$0.country.isEmpty })?.country
            let copy = Messages.entry("SECH-08.sdk_owner", [
                "owner": owner,
                "countryNote": country.map { " (\($0))" } ?? "",
                "count": String(sdks.count),
                "names": names,
            ])
            return Finding(
                ruleID: "SECH-08.sdk_owner.\(owner.lowercased().replacingOccurrences(of: " ", with: "_"))",
                vectorID: "SECH-08",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("SECH-08.sdk_owner", "SECH-08"), evidences: sdks.flatMap { s in s.endpoints.prefix(2).map { Evidence(kind: .url, value: $0, source: s.frameworks.first ?? "(main)") } },
                remediation: copy.remediation).with(metrics: copy.values)
        }
    }

    static func serverRegion(network: NetworkInventory) -> [Finding] {
        let byCountry = Dictionary(grouping: network.endpoints.filter { !($0.country ?? "").isEmpty }) { $0.country! }
        guard !byCountry.isEmpty else { return [] }
        return byCountry.sorted { $0.value.count > $1.value.count }.prefix(12).map { country, eps in
            let hosts = eps.map(\.host)
            let owners = Set(eps.compactMap(\.owner)).sorted().prefix(4).joined(separator: ", ")
            let trackerClass = eps.contains { $0.isTracker }
            let copy = Messages.entry("TRK-04.egress", [
                "country": country,
                "count": String(eps.count),
                "s": eps.count == 1 ? "" : "s",
                "ownersNote": owners.isEmpty ? "" : ", owners: \(owners)",
                "adequacyNote": (Regions.gdprAdequateOrEEA.contains(country.uppercased())
                    ? " \(country) holds an EU adequacy decision, so a transfer there needs no additional Chapter V safeguard."
                    : " \(country) holds no EU adequacy decision, so a transfer there needs an Art. 46 safeguard or an Art. 49 derogation.")
                    + (trackerClass ? " Tracker-class endpoints are among the destinations." : ""),
            ])
            return Finding(
                ruleID: "TRK-04.egress.\(country.lowercased())",
                vectorID: "TRK-04",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("TRK-04.egress", "TRK-04"), evidences: hosts.prefix(10).map { Evidence(kind: .url, value: $0, source: "network") }).with(metrics: copy.values)
        }
    }

    static func anySymbol(_ indices: [String: BinaryIndex], contains needles: [String]) -> Bool {
        for idx in indices.values {
            for s in idx.importedSymbols where needles.contains(where: { s.contains($0) }) { return true }
            for s in idx.definedSymbols where needles.contains(where: { s.contains($0) }) { return true }
        }
        return false
    }
}
