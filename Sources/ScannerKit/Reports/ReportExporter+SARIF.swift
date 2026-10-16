import Foundation

extension ReportExporter {

    public static func sarifData(_ report: ScanReport) throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try enc.encode(sarif(report))
    }

    static func sarifLevel(_ sev: Severity) -> String {
        switch sev {
        case .info: return "note"
        case .low, .medium: return "warning"
        case .high, .critical: return "error"
        }
    }

    static let sarifTaxonomyMeta: [(key: String, name: String, guid: String, uri: String)] = [
        ("maswe", "MASWE", "6f9a1c40-0000-4000-a000-0000000000a1", "https://mas.owasp.org/MASWE/"),
        ("mastg", "MASTG", "6f9a1c40-0000-4000-a000-0000000000a2", "https://mas.owasp.org/MASTG/"),
        ("cwe",   "CWE",   "6f9a1c40-0000-4000-a000-0000000000a3", "https://cwe.mitre.org/"),
        ("masvs", "MASVS", "6f9a1c40-0000-4000-a000-0000000000a4", "https://mas.owasp.org/MASVS/"),
    ]

    static func publishedCWE(_ maswe: [String]) -> [String] {
        Array(Set(maswe.compactMap(MASWECatalog.entry).flatMap(\.cwe))).sorted()
    }

    static func refs(_ key: String, _ ids: [String]) -> [FrameworkRef] {
        switch key {
        case "maswe": return FrameworkLinks.maswe(ids)
        case "mastg": return FrameworkLinks.mastg(ids)
        case "cwe":   return FrameworkLinks.cwe(ids)
        default:      return FrameworkLinks.masvsControls(ids)
        }
    }

    static func ids(_ f: Finding, _ key: String) -> [String] {
        switch key {
        case "maswe": return f.maswe
        case "mastg": return f.mastg
        case "cwe":   return f.cwe
        default:      return f.masvsControls
        }
    }

    static func sarif(_ report: ScanReport) -> SarifLog {
        var taxaByKey: [String: Set<String>] = ["maswe": [], "mastg": [], "cwe": [], "masvs": []]
        for v in Vectors.all {
            let cw = FrameworkCrosswalk.for(vectorID: v.id)
            taxaByKey["maswe"]!.formUnion(cw.maswe)
            taxaByKey["mastg"]!.formUnion(cw.mastg)
            taxaByKey["cwe"]!.formUnion(Self.publishedCWE(cw.maswe))
        }
        for f in report.findings {
            for key in taxaByKey.keys { taxaByKey[key]!.formUnion(ids(f, key)) }
        }
        let versions = ["maswe": report.frameworks.maswe, "mastg": report.frameworks.mastg,
                        "masvs": report.frameworks.masvs]
        let taxonomies: [SarifToolComponent] = sarifTaxonomyMeta.compactMap { meta in
            let all = (taxaByKey[meta.key] ?? []).sorted()
            guard !all.isEmpty else { return nil }
            return SarifToolComponent(name: meta.name, guid: meta.guid, version: versions[meta.key],
                                      informationUri: meta.uri, isComprehensive: false,
                                      taxa: refs(meta.key, all).map {
                                          SarifTaxon(id: $0.id, name: $0.title,
                                                     shortDescription: nil, helpUri: $0.url)
                                      })
        }

        let rules: [SarifReportingDescriptor] = Vectors.all.map { v in
            let cw = FrameworkCrosswalk.for(vectorID: v.id)
            var rels: [SarifRelationship] = []
            for id in cw.maswe { rels.append(.init(target: .init(id: id, toolComponent: .init(name: "MASWE", guid: "6f9a1c40-0000-4000-a000-0000000000a1")), kinds: ["relevant"])) }
            for id in cw.mastg { rels.append(.init(target: .init(id: id, toolComponent: .init(name: "MASTG", guid: "6f9a1c40-0000-4000-a000-0000000000a2")), kinds: ["relevant"])) }
            for id in Self.publishedCWE(cw.maswe) { rels.append(.init(target: .init(id: id, toolComponent: .init(name: "CWE",   guid: "6f9a1c40-0000-4000-a000-0000000000a3")), kinds: ["superset"])) }
            return SarifReportingDescriptor(
                id: v.id,
                name: v.id,
                shortDescription: .init(text: v.title),
                fullDescription: .init(text: v.description),
                relationships: rels.isEmpty ? nil : rels,
                properties: SarifPropertyBag(
                    tags: ["security", v.construct.rawValue, v.group.rawValue] + v.mitre,
                    additional: ["construct": v.construct.rawValue, "masvs-group": v.group.rawValue,
                                 "code": v.id]))
        }

        let results: [SarifResult] = report.findings.map { f in
            var sources = f.affectedBinaries
            if sources.isEmpty {
                var seen = Set<String>()
                sources = f.evidences.map(\.source).filter { seen.insert($0).inserted }
            }
            let locations = sources.map { src in
                SarifLocation(physicalLocation: .init(artifactLocation: .init(uri: src)))
            }
            var props: [String: String] = [
                "ruleID": f.ruleID,
                "severity": f.severity.rawValue,
            ]
            if !f.mitre.isEmpty { props["mitre"] = f.mitre.joined(separator: ", ") }
            if !f.masvs.isEmpty { props["masvs"] = f.masvs.joined(separator: ", ") }
            if !f.mastg.isEmpty { props["mastg"] = f.mastg.joined(separator: ", ") }
            if !f.maswe.isEmpty { props["maswe"] = f.maswe.joined(separator: ", ") }
            if !f.cwe.isEmpty { props["cwe"] = f.cwe.joined(separator: ", ") }
            if !f.linddun.isEmpty { props["linddun"] = f.linddun.joined(separator: ", ") }
            if !f.solove.isEmpty { props["solove"] = f.solove.joined(separator: ", ") }
            if !f.gdpr.isEmpty { props["gdpr"] = f.gdpr.joined(separator: ", ") }
            if let cvss = f.cvss {
                props["cvss"] = cvss
                if cvss.hasPrefix("CVSS:4.0/") { props["cvssV4"] = cvss }
            }
            if let why = f.why, !why.isEmpty { props["severityRationale"] = why }
            if let rem = f.remediation, !rem.isEmpty { props["remediation"] = rem }
            if !f.owningFrameworks.isEmpty {
                props["frameworks"] = f.owningFrameworks.joined(separator: ", ")
            }
            return SarifResult(
                ruleId: f.vectorID,
                level: sarifLevel(f.severity),
                message: .init(text: "\(f.title). \(f.explanation)"),
                locations: locations.isEmpty ? nil : locations,
                partialFingerprints: ["ruleID/v1": f.ruleID],
                taxa: sarifTaxonomyMeta.flatMap { meta in
                    ids(f, meta.key).map {
                        SarifDescriptorReference(id: $0, toolComponent: .init(name: meta.name, guid: meta.guid))
                    }
                }.nilIfEmpty,
                properties: SarifPropertyBag(tags: nil, additional: props))
        }

        let driver = SarifDriver(
            name: "ISAT",
            semanticVersion: "1.0.0",
            rules: rules)
        let m = report.metadata
        var runProps: [String: String] = [
            "bundleID": m.bundleID,
        ]
        for c in report.findings.clusterRollup() { runProps["cluster.\(c.id)"] = String(c.findingCount) }
        if let v = m.shortVersion { runProps["version"] = v }
        if let b = m.bundleVersion { runProps["build"] = b }
        if !m.supportedPlatforms.isEmpty { runProps["platforms"] = m.supportedPlatforms.joined(separator: ", ") }
        if let t = m.signedTeamID { runProps["signedTeamID"] = t }
        runProps["frameworks.masvs"] = report.frameworks.masvs
        runProps["frameworks.mastg"] = report.frameworks.mastg
        runProps["frameworks.maswe"] = report.frameworks.maswe
        runProps["frameworks.attackMobile"] = report.frameworks.attackMobile
        return SarifLog(runs: [SarifRun(tool: .init(driver: driver),
                                        taxonomies: taxonomies.isEmpty ? nil : taxonomies,
                                        results: results,
                                        properties: SarifPropertyBag(tags: nil, additional: runProps))])
    }
}

private extension Array {
    var nilIfEmpty: [Element]? { isEmpty ? nil : self }
}
