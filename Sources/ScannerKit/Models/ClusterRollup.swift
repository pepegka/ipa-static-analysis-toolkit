public enum FindingCluster: Hashable, Sendable {
    case masvs(MASVSGroup)
    case applePolicy
    case indicators

    public var id: String {
        switch self {
        case .masvs(let g):  return g.rawValue
        case .applePolicy:   return "APPLE-POLICY"
        case .indicators:    return "INDICATORS"
        }
    }

    public var title: String {
        switch self {
        case .masvs(let g):  return g.title
        case .applePolicy:   return "Apple policy"
        case .indicators:    return "Indicators outside MASVS"
        }
    }

    public var blurb: String {
        switch self {
        case .masvs(let g):  return g.blurb
        case .applePolicy:
            return "App Store obligations: privacy-manifest declarations, tracking domains, ATT consent and the kids category."
        case .indicators:
            return "Observations no MASWE weakness or MASTG test describes. Each cites its own source: Apple documentation or published research."
        }
    }

    public static let allOrdered: [FindingCluster] =
        MASVSGroup.allOrdered.map(FindingCluster.masvs) + [.applePolicy, .indicators]

    public static func of(_ f: Finding) -> FindingCluster? {
        if Vectors.construct(forVectorID: f.vectorID) == .TGAP { return .applePolicy }
        if f.maswe.isEmpty && f.mastg.isEmpty { return .indicators }
        var groups = Set(f.maswe.compactMap(MASWECatalog.group))
        if groups.isEmpty { groups = Set(f.mastg.compactMap { MASTGCatalog.test($0)?.group }) }
        let vectorGroup = Vectors.group(forVectorID: f.vectorID)
        if let vg = vectorGroup, groups.isEmpty || groups.contains(vg) { return .masvs(vg) }
        return MASVSGroup.allOrdered.first(where: groups.contains).map(FindingCluster.masvs)
    }
}

public struct ClusterSummary: Sendable, Identifiable, Hashable {
    public let id: String
    public let title: String
    public let findingCount: Int
    public let severityCounts: [Severity: Int]
    public let children: [ClusterSummary]
    public let url: String?

    public init(id: String, title: String, findingCount: Int,
                severityCounts: [Severity: Int], children: [ClusterSummary] = [],
                url: String? = nil) {
        self.id = id; self.title = title; self.findingCount = findingCount
        self.severityCounts = severityCounts; self.children = children; self.url = url
    }

    public var maxSeverity: Severity {
        severityCounts.filter { $0.value > 0 }.keys.max() ?? .info
    }

    public func count(_ s: Severity) -> Int { severityCounts[s] ?? 0 }
}

public extension Collection where Element == Finding {

    func clusterRollup() -> [ClusterSummary] {
        var byCluster: [FindingCluster: [Finding]] = [:]
        for f in self where f.polarity != .defensive {
            guard let c = FindingCluster.of(f) else { continue }
            byCluster[c, default: []].append(f)
        }
        return FindingCluster.allOrdered.compactMap { cluster in
            guard let fs = byCluster[cluster], !fs.isEmpty else { return nil }

            var weakness: [String: [Finding]] = [:]
            for f in fs where f.countsAsWeakness {
                for id in f.maswe {
                    weakness[id, default: []].append(f)
                }
            }
            let children = weakness
                .map { id, wfs in
                    ClusterSummary(id: id,
                                   title: MASWECatalog.title(id) ?? id,
                                   findingCount: wfs.count,
                                   severityCounts: Self.tally(wfs),
                                   url: MASWECatalog.url(id))
                }
                .sorted {
                    $0.findingCount != $1.findingCount
                        ? $0.findingCount > $1.findingCount
                        : $0.id < $1.id
                }

            return ClusterSummary(id: cluster.id, title: cluster.title,
                                  findingCount: fs.count,
                                  severityCounts: Self.tally(fs),
                                  children: children)
        }
    }

    private static func tally(_ fs: [Finding]) -> [Severity: Int] {
        var out: [Severity: Int] = [:]
        for f in fs { out[f.severity, default: 0] += 1 }
        return out
    }
}

public struct MitigationSummary: Sendable, Identifiable, Hashable {
    public let id: String
    public let title: String
    public let url: String?
    public let findings: [Finding]
}

public extension Collection where Element == Finding {

    func mitigationRollup() -> [MitigationSummary] {
        var by: [String: [Finding]] = [:]
        for f in self where f.polarity == .defensive {
            for id in f.maswe { by[id, default: []].append(f) }
        }
        return by.keys.sorted().map { id in
            MitigationSummary(id: id, title: MASWECatalog.title(id) ?? id,
                              url: MASWECatalog.url(id), findings: by[id] ?? [])
        }
    }
}

public struct ControlSummary: Sendable, Identifiable, Hashable {
    public let id: String
    public let statement: String
    public let url: String?
    public let findingCount: Int
    public let severityCounts: [Severity: Int]

    public var maxSeverity: Severity { severityCounts.filter { $0.value > 0 }.keys.max() ?? .info }
    public func count(_ s: Severity) -> Int { severityCounts[s] ?? 0 }
}

public extension Collection where Element == Finding {

    func controlRollup() -> [ControlSummary] {
        var byControl: [String: [Finding]] = [:]
        for f in self where f.countsAsWeakness { for c in f.masvsControls { byControl[c, default: []].append(f) } }
        let masvsOrder = ["STORAGE", "CRYPTO", "AUTH", "NETWORK", "PLATFORM", "CODE", "RESILIENCE", "PRIVACY"]
        func order(_ id: String) -> (Int, Int) {
            let parts = id.split(separator: "-")
            let group = parts.count == 3 ? masvsOrder.firstIndex(of: String(parts[1])) ?? 99 : 99
            return (group, Int(parts.last ?? "") ?? 0)
        }
        return byControl.keys.sorted { order($0) < order($1) }.map { id in
            let fs = byControl[id] ?? []
            var tally: [Severity: Int] = [:]
            for f in fs { tally[f.severity, default: 0] += 1 }
            let c = MASVSCatalog.control(id)
            return ControlSummary(id: id, statement: c?.statement ?? "", url: c?.url,
                                  findingCount: fs.count, severityCounts: tally)
        }
    }
}
