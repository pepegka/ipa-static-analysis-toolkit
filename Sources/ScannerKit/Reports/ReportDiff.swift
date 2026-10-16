import Foundation

public enum ReportDiff {

    public struct Result: Codable, Sendable {
        public var bundleID: String
        public var oldVersion: String?
        public var newVersion: String?
        public var severitiesOld: [String: Int]
        public var severitiesNew: [String: Int]
        public var clustersOld: [String: Int]
        public var clustersNew: [String: Int]
        public var addedFindings: [String]
        public var removedFindings: [String]
        public var addedOwners: [String]
        public var removedOwners: [String]
    }

    public static func compute(old: ScanReport, new: ScanReport) -> Result {
        func severities(_ r: ScanReport) -> [String: Int] {
            var out: [String: Int] = [:]
            for f in r.findings { out[f.severity.rawValue, default: 0] += 1 }
            return out
        }

        let oldRules = Set(old.findings.map(\.ruleID))
        let newRules = Set(new.findings.map(\.ruleID))
        let oldOwners = Set(old.network.detectedSDKs.map { $0.owner.isEmpty ? $0.name : $0.owner })
        let newOwners = Set(new.network.detectedSDKs.map { $0.owner.isEmpty ? $0.name : $0.owner })

        return Result(
            bundleID: new.metadata.bundleID,
            oldVersion: old.metadata.shortVersion, newVersion: new.metadata.shortVersion,
            severitiesOld: severities(old), severitiesNew: severities(new),
            clustersOld: Dictionary(uniqueKeysWithValues:
                old.findings.clusterRollup().map { ($0.id, $0.findingCount) }),
            clustersNew: Dictionary(uniqueKeysWithValues:
                new.findings.clusterRollup().map { ($0.id, $0.findingCount) }),
            addedFindings: newRules.subtracting(oldRules).sorted(),
            removedFindings: oldRules.subtracting(newRules).sorted(),
            addedOwners: newOwners.subtracting(oldOwners).sorted(),
            removedOwners: oldOwners.subtracting(newOwners).sorted())
    }

    public static func render(_ d: Result) -> String {
        func sign(_ n: Int) -> String { n > 0 ? "+\(n)" : "\(n)" }
        var s = "Diff for \(d.bundleID)  \(d.oldVersion ?? "?") → \(d.newVersion ?? "?")\n"
        let clusterIDs = Set(d.clustersOld.keys).union(d.clustersNew.keys)
        if !clusterIDs.isEmpty {
            s += "\nFindings by cluster:\n"
            for id in FindingCluster.allOrdered.map(\.id) where clusterIDs.contains(id) {
                let o = d.clustersOld[id] ?? 0, n = d.clustersNew[id] ?? 0
                guard o != 0 || n != 0 else { continue }
                let marker = n == o ? " " : (n > o ? "▲" : "▼")
                s += "  \(marker) \(id.padding(toLength: 16, withPad: " ", startingAt: 0)) \(o) → \(n) (\(sign(n - o)))\n"
            }
        }
        s += "\nFindings by severity:\n"
        for sev in Severity.allCases.reversed() {
            let o = d.severitiesOld[sev.rawValue] ?? 0, n = d.severitiesNew[sev.rawValue] ?? 0
            guard o != 0 || n != 0 else { continue }
            let marker = n == o ? " " : (n > o ? "▲" : "▼")
            s += "  \(marker) \(sev.rawValue.padding(toLength: 8, withPad: " ", startingAt: 0)) \(o) → \(n) (\(sign(n - o)))\n"
        }
        func section(_ title: String, _ items: [String]) {
            guard !items.isEmpty else { return }
            s += "\n\(title) (\(items.count)):\n"
            for i in items.prefix(50) { s += "  \(i)\n" }
            if items.count > 50 { s += "  … and \(items.count - 50) more\n" }
        }
        section("+ Added findings", d.addedFindings)
        section("- Removed findings", d.removedFindings)
        section("+ New SDK/tracker owners", d.addedOwners)
        section("- Dropped SDK/tracker owners", d.removedOwners)
        if d.addedFindings.isEmpty && d.removedFindings.isEmpty
            && d.addedOwners.isEmpty && d.removedOwners.isEmpty {
            s += "\nNo finding or owner changes.\n"
        }
        return s
    }
}
