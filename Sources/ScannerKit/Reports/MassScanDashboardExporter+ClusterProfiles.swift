import Foundation

struct ClusterProfile {
    struct Member { let label: String; let apps: Int }
    struct Row {
        let label: String
        let apps: Int
        let severity: Severity
        let rules: [String]
        let members: [Member]
    }
    struct Weakness { let id: String; let title: String; let apps: Int }

    let id: String
    let title: String
    let blurb: String
    let reach: Int
    let weaknesses: [Weakness]
    let top: [Row]
    let inventory: [Row]
}

extension MassScanDashboardExporter {

    static let mitigationsProfileID = "MITIGATIONS"

    static func clusterProfiles(_ report: MassScanReport) -> [ClusterProfile] {
        final class Bucket {
            var apps = Set<String>()
            var weakness: [String: Set<String>] = [:]
            var top: [String: Tally] = [:]
            var inventory: [String: Tally] = [:]
        }
        final class Tally {
            var apps = Set<String>()
            var severity = Severity.info
            var ruleApps: [String: Set<String>] = [:]
            var ruleLabels: [String: Set<String>] = [:]
            func add(_ app: String, rule: String, label: String, severity sev: Severity) {
                apps.insert(app)
                severity = max(severity, sev)
                ruleApps[rule, default: []].insert(app)
                ruleLabels[rule, default: []].insert(label)
            }
        }

        var buckets: [String: Bucket] = [:]
        for app in report.apps where app.ok {
            guard let det = app.details else { continue }
            let key = app.bundleID
            for (d, f) in zip(det.findings, MassScanReport.findings(det)) {
                let rule = (d.rule?.isEmpty == false) ? d.rule! : d.label
                let family = Messages.familyKey(rule)
                let target: String
                let counted: Bool
                switch f.polarity {
                case .defensive:
                    target = mitigationsProfileID; counted = true
                case .offensive, .neutral:
                    guard let c = d.cluster ?? FindingCluster.of(f)?.id else { continue }
                    target = c; counted = f.countsAsWeakness && f.severity > .info
                }
                let b = buckets[target] ?? Bucket()
                buckets[target] = b
                let slot = counted ? \Bucket.top : \Bucket.inventory
                let t = b[keyPath: slot][family] ?? Tally()
                b[keyPath: slot][family] = t
                t.add(key, rule: rule, label: d.label, severity: f.severity)
                if counted {
                    b.apps.insert(key)
                    if target != mitigationsProfileID {
                        for w in f.maswe { b.weakness[w, default: []].insert(key) }
                    }
                }
            }
        }

        func rows(_ tallies: [String: Tally]) -> [ClusterProfile.Row] {
            tallies.values.map { t in
                let rules = t.ruleApps.keys.sorted()
                let labels = rules.map { familyLabel(Array(t.ruleLabels[$0] ?? [])).label }
                guard rules.count > 1 else {
                    return ClusterProfile.Row(label: labels.first ?? "", apps: t.apps.count,
                                              severity: t.severity, rules: rules, members: [])
                }
                let family = familyLabel(labels)
                let members = zip(rules, family.members).map {
                    ClusterProfile.Member(label: $0.1, apps: t.ruleApps[$0.0]?.count ?? 0)
                }.sorted { $0.apps != $1.apps ? $0.apps > $1.apps : $0.label < $1.label }
                return ClusterProfile.Row(label: family.label, apps: t.apps.count,
                                          severity: t.severity, rules: rules, members: members)
            }.sorted { $0.apps != $1.apps ? $0.apps > $1.apps : $0.label < $1.label }
        }

        var out: [ClusterProfile] = []
        for c in FindingCluster.allOrdered {
            guard let b = buckets[c.id], !(b.top.isEmpty && b.inventory.isEmpty) else { continue }
            let weaknesses = b.weakness.map {
                ClusterProfile.Weakness(id: $0.key, title: MASWECatalog.title($0.key) ?? $0.key,
                                        apps: $0.value.count)
            }.sorted { $0.apps != $1.apps ? $0.apps > $1.apps : $0.id < $1.id }
            out.append(ClusterProfile(id: c.id, title: c.title, blurb: c.blurb, reach: b.apps.count,
                                      weaknesses: weaknesses, top: rows(b.top),
                                      inventory: rows(b.inventory)))
        }
        if let b = buckets[mitigationsProfileID] {
            out.append(ClusterProfile(
                id: mitigationsProfileID, title: "Mitigations observed",
                blurb: "Evidence of a published mitigation (App Attest, backup exclusion, capture detection). A plus for the app, never tallied as a weakness.",
                reach: b.apps.count, weaknesses: [], top: rows(b.top), inventory: []))
        }
        return out
    }

    static func familyLabel(_ labels: [String]) -> (label: String, members: [String]) {
        let distinct = Array(Set(labels))
        guard distinct.count > 1 else { return (labels.first ?? "", labels) }
        let prefix = commonPrefix(distinct)
        var head = prefix
        var cut = prefix.endIndex
        var trailer = ""
        if let r = prefix.range(of: ": ", options: .backwards) {
            head = String(prefix[..<r.lowerBound]); cut = r.upperBound
        } else if let r = prefix.range(of: " (", options: .backwards) {
            head = String(prefix[..<r.lowerBound]); cut = prefix.index(after: r.lowerBound)
        } else if let r = prefix.range(of: " ", options: .backwards) {
            head = String(prefix[..<r.lowerBound]); cut = r.upperBound; trailer = " \u{2026}"
        } else {
            head = ""; cut = prefix.startIndex
        }
        let offset = prefix.distance(from: prefix.startIndex, to: cut)
        var rests = labels.map { String($0.dropFirst(offset)) }
        let tail = commonSuffix(rests)
        if let space = tail.firstIndex(of: " ") {
            let drop = tail.distance(from: space, to: tail.endIndex)
            if rests.allSatisfy({ $0.count > drop }) { rests = rests.map { String($0.dropLast(drop)) } }
        }
        rests = rests.map { r in
            r.hasPrefix("(") && r.hasSuffix(")") && r.filter({ $0 == "(" }).count == 1
                ? String(r.dropFirst().dropLast()) : r
        }
        let label = head.trimmingCharacters(in: .whitespaces)
        return (label.isEmpty ? (labels.first ?? "") : label + trailer, rests)
    }

    private static func commonPrefix(_ xs: [String]) -> String {
        guard var p = xs.first else { return "" }
        for x in xs.dropFirst() {
            p = String(zip(p, x).prefix { $0 == $1 }.map(\.0))
        }
        return p
    }

    private static func commonSuffix(_ xs: [String]) -> String {
        String(commonPrefix(xs.map { String($0.reversed()) }).reversed())
    }

    static func clusterProfilesHTML(_ report: MassScanReport, top limit: Int = 8) -> String {
        let profiles = clusterProfiles(report)
        guard !profiles.isEmpty else { return "" }
        let n = report.apps.filter { $0.ok && $0.details != nil }.count
        var s = "<div class=profiles>"
        for p in profiles {
            let mitigations = p.id == mitigationsProfileID
            s += "<div class=\"card profile\(mitigations ? " defences" : "")\" id=\"p-\(HTML.esc(p.id))\">"
            s += "<div class=phead><span class=pid>\(HTML.esc(mitigations ? p.title : p.id))</span>"
            if !mitigations { s += "<span class=ptitle>\(HTML.esc(p.title))</span>" }
            let what = mitigations ? "apps with at least one" : "apps with a low-or-above weakness"
            s += "<span class=preach title=\"\(what)\"><b>\(p.reach)</b> of \(n) apps</span></div>"
            s += "<div class=pblurb>\(HTML.esc(p.blurb))</div>"
            if !p.weaknesses.isEmpty {
                s += "<div class=pweak>"
                for w in p.weaknesses {
                    let id = MASWECatalog.url(w.id).map { "<a href=\"\(HTML.esc($0))\" target=_blank rel=noopener>\(HTML.esc(w.id))</a>" }
                        ?? HTML.esc(w.id)
                    s += "<span class=pw>\(id) \(HTML.esc(w.title)) <b>\(w.apps)</b></span>"
                }
                s += "</div>"
            }
            s += profileRows(Array(p.top.prefix(limit)), n: n, dim: false)
            if p.top.count > limit {
                let rest = p.top.count - limit
                s += "<details class=pmore><summary>+\(rest) more finding\(rest == 1 ? "" : "s")</summary>"
                s += profileRows(Array(p.top.dropFirst(limit)), n: n, dim: false)
                s += "</details>"
            }
            if !p.inventory.isEmpty {
                s += "<details class=pinv><summary>Also filed here, not counted "
                s += "<span class=dim>(references and info level)</span></summary>"
                s += profileRows(p.inventory, n: n, dim: true)
                s += "</details>"
            }
            s += "</div>"
        }
        return s + "</div>"
    }

    private static func profileRows(_ rows: [ClusterProfile.Row], n: Int, dim: Bool) -> String {
        guard !rows.isEmpty else { return "" }
        var s = "<ol class=\"pbars\(dim ? " dim" : "")\">"
        for r in rows {
            let width = n > 0 ? min(100, Double(r.apps) / Double(n) * 100) : 0
            var sub = ""
            if !r.members.isEmpty {
                let all = r.members.map { "\(HTML.esc($0.label)) <b>\($0.apps)</b>" }
                sub = "<span class=psub>\(all.joined(separator: " \u{00B7} "))</span>"
            }
            s += "<li title=\"\(HTML.esc(r.rules.joined(separator: ", ")))\">"
            s += "<span class=plab>\(HTML.esc(r.label))</span>"
            s += "<span class=ptrack><i class=b-\(r.severity.rawValue) style=\"width:\(String(format: "%.1f", width))%\"></i></span>"
            s += "<span class=pn>\(r.apps)</span>\(sub)</li>"
        }
        return s + "</ol>"
    }

    static func clusterProfilesMarkdown(_ report: MassScanReport) -> String {
        let profiles = clusterProfiles(report)
        guard !profiles.isEmpty else { return "" }
        let n = report.apps.filter { $0.ok && $0.details != nil }.count
        var s = "## Cluster profiles\n\n"
        s += "Apps per finding. Counted rows are offensive at low or above, the cluster reach test; "
        s += "a family of per-value rules is one row, its members in brackets.\n\n"
        for p in profiles {
            s += "### \(p.id == mitigationsProfileID ? p.title : "\(p.id) \u{00B7} \(p.title)")\n\n"
            s += "\(p.blurb) **\(p.reach) of \(n) apps.**\n\n"
            if !p.weaknesses.isEmpty {
                s += p.weaknesses.map { "\($0.id) \($0.title) (\($0.apps))" }.joined(separator: " \u{00B7} ") + "\n\n"
            }
            s += "| Finding | Apps | Worst severity |\n|---|---:|---|\n"
            for r in p.top {
                let members = r.members.isEmpty ? ""
                    : " (" + r.members.map { "\($0.label) \($0.apps)" }.joined(separator: ", ") + ")"
                s += "| \(mdCell(r.label + members)) | \(r.apps) | \(r.severity.rawValue) |\n"
            }
            if !p.inventory.isEmpty {
                let inv = p.inventory.map { "\($0.label) (\($0.apps))" }.joined(separator: " \u{00B7} ")
                s += "\nNot counted: \(inv)\n"
            }
            s += "\n"
        }
        return s
    }

    private static func mdCell(_ text: String) -> String {
        text.replacingOccurrences(of: "|", with: "\\|")
    }
}
