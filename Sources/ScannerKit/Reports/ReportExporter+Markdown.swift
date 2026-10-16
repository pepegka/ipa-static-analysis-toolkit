import Foundation

extension ReportExporter {

    public static func markdown(_ report: ScanReport) -> String {
        var s = ""
        let m = report.metadata
        s += "# \(m.displayName ?? m.bundleName): security scan\n\n"
        s += "- **Bundle ID:** `\(m.bundleID)`\n"
        if let v = m.shortVersion { s += "- **Version:** \(v)\n" }
        if let b = m.bundleVersion { s += "- **Build:** \(b)\n" }
        if let exe = m.executableName { s += "- **Executable:** `\(exe)`\n" }
        if let min = m.minimumOSVersion { s += "- **Minimum iOS:** \(min)\n" }
        s += "- **Findings:** \(report.findings.count)\n"
        s += "- **Scan duration:** \(String(format: "%.2f", report.scanDurationSeconds))s\n"
        s += "- **Generated:** \(ISO8601DateFormatter().string(from: report.createdAt))\n\n"

        let clusters = report.findings.clusterRollup()
        if !clusters.isEmpty {
            s += "## Findings by cluster\n\n"
            s += "| Cluster | Findings | Critical | High | Medium | Low | Info |\n|---|---|---|---|---|---|---|\n"
            for c in clusters {
                s += "| **\(c.title)** `\(c.id)` | \(c.findingCount) | \(c.count(.critical)) | "
                s += "\(c.count(.high)) | \(c.count(.medium)) | \(c.count(.low)) | \(c.count(.info)) |\n"
            }
            s += "\n"
            for c in clusters where !c.children.isEmpty {
                s += "**\(c.title)** weakness classes: "
                s += c.children.map { "\($0.id) \($0.title) (\($0.findingCount))" }.joined(separator: "; ")
                s += "\n\n"
            }
        }

        let controls = report.findings.controlRollup()
        if !controls.isEmpty {
            s += "## MASVS controls\n\n| Control | Findings | Worst |\n|---|---|---|\n"
            for c in controls {
                let id = c.url.map { "[\(c.id)](\($0))" } ?? c.id
                s += "| \(id) \(c.statement) | \(c.findingCount) | \(c.maxSeverity.rawValue) |\n"
            }
            s += "\nA control with no row had no finding; that is not the same as passing it.\n\n"
        }

        if !report.notes.isEmpty {
            s += "## Scanner notes\n\n"
            for n in report.notes { s += "- \(n)\n" }
            s += "\n"
        }

        let rollup = report.masvsRollup()
        if !rollup.isEmpty {
            s += "## MASVS group summary\n\n"
            s += "| Group | Hits | Max severity |\n"
            s += "|---|---:|---|\n"
            for g in rollup {
                s += "| \(g.group.rawValue), \(g.group.title) | \(g.hitCount) | \(g.maxSeverity.rawValue) |\n"
            }
            s += "\n"
        }

        s += appDetailsMarkdown(report)

        s += "## Vector summary\n\n"
        s += "| Vector | Hits | Max severity |\n"
        s += "|---|---:|---|\n"
        for v in report.vectorSummaries where v.uniqueArtifactCount > 0 {
            let vec = Vectors.byID[v.vectorID]
            s += "| \(v.vectorID), \(vec?.title ?? "") | \(v.uniqueArtifactCount) | \(v.maxSeverity.rawValue) |\n"
        }
        s += "\n"

        s += "## Findings (\(report.findings.count))\n\n"
        for f in report.findings {
            s += "### `\(f.ruleID)` \(f.title)\n\n"
            s += "- **Severity:** \(f.severity.rawValue)\n"
            s += "- **Vector:** \(f.vectorID)\n"
            if !f.owningFrameworks.isEmpty {
                s += "- **Owning framework(s):** \(f.owningFrameworks.joined(separator: ", "))\n"
            } else if let fw = f.owningFramework {
                s += "- **Owning framework:** \(fw)\n"
            }
            if !f.affectedBinaries.isEmpty {
                s += "- **Affected binaries (\(f.affectedBinaries.count)):**\n"
                for b in f.affectedBinaries { s += "  - `\(b)`\n" }
            }
            if let why = f.why, !why.isEmpty { s += "- **Why this severity:** \(why)\n" }
            func taxonomy(_ label: String, _ items: [String]) {
                guard !items.isEmpty else { return }
                s += "- **\(label):** \(items.joined(separator: ", "))\n"
            }
            func linked(_ label: String, _ refs: [FrameworkRef]) {
                guard !refs.isEmpty else { return }
                let parts = refs.map { r -> String in
                    let name = r.title.map { "\(r.id) (\($0))" } ?? r.id
                    return r.url.map { "[\(name)](\($0))" } ?? name
                }
                s += "- **\(label):** \(parts.joined(separator: ", "))\n"
            }
            if let cvss = f.cvss, !cvss.isEmpty { linked("CVSS", [FrameworkLinks.cvss(cvss)]) }
            taxonomy("MASVS", f.masvs)
            linked("MASVS controls", FrameworkLinks.masvsControls(f.masvsControls))
            linked("MASWE", FrameworkLinks.maswe(f.maswe))
            taxonomy("MAS profiles", FrameworkLinks.profileLabels(maswe: f.maswe))
            linked("MASTG", FrameworkLinks.mastg(f.mastg))
            linked("CWE", FrameworkLinks.cwe(f.cwe))
            linked("MITRE", FrameworkLinks.attack(f.mitre))
            taxonomy("LINDDUN", f.linddun)
            taxonomy("Solove", f.solove)
            taxonomy("GDPR", f.gdpr)
            taxonomy("Permissions required", f.permissionsRequired)
            taxonomy("Permissions granted", f.permissionsGranted)
            s += "\n\(f.explanation)\n\n"
            if let rem = f.remediation, !rem.isEmpty {
                s += "**Remediation (developer):** \(rem)\n\n"
            }
            if let adv = Messages.userAdvice(ruleID: f.ruleID, vectorID: f.vectorID) {
                s += "**For users:** \(adv)\n\n"
            }
            if !f.evidences.isEmpty {
                s += "<details><summary>Evidence (\(f.evidences.count))</summary>\n\n"
                for e in f.evidences {
                    let val = e.value.replacingOccurrences(of: "|", with: "\\|")
                    s += "- `\(e.kind.rawValue)` `\(val)` in `\(e.source)`"
                    if let sec = e.section { s += " (\(sec)" + (e.offset.map { String(format: " @0x%llx)", $0) } ?? ")") }
                    s += "\n"
                }
                s += "\n</details>\n\n"
            }
            if !f.references.isEmpty {
                s += "References:\n"
                for r in f.references { s += "- \(r)\n" }
                s += "\n"
            }
        }

        s += "## Security posture (MASVS)\n\n"
        let ats = report.ats
        s += "- **ATS arbitrary loads (global):** \(ats.allowsArbitraryLoads ? "ENABLED ⚠︎" : "disabled")\n"
        if ats.allowsArbitraryLoadsInWebContent { s += "- **ATS arbitrary loads in web content:** ENABLED ⚠︎\n" }
        if ats.allowsArbitraryLoadsForMedia { s += "- **ATS arbitrary loads for media:** ENABLED ⚠︎\n" }
        if ats.allowsLocalNetworking { s += "- **ATS local networking:** allowed\n" }
        s += "- **ATS exception domains:** \(ats.exceptionDomains.count)\n"
        s += "- **Potential hardcoded secrets:** \(report.secrets.count)\n\n"
        if !ats.exceptionDomains.isEmpty {
            s += "### ATS exception domains (\(ats.exceptionDomains.count))\n\n"
            s += "| Domain | Insecure HTTP | Subdomains | Min TLS | Forward secrecy |\n|---|:--:|:--:|---|:--:|\n"
            for d in ats.exceptionDomains {
                let fs = d.requiresForwardSecrecy.map { $0 ? "✓" : "✗" } ?? "default"
                s += "| `\(d.domain)` | \(d.allowsInsecureHTTPLoads ? "yes ⚠︎" : "no") | \(d.includesSubdomains ? "yes" : "no") | \(d.minimumTLSVersion ?? "default") | \(fs) |\n"
            }
            s += "\n"
        }
        if !report.hardening.isEmpty {
            s += "### Binary hardening\n\n"
            s += "| Binary | Arch | PIE | Canary | ARC | Encrypted |\n"
            s += "|---|---|:--:|:--:|:--:|:--:|\n"
            for h in report.hardening {
                s += "| `\(h.name)` | \(h.architectures.joined(separator: ", ")) | \(HTML.mark(h.hasPIE)) | \(HTML.mark(h.hasStackCanary)) | \(HTML.mark(h.hasARC)) | \(HTML.mark(h.isEncrypted)) |\n"
            }
            s += "\n"
        }
        if !report.secrets.isEmpty {
            s += "### Potential secrets (\(report.secrets.count)), redacted\n\n"
            s += "| Type | Severity | Entropy | Source | Section |\n|---|---|---:|---|---|\n"
            for h in report.secrets {
                s += "| \(h.type) | \(h.severity.rawValue) | \(String(format: "%.1f", h.entropy)) | `\(h.source)` | \(h.section ?? "") |\n"
            }
            s += "\n"
        }

        if !report.network.endpoints.isEmpty {
            s += "## Network endpoints (\(report.network.endpoints.count))\n\n"
            s += "| Host | Domain | Country | Owner | Category | Tracker | Hits | Sources |\n"
            s += "|---|---|---|---|---|---|---:|---|\n"
            for e in report.network.endpoints {
                let src = e.sources.prefix(3).map { URL(fileURLWithPath: $0).lastPathComponent }.joined(separator: ", ")
                s += "| `\(e.host)` | `\(e.registrableDomain)` | \(e.country ?? "") | \(e.owner ?? "") | \(e.category ?? "") | \(e.isTracker ? "yes" : "") | \(e.occurrenceCount) | \(src) |\n"
            }
            s += "\n"
        }
        if !report.network.detectedSDKs.isEmpty {
            s += "## Detected SDKs (\(report.network.detectedSDKs.count))\n\n"
            for sdk in report.network.detectedSDKs {
                s += "### \(sdk.name)  \(sdk.isTracker ? "_(tracker)_" : "")\n\n"
                s += "- Owner: \(sdk.owner) · Country: \(sdk.country) · Category: \(sdk.category)\n"
                if !sdk.frameworks.isEmpty {
                    s += "- Frameworks: \(sdk.frameworks.map { "`\($0)`" }.joined(separator: ", "))\n"
                }
                if !sdk.endpoints.isEmpty {
                    s += "- Endpoints (\(sdk.endpoints.count)):\n"
                    for ep in sdk.endpoints { s += "  - `\(ep)`\n" }
                }
                s += "\n"
            }
        }

        if !report.fileManifest.isEmpty {
            let flagged = report.fileManifest.filter(\.isSuspicious)
            s += "## File manifest (\(report.fileManifest.count) files"
            s += flagged.isEmpty ? ")\n\n" : ", \(flagged.count) flagged)\n\n"
            if !flagged.isEmpty {
                s += "### Flagged files\n\n"
                s += "| File | Kind | Size | Reason |\n|---|---|---:|---|\n"
                for e in flagged {
                    s += "| `\(e.relativePath)` | \(e.kind) | \(HTML.byteSize(e.sizeBytes)) | \(e.suspicionReason ?? "") |\n"
                }
                s += "\n"
            }
            s += "<details><summary>All files (\(report.fileManifest.count))</summary>\n\n"
            s += "| File | Kind | Size | SHA-256 |\n|---|---|---:|---|\n"
            for e in report.fileManifest {
                s += "| `\(e.relativePath)` | \(e.kind) | \(HTML.byteSize(e.sizeBytes)) | `\(e.sha256 ?? "")` |\n"
            }
            s += "\n</details>\n\n"
        }
        return s
    }

    static func appDetailsMarkdown(_ report: ScanReport) -> String {
        func esc(_ v: String) -> String { v.replacingOccurrences(of: "|", with: "\\|") }
        var s = "## App details\n\n"
        for section in AppDetailSection.all(report.metadata) {
            switch section {
            case .summary(let rows):
                for r in rows {
                    s += r.code ? "- **\(r.label):** `\(r.value)`\n" : "- **\(r.label):** \(r.value)\n"
                }
                s += "\n"

            case .permissions(let perms):
                s += "### Permissions (\(perms.count))\n\n"
                s += "| Key | Vector | Category | Purpose string |\n|---|---|---|---|\n"
                for p in perms {
                    s += "| `\(p.key)` | \(p.vectorID ?? "") | \(p.category ?? "") | \(esc(p.value)) |\n"
                }
                s += "\n"

            case .identifiers(let title, let values):
                s += "### \(title) (\(values.count))\n\n"
                for v in values { s += "- `\(v)`\n" }
                s += "\n"

            case .entitlements(let ents):
                s += "### Entitlements (\(ents.count))\n\n| Key | Value |\n|---|---|\n"
                for k in ents.keys.sorted() { s += "| `\(k)` | \(esc(ents[k]!)) |\n" }
                s += "\n"

            case .privacyManifest(let path, let apis, let domains):
                s += "### Privacy manifest\n\n"
                if let path { s += "- **Path:** `\(path)`\n" }
                if !apis.isEmpty {
                    s += "- **Accessed API categories (\(apis.count)):** "
                        + apis.map { "`\($0)`" }.joined(separator: ", ") + "\n"
                }
                if !domains.isEmpty {
                    s += "- **Tracking domains (\(domains.count)):** "
                        + domains.map { "`\($0)`" }.joined(separator: ", ") + "\n"
                }
                s += "\n"

            case .binaries(let bins):
                s += "### Embedded binaries (\(bins.count))\n\n"
                s += "| Binary | Arch | Encrypted | Size | Dylibs |\n|---|---|:--:|---:|---:|\n"
                for b in bins {
                    s += "| `\(b.relativePath)` | \(b.architectures.joined(separator: ", ")) "
                        + "| \(b.isFairPlayEncrypted ? "yes" : "no") | \(HTML.byteSize(b.sizeBytes)) "
                        + "| \(b.linkedDylibs.count) |\n"
                }
                s += "\n"

            case .frameworks(let fws):
                s += "### Embedded frameworks (\(fws.count))\n\n"
                for fw in fws { s += "- `\(fw)`\n" }
                s += "\n"
            }
        }
        return s
    }
}
