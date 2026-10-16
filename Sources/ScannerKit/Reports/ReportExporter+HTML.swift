import Foundation

extension ReportExporter {

    struct Outline {
        private(set) var entries: [(id: String, title: String, count: Int?)] = []

        mutating func add(_ id: String, _ title: String, count: Int? = nil) {
            entries.append((id, title, count))
        }

        func nav(back: String?) -> String {
            var s = "<nav class=toc aria-label=\"Report sections\">"
            if let back {
                s += "<a class=back href=\"\(HTML.esc(back))\">&larr; All apps</a>"
            }
            for e in entries {
                s += "<a href=\"#\(e.id)\">\(HTML.esc(e.title))"
                if let c = e.count { s += " <span class=n>\(c)</span>" }
                s += "</a>"
            }
            return s + "</nav>"
        }
    }

    static func refHTML(_ s: String) -> String {
        guard s.hasPrefix("https://") || s.hasPrefix("http://"), URL(string: s) != nil else {
            return HTML.esc(s)
        }
        return "<a href=\"\(HTML.esc(s))\" rel=noreferrer>\(HTML.esc(s))</a>"
    }

    static func metaRow(_ label: String, _ items: [String]) -> String {
        guard !items.isEmpty else { return "" }
        return "<dt>\(HTML.esc(label))</dt><dd>"
            + items.map { "<code>\(HTML.esc($0))</code>" }.joined(separator: " ") + "</dd>"
    }

    static func linkRow(_ label: String, _ refs: [FrameworkRef]) -> String {
        guard !refs.isEmpty else { return "" }
        return "<dt>\(HTML.esc(label))</dt><dd>" + refs.map { r in
            let chip = "<code>\(HTML.esc(r.id))</code>"
            guard let url = r.url else { return chip }
            let title = r.title.map { " title=\"\(HTML.esc($0))\"" } ?? ""
            return "<a href=\"\(HTML.esc(url))\" rel=noreferrer\(title)>\(chip)</a>"
        }.joined(separator: " ") + "</dd>"
    }

    static func appDetailsHTML(_ report: ScanReport, _ toc: inout Outline) -> String {
        toc.add("app-details", "App details")
        var s = "<h2 id=app-details>App details</h2>"
        for section in AppDetailSection.all(report.metadata) {
            switch section {
            case .summary(let rows):
                s += "<ul>"
                for r in rows {
                    let v = r.code ? "<code>\(HTML.esc(r.value))</code>" : HTML.esc(r.value)
                    s += "<li>\(HTML.esc(r.label)): \(v)</li>"
                }
                s += "</ul>"

            case .permissions(let perms):
                s += "<h3>Permissions (\(perms.count))</h3><div class=scroll><table><thead><tr>"
                s += "<th>Key</th><th>Vector</th><th>Category</th><th>Purpose string</th></tr></thead><tbody>"
                for p in perms {
                    s += "<tr><td class=nw><code>\(HTML.esc(p.key))</code></td>"
                        + "<td class=nw>\(HTML.esc(p.vectorID ?? ""))</td>"
                        + "<td class=nw>\(HTML.esc(p.category ?? ""))</td>"
                        + "<td>\(HTML.esc(p.value))</td></tr>"
                }
                s += "</tbody></table></div>"

            case .identifiers(let title, let values):
                s += "<h3>\(HTML.esc(title)) (\(values.count))</h3><div>"
                for v in values { s += "<span class=pill><code>\(HTML.esc(v))</code></span> " }
                s += "</div>"

            case .entitlements(let ents):
                s += "<details><summary>Entitlements (\(ents.count))</summary>"
                    + "<div class=\"ev scroll\"><table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>"
                for k in ents.keys.sorted() {
                    s += "<tr><td><code>\(HTML.esc(k))</code></td><td><code>\(HTML.esc(ents[k]!))</code></td></tr>"
                }
                s += "</tbody></table></div></details>"

            case .privacyManifest(let path, let apis, let domains):
                s += "<h3>Privacy manifest</h3><ul>"
                if let path { s += "<li>Path: <code>\(HTML.esc(path))</code></li>" }
                if !apis.isEmpty {
                    s += "<li>Accessed API categories: "
                        + apis.map { "<code>\(HTML.esc($0))</code>" }.joined(separator: ", ") + "</li>"
                }
                if !domains.isEmpty {
                    s += "<li>Tracking domains: "
                        + domains.map { "<code>\(HTML.esc($0))</code>" }.joined(separator: ", ") + "</li>"
                }
                s += "</ul>"

            case .binaries(let bins):
                s += "<details><summary>Embedded binaries (\(bins.count))</summary>"
                    + "<div class=\"ev scroll\"><table><thead><tr><th>Binary</th><th>Arch</th>"
                    + "<th>Encrypted</th><th>Size</th><th>Dylibs</th></tr></thead><tbody>"
                for b in bins {
                    s += "<tr><td><code>\(HTML.esc(b.relativePath))</code></td>"
                        + "<td class=nw>\(HTML.esc(b.architectures.joined(separator: ", ")))</td>"
                        + "<td>\(b.isFairPlayEncrypted ? "yes" : "no")</td>"
                        + "<td class=num>\(HTML.esc(HTML.byteSize(b.sizeBytes)))</td>"
                        + "<td class=num>\(b.linkedDylibs.count)</td></tr>"
                }
                s += "</tbody></table></div></details>"

            case .frameworks(let fws):
                s += "<h3>Embedded frameworks (\(fws.count))</h3><div>"
                for fw in fws { s += "<span class=pill><code>\(HTML.esc(fw))</code></span> " }
                s += "</div>"
            }
        }
        return s
    }

    static func evidenceTable(_ evs: [Evidence]) -> String {
        let hasSection = evs.contains { !($0.section ?? "").isEmpty }
        let hasOffset = evs.contains { $0.offset != nil }
        let hasContext = evs.contains { !($0.context ?? "").isEmpty }
        var s = "<details><summary>Evidence (\(evs.count))</summary><div class=\"ev scroll\"><table><thead><tr><th>Kind</th><th>Value</th>"
        if hasContext { s += "<th>Context</th>" }
        s += "<th>Source</th>"
        if hasSection { s += "<th>Section</th>" }
        if hasOffset { s += "<th>Offset</th>" }
        s += "</tr></thead><tbody>"
        for e in evs {
            s += "<tr><td class=nw><code>\(e.kind.rawValue)</code></td>"
            s += e.value.isEmpty ? "<td><code class=dim>\"\"</code> <small>(empty)</small></td>" : "<td><code>\(HTML.esc(e.value))</code></td>"
            if hasContext { s += "<td>\(HTML.esc(e.context ?? ""))</td>" }
            s += "<td><code>\(HTML.esc(e.source))</code></td>"
            if hasSection { s += "<td class=nw><code>\(HTML.esc(e.section ?? ""))</code></td>" }
            if hasOffset { s += "<td class=nw><code>\(e.offset.map { String(format: "0x%llx", $0) } ?? "")</code></td>" }
            s += "</tr>"
        }
        return s + "</tbody></table></div></details>"
    }

    static let manifestEmbedLimit = 1500

    static func manifestRows(_ manifest: [FileManifestEntry]) -> (rows: [FileManifestEntry], total: Int) {
        guard manifest.count > manifestEmbedLimit else { return (manifest, manifest.count) }
        let flagged = manifest.filter(\.isSuspicious)
        let rest = manifest.filter { !$0.isSuspicious }
            .sorted { $0.sizeBytes > $1.sizeBytes }
            .prefix(max(0, manifestEmbedLimit - flagged.count))
        let kept = Set((flagged + rest).map(\.relativePath))
        return (manifest.filter { kept.contains($0.relativePath) }, manifest.count)
    }

    static func manifestJSON(_ rows: [FileManifestEntry], total: Int) -> String {
        let payload: [String: Any] = [
            "total": total,
            "rows": rows.map { [$0.relativePath, $0.kind, $0.sizeBytes, $0.sha256 ?? ""] as [Any] },
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return "{\"total\":0,\"rows\":[]}" }
        return text.replacingOccurrences(of: "<", with: "\\u003c")
    }

    public static func html(_ report: ScanReport, dashboardPath: String? = nil) -> String {
        let m = report.metadata
        var toc = Outline()
        var s = ""

        s += "<header>"
        s += "<div><h1>\(HTML.esc(m.displayName ?? m.bundleName))</h1>"
        s += "<div class=sub><code>\(HTML.esc(m.bundleID))</code>"
        if let v = m.shortVersion { s += " · v\(HTML.esc(v))" }
        if let b = m.bundleVersion { s += " · build \(HTML.esc(b))" }
        if let min = m.minimumOSVersion { s += " · iOS \(HTML.esc(min))+" }
        s += "</div>"
        s += "<div class=sub><small>\(report.findings.count) findings · \(report.network.endpoints.count) endpoints · \(String(format: "%.2f", report.scanDurationSeconds))s scan · generated \(ISO8601DateFormatter().string(from: report.createdAt))</small></div>"
        s += "</div>"
        s += "</header>"

        s += "<p class=note>Frameworks: MASVS \(HTML.esc(report.frameworks.masvs)), "
        s += "MASTG \(HTML.esc(report.frameworks.mastg)), MASWE \(HTML.esc(report.frameworks.maswe)), "
        s += "ATT&amp;CK Mobile \(HTML.esc(report.frameworks.attackMobile)), CVSS \(HTML.esc(report.frameworks.cvss))</p>"

        if !report.notes.isEmpty {
            toc.add("notes", "Scanner notes", count: report.notes.count)
            s += "<h2 id=notes>Scanner notes</h2><ul>"
            for n in report.notes { s += "<li>\(HTML.esc(n))</li>" }
            s += "</ul>"
        }

        let clusterRollup = report.findings.clusterRollup()
        if !clusterRollup.isEmpty {
            toc.add("clusters", "Findings by cluster", count: clusterRollup.count)
            s += "<h2 id=clusters>Findings by cluster</h2>"
            s += "<div class=scroll><table><thead><tr><th>Cluster</th><th>Findings</th>"
            for sev in Severity.allCases.reversed() {
                s += "<th>\(HTML.esc(sev.rawValue.capitalized))</th>"
            }
            s += "</tr></thead><tbody>"
            for c in clusterRollup {
                s += "<tr><td class=nw><code>\(HTML.esc(c.id))</code> \(HTML.esc(c.title))</td>"
                s += "<td class=num>\(c.findingCount)</td>"
                for sev in Severity.allCases.reversed() {
                    let n = c.count(sev)
                    s += n > 0 ? "<td class=\"num sev-\(sev.rawValue)\">\(n)</td>" : "<td class=num>—</td>"
                }
                s += "</tr>"
                for w in c.children {
                    s += "<tr class=wrow><td class=nw>&#8627; "
                    if let u = w.url {
                        s += "<a href=\"\(HTML.esc(u))\"><code>\(HTML.esc(w.id))</code></a> "
                    } else {
                        s += "<code>\(HTML.esc(w.id))</code> "
                    }
                    s += "<small>\(HTML.esc(w.title))</small></td>"
                    s += "<td class=num>\(w.findingCount)</td>"
                    for sev in Severity.allCases.reversed() {
                        let n = w.count(sev)
                        s += n > 0 ? "<td class=num>\(n)</td>" : "<td class=num></td>"
                    }
                    s += "</tr>"
                }
            }
            s += "</tbody></table></div>"
            s += "<p class=note>Clusters are OWASP MASVS \(HTML.esc(report.frameworks.masvs)) control groups, "
            s += "plus Apple App Store policy obligations MASVS does not cover. Indented rows are "
            s += "OWASP MASWE \(HTML.esc(MASWECatalog.version)) weakness classes; a finding reaches "
            s += "every weakness it is bound to, so they may sum above the cluster total. A weakness row "
            s += "counts only findings that evidence the weakness: bare API references count toward "
            s += "their cluster, and mitigations are listed separately below.</p>"
        }

        let mitigations = report.findings.mitigationRollup()
        if !mitigations.isEmpty {
            toc.add("mitigations", "Mitigations observed", count: mitigations.count)
            s += "<h2 id=mitigations>Mitigations observed</h2>"
            s += "<p class=note>Evidence of a published mitigation for these OWASP MASWE weaknesses. "
            s += "Presence in the binary shows the measure is built in, not that it covers every path.</p>"
            s += "<div class=scroll><table><thead><tr><th>Weakness mitigated</th><th>Evidence</th></tr></thead><tbody>"
            for m in mitigations {
                let link = m.url.map { "<a href=\"\(HTML.esc($0))\" rel=noreferrer><code>\(HTML.esc(m.id))</code></a>" }
                    ?? "<code>\(HTML.esc(m.id))</code>"
                s += "<tr><td>\(link) <small>\(HTML.esc(m.title))</small></td><td>"
                s += m.findings.map { HTML.esc($0.title) }.joined(separator: "<br>") + "</td></tr>"
            }
            s += "</tbody></table></div>"
        }

        let controls = report.findings.controlRollup()
        if !controls.isEmpty {
            toc.add("controls", "MASVS controls", count: controls.count)
            s += "<h2 id=controls>MASVS controls</h2>"
            s += "<div class=scroll><table><thead><tr><th>Control</th><th>Findings</th><th>Worst</th></tr></thead><tbody>"
            for c in controls {
                let link = c.url.map { "<a href=\"\(HTML.esc($0))\" rel=noreferrer><code>\(HTML.esc(c.id))</code></a>" }
                    ?? "<code>\(HTML.esc(c.id))</code>"
                s += "<tr><td>\(link) <small>\(HTML.esc(c.statement))</small></td>"
                s += "<td class=num>\(c.findingCount)</td>"
                s += "<td class=\"nw sev-\(c.maxSeverity.rawValue)\">\(c.maxSeverity.rawValue)</td></tr>"
            }
            s += "</tbody></table></div>"
            s += "<p class=note>Each finding reaches the MASVS \(HTML.esc(MASVSCatalog.version)) controls its MASWE "
            s += "weaknesses map to. A control with no row had no finding; that is not the same as passing it.</p>"
        }

        s += appDetailsHTML(report, &toc)

        let vectors = report.vectorSummaries.filter { $0.uniqueArtifactCount > 0 }
        if !vectors.isEmpty {
            toc.add("vectors", "Vectors", count: vectors.count)
            s += "<h2 id=vectors>Vectors</h2><div class=scroll><table><thead><tr><th>Vector</th><th>Findings</th><th>Evidence items</th><th>Max severity</th></tr></thead><tbody>"
            for v in vectors {
                let vec = Vectors.byID[v.vectorID]
                let n = report.findings.filter { $0.vectorID == v.vectorID }.count
                s += "<tr><td class=nw><code>\(HTML.esc(v.vectorID))</code> \(HTML.esc(vec?.title ?? ""))</td>"
                s += "<td class=num>\(n)</td>"
                s += "<td class=num>\(v.uniqueArtifactCount)</td>"
                s += "<td class=\"sev-\(v.maxSeverity.rawValue)\">\(v.maxSeverity.rawValue)</td></tr>"
            }
            s += "</tbody></table></div>"
        }

        toc.add("findings-h", "Findings", count: report.findings.count)
        s += "<h2 id=findings-h>Findings (\(report.findings.count))</h2>"
        s += "<div id=finding-filter class=filter></div>"
        s += "<div id=findings>"
        for f in report.findings.sorted(by: { ($0.severity, $1.ruleID) > ($1.severity, $0.ruleID) }) {
            let haystack = "\(f.ruleID) \(f.title) \(f.vectorID)".lowercased()
            s += "<details data-sev=\"\(f.severity.rawValue)\" data-find=\"\(HTML.esc(haystack))\">"
            s += "<summary><span class=\"sevtag sev-\(f.severity.rawValue)\">\(f.severity.rawValue.uppercased())</span>"
            s += "<code>\(HTML.esc(f.ruleID))</code> · \(HTML.esc(f.title))"
            switch f.polarity {
            case .defensive: s += " <span class=\"pill pol-def\" title=\"Evidence of a mitigation, not of the weakness\">mitigation</span>"
            case .neutral: s += " <span class=\"pill pol-ref\" title=\"A reference to the API a test inspects; proves neither the weakness nor its mitigation\">reference</span>"
            case .offensive: break
            }
            s += "</summary>"
            s += "<p>\(HTML.esc(f.explanation))</p>"

            s += "<dl class=meta>"
            s += metaRow("Vector", [f.vectorID])
            if let inst = f.instance { s += metaRow("Instance", [inst]) }
            if let why = f.why, !why.isEmpty { s += metaRow("Why this severity", [why]) }
            if let cvss = f.cvss, !cvss.isEmpty { s += linkRow("CVSS", [FrameworkLinks.cvss(cvss)]) }
            s += metaRow("MASVS", f.masvs)
            s += linkRow("MASVS controls", FrameworkLinks.masvsControls(f.masvsControls))
            s += linkRow("MASWE", FrameworkLinks.maswe(f.maswe))
            s += metaRow("MAS profiles", FrameworkLinks.profileLabels(maswe: f.maswe))
            s += linkRow("MASTG", FrameworkLinks.mastg(f.mastg))
            s += linkRow("CWE", FrameworkLinks.cwe(f.cwe))
            s += linkRow("MITRE", FrameworkLinks.attack(f.mitre))
            s += metaRow("LINDDUN", f.linddun)
            s += metaRow("Solove", f.solove)
            s += metaRow("GDPR", f.gdpr)
            s += metaRow("Permissions required", f.permissionsRequired)
            s += metaRow("Permissions granted", f.permissionsGranted)
            s += metaRow("Frameworks", f.owningFrameworks.isEmpty ? f.owningFramework.map { [$0] } ?? [] : f.owningFrameworks)
            s += metaRow("Affected binaries", f.affectedBinaries)
            s += "</dl>"

            if let rem = f.remediation, !rem.isEmpty {
                s += "<div><b>Remediation (developer):</b> \(HTML.esc(rem))</div>"
            }
            if let adv = Messages.userAdvice(ruleID: f.ruleID, vectorID: f.vectorID) {
                s += "<div class=advice><b>For users:</b> \(HTML.esc(adv))</div>"
            }
            if !f.evidences.isEmpty {
                s += evidenceTable(f.evidences)
            }
            if !f.references.isEmpty {
                s += "<div>References:<ul>"
                for r in f.references { s += "<li>\(refHTML(r))</li>" }
                s += "</ul></div>"
            }
            s += "</details>"
        }
        s += "</div>"

        toc.add("posture", "Security posture")
        s += "<h2 id=posture>Security posture (MASVS)</h2>"
        let ats = report.ats
        s += "<ul>"
        s += "<li>ATS arbitrary loads (global): <b>\(ats.allowsArbitraryLoads ? "ENABLED ⚠︎" : "disabled")</b></li>"
        if ats.allowsArbitraryLoadsInWebContent { s += "<li>ATS arbitrary loads in web content: <b>ENABLED ⚠︎</b></li>" }
        if ats.allowsArbitraryLoadsForMedia { s += "<li>ATS arbitrary loads for media: <b>ENABLED ⚠︎</b></li>" }
        if ats.allowsLocalNetworking { s += "<li>ATS local networking: allowed</li>" }
        s += "<li>ATS exception domains: \(ats.exceptionDomains.count)</li>"
        let credentials = report.secrets.filter(\.isCredential).count
        s += "<li>Hard-coded credentials: \(credentials)"
        if report.secrets.count > credentials {
            s += " <small>(plus \(report.secrets.count - credentials) public client identifier(s), such as a Firebase API key in its configuration file, which identify rather than authorise)</small>"
        }
        s += "</li>"
        s += "</ul>"
        if !ats.exceptionDomains.isEmpty {
            s += "<h3>ATS exception domains (\(ats.exceptionDomains.count))</h3><div class=scroll><table><thead><tr><th>Domain</th><th>Insecure HTTP</th><th>Subdomains</th><th>Min TLS</th><th>Forward secrecy</th></tr></thead><tbody>"
            for d in ats.exceptionDomains {
                let fs = d.requiresForwardSecrecy.map { $0 ? "✓" : "✗" } ?? "default"
                s += "<tr><td><code>\(HTML.esc(d.domain))</code></td><td>\(d.allowsInsecureHTTPLoads ? "yes ⚠︎" : "no")</td><td>\(d.includesSubdomains ? "yes" : "no")</td><td class=nw>\(HTML.esc(d.minimumTLSVersion ?? "default"))</td><td>\(fs)</td></tr>"
            }
            s += "</tbody></table></div>"
        }
        if !report.hardening.isEmpty {
            s += "<h3>Binary hardening</h3><div class=scroll><table><thead><tr><th>Binary</th><th>Arch</th><th>PIE</th><th>Canary</th><th>ARC</th><th>Encrypted</th></tr></thead><tbody>"
            for h in report.hardening {
                s += "<tr><td><code>\(HTML.esc(h.name))</code></td><td class=nw>\(HTML.esc(h.architectures.joined(separator: ", ")))</td><td>\(HTML.mark(h.hasPIE))</td><td>\(HTML.mark(h.hasStackCanary))</td><td>\(HTML.mark(h.hasARC))</td><td>\(HTML.mark(h.isEncrypted))</td></tr>"
            }
            s += "</tbody></table></div>"
        }
        if !report.secrets.isEmpty {
            s += "<h3>Secret-shaped values (\(report.secrets.count)), redacted</h3><div class=scroll><table><thead><tr><th>Type</th><th>Kind</th><th>Severity</th><th>Entropy</th><th>Source</th><th>Section</th></tr></thead><tbody>"
            for h in report.secrets {
                s += "<tr><td>\(HTML.esc(h.type))</td><td class=nw>\(h.isCredential ? "credential" : "public identifier")</td><td class=\"sev-\(h.severity.rawValue)\">\(h.severity.rawValue)</td><td class=num>\(String(format: "%.1f", h.entropy))</td><td><code>\(HTML.esc(h.source))</code></td><td><code>\(HTML.esc(h.section ?? ""))</code></td></tr>"
            }
            s += "</tbody></table></div>"
        }

        if !report.network.endpoints.isEmpty {
            toc.add("endpoints", "Network endpoints", count: report.network.endpoints.count)
            s += "<h2 id=endpoints>Network endpoints (\(report.network.endpoints.count))</h2>"
            if let total = report.network.hostsBeforeCap {
                s += "<p class=note>The bundle references \(total) distinct hosts; the \(report.network.endpoints.count) listed are "
                s += "the ones the app declares, then the ones a known organisation owns, then the most referenced.</p>"
            }
            s += "<p class=note>Hosts found in the bundle, not observed traffic. Country is the owner's home jurisdiction "
            s += "from the tracker database, not where a server is hosted. First-party hosts sit under the app's own associated domains.</p>"
            s += "<div class=scroll><table><thead><tr><th>Host</th><th>Domain</th><th>Country</th><th>Owner</th><th>Category</th><th>Tracker</th><th>Hits</th><th>Sources</th></tr></thead><tbody>"
            for e in report.network.endpoints {
                let src = e.sources.prefix(3).map { URL(fileURLWithPath: $0).lastPathComponent }.joined(separator: ", ")
                s += "<tr><td><code>\(HTML.esc(e.host))</code></td>"
                s += "<td><code>\(HTML.esc(e.registrableDomain))</code></td>"
                s += "<td class=nw>\(HTML.esc(e.country ?? ""))</td>"
                s += "<td>\(HTML.esc(e.owner ?? ""))\(e.firstParty == true ? " <span class=\"pill pol-ref\">first party</span>" : "")</td>"
                s += "<td>\(HTML.esc(e.category ?? ""))</td>"
                s += "<td>\(e.isTracker ? "✓" : "")</td>"
                s += "<td class=num>\(e.occurrenceCount)</td>"
                s += "<td>\(HTML.esc(src))</td></tr>"
            }
            s += "</tbody></table></div>"
        }

        if !report.network.detectedSDKs.isEmpty {
            toc.add("sdks", "Known services", count: report.network.detectedSDKs.count)
            s += "<h2 id=sdks>Known services and SDKs referenced (\(report.network.detectedSDKs.count))</h2>"
            s += "<p class=note>Organisations in the tracker database whose domains appear in the bundle. "
            s += "Only the ones marked TRACKER count toward tracker totals.</p>"
            for sdk in report.network.detectedSDKs {
                s += "<details><summary><b>\(HTML.esc(sdk.name))</b> "
                s += "<span class=pill>\(HTML.esc(sdk.country))</span>"
                s += "<span class=pill>\(HTML.esc(sdk.category))</span>"
                if sdk.isTracker { s += "<span class=\"pill sev-critical\">TRACKER</span>" }
                s += "</summary>"
                s += "<div>Owner: \(HTML.esc(sdk.owner))</div>"
                if !sdk.frameworks.isEmpty {
                    s += "<div>Frameworks: " + sdk.frameworks.map { "<code>\(HTML.esc($0))</code>" }.joined(separator: " ") + "</div>"
                }
                if !sdk.endpoints.isEmpty {
                    s += "<div>Endpoints (\(sdk.endpoints.count)): " + sdk.endpoints.map { "<code>\(HTML.esc($0))</code>" }.joined(separator: " ") + "</div>"
                }
                s += "</details>"
            }
        }

        if !report.fileManifest.isEmpty {
            let flagged = report.fileManifest.filter(\.isSuspicious)
            toc.add("manifest-h", "File manifest", count: report.fileManifest.count)
            s += "<h2 id=manifest-h>File manifest (\(report.fileManifest.count) files\(flagged.isEmpty ? "" : ", \(flagged.count) flagged"))</h2>"
            if !flagged.isEmpty {
                s += "<h3>Flagged files</h3><div class=scroll><table><thead><tr><th>File</th><th>Kind</th><th>Size</th><th>Reason</th></tr></thead><tbody>"
                for e in flagged {
                    s += "<tr><td><code>\(HTML.esc(e.relativePath))</code></td><td class=nw>\(HTML.esc(e.kind))</td>"
                    s += "<td class=num>\(HTML.esc(HTML.byteSize(e.sizeBytes)))</td><td>\(HTML.esc(e.suspicionReason ?? ""))</td></tr>"
                }
                s += "</tbody></table></div>"
            }
            let (rows, total) = manifestRows(report.fileManifest)
            s += "<details><summary>All files (\(report.fileManifest.count))</summary>"
            if rows.count < total {
                s += "<p class=note>The \(rows.count) flagged and largest files are embedded here. "
                s += "The full list of \(total) is in <a href=\"report.json\">report.json</a>.</p>"
            }
            s += "<div id=manifest></div>"
            s += "<noscript><p class=note>The file list needs JavaScript. "
            s += "It is also in <a href=\"report.json\">report.json</a>.</p></noscript>"
            s += "<script type=\"application/json\" id=manifest-data>\(manifestJSON(rows, total: total))</script>"
            s += "</details>"
        }

        var page = "<!doctype html><html lang=en><head><meta charset=utf-8>"
        page += "<meta name=viewport content=\"width=device-width, initial-scale=1\">"
        page += "<title>\(HTML.esc(m.displayName ?? m.bundleName)): iOS scan</title>"
        page += "<style>\(ReportAssets.css)</style></head><body>"
        page += "<div class=wrap>\(toc.nav(back: dashboardPath))<main>\(s)</main></div>"
        page += "<script>\(ReportAssets.js)</script>"
        page += "</body></html>"
        return page
    }

    enum ReportAssets {
        static let css = HTML.bundledText("report/report.css")
        static let js = HTML.bundledText("report/report.js")
    }
}
