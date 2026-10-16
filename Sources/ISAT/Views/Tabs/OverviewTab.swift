import SwiftUI
import Charts
import ScannerKit

func severityDotColor(_ sev: Severity) -> Color {
    switch sev {
    case .info: return .gray
    case .low: return .blue
    case .medium: return .yellow
    case .high: return .orange
    case .critical: return .red
    }
}

struct OverviewTab: View {
    let report: ScanReport
    @State private var showAllVectors = false

    var body: some View {
        Form {
            if !report.notes.isEmpty {
                Section("Scanner notes") {
                    ForEach(report.notes, id: \.self) { n in
                        Label { Text(n).foregroundStyle(.secondary) }
                            icon: { Image(systemName: "info.circle").foregroundStyle(.secondary) }
                            .font(.callout)
                    }
                }
            }

            ClusterSection(clusters: report.findings.clusterRollup())

            VectorCoverageSection(summaries: report.vectorSummaries,
                                  showAll: $showAllVectors)

            Section("Bundle") {
                let m = report.metadata
                bundleRow("Name", m.displayName ?? m.bundleName)
                bundleRow("Bundle ID", m.bundleID, mono: true)
                if let v = m.shortVersion { bundleRow("Version", v) }
                if let b = m.bundleVersion { bundleRow("Build", b) }
                if let exe = m.executableName { bundleRow("Executable", exe, mono: true) }
                if let min = m.minimumOSVersion { bundleRow("Minimum iOS", min) }
                if !m.supportedPlatforms.isEmpty {
                    bundleRow("Platforms", m.supportedPlatforms.joined(separator: ", "))
                }
                if let team = m.signedTeamID { bundleRow("Signed by team", team, mono: true) }
                if let prov = m.provisioning {
                    bundleRow("Profile type", prov.kind.rawValue)
                    if let name = prov.teamName { bundleRow("Profile team", name) }
                    if let exp = prov.expirationDate {
                        bundleRow("Profile expires", exp.formatted(date: .abbreviated, time: .omitted))
                    }
                }
            }

            TopFindingsSection(findings: report.findings)
        }
        .formStyle(.grouped)
    }

    private func bundleRow(_ label: String, _ value: String, mono: Bool = false) -> some View {
        LabeledContent(label) {
            Text(value)
                .font(mono ? .body.monospaced() : .body)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .multilineTextAlignment(.trailing)
        }
    }
}

private struct ClusterSection: View {
    let clusters: [ClusterSummary]
    @State private var expanded: Set<String> = []

    var body: some View {
        Section {
            if clusters.isEmpty {
                Text("Nothing flagged.").foregroundStyle(.secondary)
            } else {
                ForEach(clusters) { c in
                    LabeledContent {
                        Text("\(c.findingCount)").font(.body.monospacedDigit().weight(.semibold))
                            .foregroundStyle(severityDotColor(c.maxSeverity))
                    } label: {
                        HStack(spacing: 8) {
                            Circle().fill(severityDotColor(c.maxSeverity)).frame(width: 8, height: 8)
                            Text(c.title)
                            Text(c.id).font(.caption.monospaced()).foregroundStyle(.tertiary)
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture {
                        if expanded.contains(c.id) { expanded.remove(c.id) } else { expanded.insert(c.id) }
                    }
                    if expanded.contains(c.id) {
                        ForEach(c.children) { w in
                            LabeledContent {
                                Text("\(w.findingCount)").font(.caption.monospacedDigit())
                                    .foregroundStyle(.secondary)
                            } label: {
                                HStack(spacing: 6) {
                                    Text("↳").foregroundStyle(.tertiary)
                                    Text(w.title).font(.caption)
                                    Text(w.id).font(.caption2.monospaced()).foregroundStyle(.tertiary)
                                }
                            }
                        }
                    }
                }
            }
        } header: {
            Label("Findings by cluster", systemImage: "square.grid.2x2")
        } footer: {
            Text("OWASP MASVS control groups plus Apple App Store policy. Tap a cluster for its MASWE weakness classes.")
        }
    }
}

private struct VectorCoverageSection: View {
    let summaries: [VectorSummary]
    @Binding var showAll: Bool

    private var shown: [VectorSummary] {
        showAll ? summaries : summaries.filter { $0.uniqueArtifactCount > 0 }
    }

    var body: some View {
        Section {
            if shown.isEmpty {
                Text("No vectors with findings.").foregroundStyle(.secondary)
            } else {
                Chart {
                    ForEach(shown) { s in
                        let v = Vectors.byID[s.vectorID]
                        BarMark(
                            x: .value("Count", s.uniqueArtifactCount),
                            y: .value("Vector", v?.id ?? s.vectorID)
                        )
                        .foregroundStyle(severityDotColor(s.maxSeverity))
                        .annotation(position: .trailing) {
                            if s.uniqueArtifactCount > 0 {
                                Text("\(s.uniqueArtifactCount)").font(.caption2.monospacedDigit())
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                .chartXAxis { AxisMarks(position: .bottom) }
                .chartYAxis { AxisMarks(position: .leading) }
                .frame(height: CGFloat(shown.count) * 24 + 24)
            }
        } header: {
            HStack {
                Text("Vector coverage")
                Spacer()
                let hitCount = summaries.filter { $0.uniqueArtifactCount > 0 }.count
                Button(showAll ? "Show hits only" : "Show all \(summaries.count)") {
                    showAll.toggle()
                }
                .font(.caption)
                .disabled(hitCount == summaries.count)
            }
        }
    }
}

private struct TopFindingsSection: View {
    let findings: [Finding]
    private let cap = 12
    var body: some View {
        let top = Array(findings.prefix(cap))
        Section {
            if top.isEmpty {
                Text("No findings.").foregroundStyle(.secondary)
            } else {
                ForEach(top) { FindingRow(finding: $0) }
            }
        } header: {
            Text("Top findings")
        } footer: {
            if findings.count > cap {
                Text("Showing \(cap) of \(findings.count). See the Privacy / Security / Network tabs for the full list.")
            }
        }
    }
}
