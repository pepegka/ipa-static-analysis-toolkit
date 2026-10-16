import SwiftUI
import ScannerKit

struct VectorsTab: View {
    let report: ScanReport
    var groups: [MASVSGroup]? = nil
    @State private var expanded: Set<String> = []
    @State private var showEmpty = false

    private var shownGroups: [MASVSGroup] {
        let wanted = groups.map(Set.init) ?? Set(MASVSGroup.allCases)
        return MASVSGroup.allOrdered.filter { wanted.contains($0) }
    }

    private func vectors(in group: MASVSGroup) -> [Vector] {
        let all = Vectors.byGroup[group] ?? []
        if showEmpty { return all }
        return all.filter { v in report.findings.contains { $0.vectorID == v.id } }
    }

    var body: some View {
        let visibleGroups = shownGroups.filter { !vectors(in: $0).isEmpty }
        VStack(spacing: 0) {
            HStack {
                Spacer()
                Toggle("Show empty", isOn: $showEmpty)
                    .toggleStyle(.button).controlSize(.small)
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if visibleGroups.isEmpty {
                        ContentUnavailableView("No findings",
                            systemImage: "checkmark.shield",
                            description: Text("Nothing flagged here. Toggle \u{201c}Show empty\u{201d} to list all vectors."))
                            .padding(.top, 40)
                    }
                    ForEach(visibleGroups) { g in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(spacing: 8) {
                                Text(g.title).font(.headline)
                                Text(g.rawValue).font(.caption2.monospaced())
                                    .padding(.horizontal, 6).padding(.vertical, 2)
                                    .background(.blue.opacity(0.15), in: Capsule())
                                    .foregroundStyle(.blue)
                            }
                            Text(g.blurb).font(.caption).foregroundStyle(.secondary)
                            ForEach(vectors(in: g)) { v in
                                let findings = report.findings.filter { $0.vectorID == v.id }
                                VectorSection(vector: v, findings: findings,
                                              isExpanded: expanded.contains(v.id),
                                              toggle: { toggle(v.id) })
                            }
                        }
                    }
                }
                .padding(16)
            }
        }
    }
    private func toggle(_ id: String) {
        if expanded.contains(id) { expanded.remove(id) } else { expanded.insert(id) }
    }
}

struct VectorSection: View {
    let vector: Vector
    let findings: [Finding]
    let isExpanded: Bool
    let toggle: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Text(vector.id).font(.caption.monospaced().weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(.background, in: Capsule())
                Text(vector.title).font(.callout.weight(.medium))
                Spacer()
                Text("\(findings.count)")
                    .font(.caption.monospacedDigit().weight(.bold))
                    .padding(.horizontal, 8).padding(.vertical, 2)
                    .background(findings.isEmpty ? Color.green.opacity(0.18) : Color.orange.opacity(0.18),
                                in: Capsule())
                    .foregroundStyle(findings.isEmpty ? .green : .orange)
                Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                    .foregroundStyle(.secondary)
            }
            .padding(10)
            .contentShape(Rectangle())
            .onTapGesture { toggle() }

            if isExpanded {
                Divider()
                if findings.isEmpty {
                    Text(vector.description)
                        .font(.caption).foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                } else {
                    VStack(spacing: 0) {
                        ForEach(findings) { f in
                            FindingRow(finding: f)
                                .padding(.horizontal, 10)
                            Divider()
                        }
                    }
                }
            }
        }
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }
}
