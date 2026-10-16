import SwiftUI
import ScannerKit

struct FindingRow: View {
    let finding: Finding
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                SeverityChip(severity: finding.severity)
                Text(finding.title).font(.callout.weight(.medium))
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                if !finding.permissionsRequired.isEmpty {
                    PermissionBadge(permissions: finding.permissionsRequired,
                                    granted: finding.permissionsGranted)
                }
                Image(systemName: expanded ? "chevron.down" : "chevron.right")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
            .onTapGesture { expanded.toggle() }

            if expanded {
                expandedBody
            }
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private var expandedBody: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(finding.explanation).font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let why = finding.why, !why.isEmpty {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "scalemass")
                        .font(.caption2).foregroundStyle(.secondary)
                    Text(why).font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if let rem = finding.remediation, !rem.isEmpty {
                HStack(alignment: .top, spacing: 6) {
                    Image(systemName: "wrench.and.screwdriver")
                        .font(.caption2).foregroundStyle(.green)
                    Text(rem).font(.caption).foregroundStyle(.primary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(8)
                .background(.green.opacity(0.10), in: RoundedRectangle(cornerRadius: 6))
            }

            HStack(spacing: 8) {
                Label(finding.ruleID, systemImage: "number")
                    .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                Label(finding.vectorID, systemImage: "scope")
                    .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                if let g = Vectors.group(forVectorID: finding.vectorID) {
                    Text(g.rawValue).font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(.blue.opacity(0.15), in: Capsule())
                        .foregroundStyle(.blue)
                }
                if !finding.mitre.isEmpty {
                    Text(finding.mitre.joined(separator: " · "))
                        .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                }
                ForEach(finding.masvs, id: \.self) { tag in
                    Text(tag).font(.caption2.weight(.semibold))
                        .padding(.horizontal, 6).padding(.vertical, 1)
                        .background(.purple.opacity(0.15), in: Capsule())
                        .foregroundStyle(.purple)
                }
            }

            FrameworkLinksView(finding: finding)

            if !finding.permissionsRequired.isEmpty {
                PermissionGateDetail(permissions: finding.permissionsRequired,
                                     granted: finding.permissionsGranted)
            }

            if !finding.owningFrameworks.isEmpty {
                ChipFlow(label: "Frameworks", items: finding.owningFrameworks,
                         displayTransform: { $0 })
            }
            if !finding.affectedBinaries.isEmpty {
                ChipFlow(label: "Binaries (\(finding.affectedBinaries.count))",
                         items: finding.affectedBinaries,
                         displayTransform: { URL(fileURLWithPath: $0).lastPathComponent })
            }

            if !finding.evidences.isEmpty {
                GroupedEvidenceView(evidences: finding.evidences)
            }
        }
        .padding(.leading, 8).padding(.top, 4)
    }
}

private struct GroupedEvidenceView: View {
    let evidences: [Evidence]

    fileprivate struct Group: Identifiable {
        let id: String
        let kind: Evidence.Kind
        let value: String
        let sources: [String]
        let sections: [String]
    }

    private var groups: [Group] {
        var byKey: [String: (kind: Evidence.Kind, value: String,
                             sources: [String], sections: Set<String>)] = [:]
        var order: [String] = []
        for e in evidences {
            let key = "\(e.kind.rawValue)\u{1}\(e.value)"
            if byKey[key] == nil {
                byKey[key] = (e.kind, e.value, [], [])
                order.append(key)
            }
            if !byKey[key]!.sources.contains(e.source) {
                byKey[key]!.sources.append(e.source)
            }
            if let s = e.section { byKey[key]!.sections.insert(s) }
        }
        return order.map {
            let v = byKey[$0]!
            return Group(id: $0, kind: v.kind, value: v.value,
                         sources: v.sources, sections: v.sections.sorted())
        }
    }

    var body: some View {
        let g = groups
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("Evidence")
                    .font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                Text("\(g.count) unique · \(evidences.count) total")
                    .font(.caption2).foregroundStyle(.tertiary)
            }
            LazyVStack(alignment: .leading, spacing: 3) {
                ForEach(g) { row in
                    GroupedEvidenceRow(group: row)
                }
            }
            .padding(8)
            .background(.background, in: RoundedRectangle(cornerRadius: 6))
        }
    }
}

private struct GroupedEvidenceRow: View {
    let group: GroupedEvidenceView.Group

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(group.kind.rawValue)
                    .font(.caption2.monospaced())
                    .foregroundStyle(.tertiary)
                    .frame(width: 90, alignment: .leading)
                Text(group.value)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                if !group.sections.isEmpty {
                    Text(group.sections.joined(separator: ","))
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                        .lineLimit(1).truncationMode(.middle)
                        .help(group.sections.joined(separator: "\n"))
                }
            }
            HStack(alignment: .top, spacing: 4) {
                Text("in")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .frame(width: 90, alignment: .leading)
                FlowLayout(spacing: 4, lineSpacing: 3) {
                    ForEach(Array(group.sources.enumerated()), id: \.offset) { _, src in
                        BinaryChip(path: src)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.vertical, 2)
    }
}

private struct BinaryChip: View {
    let path: String
    var body: some View {
        let basename = URL(fileURLWithPath: path).lastPathComponent
        Text(basename)
            .font(.caption2.monospaced())
            .padding(.horizontal, 5).padding(.vertical, 1)
            .background(.background.secondary, in: Capsule())
            .help(path)
            .textSelection(.enabled)
    }
}

private struct FrameworkLinksView: View {
    let finding: Finding

    private var rows: [(String, [FrameworkRef])] {
        [("MASVS controls", FrameworkLinks.masvsControls(finding.masvsControls)),
         ("MASWE", FrameworkLinks.maswe(finding.maswe)),
         ("MASTG", FrameworkLinks.mastg(finding.mastg)),
         ("CWE", FrameworkLinks.cwe(finding.cwe)),
         ("CVSS", finding.cvss.map { [FrameworkLinks.cvss($0)] } ?? [])]
            .filter { !$0.1.isEmpty }
    }

    var body: some View {
        let profiles = FrameworkLinks.profiles(maswe: finding.maswe)
        if !rows.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                ForEach(rows, id: \.0) { label, refs in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text(label).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
                            .frame(width: 96, alignment: .leading)
                        FlowLayout(spacing: 4, lineSpacing: 3) {
                            ForEach(refs, id: \.id) { ref in
                                if let s = ref.url, let url = URL(string: s) {
                                    Link(ref.id, destination: url)
                                        .font(.caption2.monospaced())
                                        .help(ref.title ?? s)
                                } else {
                                    Text(ref.id).font(.caption2.monospaced()).textSelection(.enabled)
                                }
                            }
                        }
                    }
                }
                if !profiles.isEmpty {
                    Text("MASWE profiles: " + profiles.joined(separator: ", "))
                        .font(.caption2).foregroundStyle(.tertiary)
                }
            }
        }
    }
}

private struct ChipFlow: View {
    let label: String
    let items: [String]
    let displayTransform: (String) -> String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
            FlowLayout(spacing: 4, lineSpacing: 3) {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    Text(displayTransform(item))
                        .font(.caption2.monospaced())
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(.background, in: Capsule())
                        .help(item)
                        .textSelection(.enabled)
                }
            }
        }
    }
}

private struct PermissionBadge: View {
    let permissions: [String]
    let granted: [String]
    var body: some View {
        let allGranted = granted.count == permissions.count && !permissions.isEmpty
        let anyGranted = !granted.isEmpty
        HStack(spacing: 3) {
            Image(systemName: allGranted ? "lock.open.fill"
                              : anyGranted ? "lock.open" : "lock.fill")
                .font(.caption2)
            Text(allGranted ? "permission requested"
                 : anyGranted ? "partial permission"
                 : "permission-gated")
                .font(.caption2.weight(.medium))
        }
        .padding(.horizontal, 6).padding(.vertical, 2)
        .background(
            (allGranted ? Color.orange : (anyGranted ? Color.yellow : Color.gray))
                .opacity(0.18), in: Capsule())
        .foregroundStyle(allGranted ? .orange : (anyGranted ? .yellow : .secondary))
        .help(helpText)
    }

    private var helpText: String {
        let g = granted.isEmpty ? "(none requested)" : granted.joined(separator: ", ")
        return "Permission-gated capability.\nRequires: \(permissions.joined(separator: ", "))\nDeclared in Info.plist: \(g)"
    }
}

private struct PermissionGateDetail: View {
    let permissions: [String]
    let granted: [String]
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("Permission gate").font(.caption2.weight(.semibold)).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                ForEach(permissions, id: \.self) { p in
                    HStack(spacing: 6) {
                        let isGranted = granted.contains(p)
                        Image(systemName: isGranted ? "checkmark.circle.fill" : "circle")
                            .font(.caption2)
                            .foregroundStyle(isGranted ? .orange : .secondary)
                        Text(p).font(.caption2.monospaced())
                        Text(isGranted ? "requested in Info.plist"
                                       : "not requested, capability inert unless permission added")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
            .padding(6)
            .background(.background, in: RoundedRectangle(cornerRadius: 6))
        }
    }
}

struct FlowLayout: Layout {
    var spacing: CGFloat = 6
    var lineSpacing: CGFloat = 4

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, lineH: CGFloat = 0
        for sv in subviews {
            let size = sv.sizeThatFits(.unspecified)
            if x + size.width > maxWidth && x > 0 {
                x = 0; y += lineH + lineSpacing; lineH = 0
            }
            x += size.width + spacing
            lineH = max(lineH, size.height)
        }
        return CGSize(width: maxWidth.isFinite ? maxWidth : x, height: y + lineH)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let maxWidth = bounds.width
        var x: CGFloat = bounds.minX, y: CGFloat = bounds.minY, lineH: CGFloat = 0
        for sv in subviews {
            let size = sv.sizeThatFits(.unspecified)
            if x - bounds.minX + size.width > maxWidth && x > bounds.minX {
                x = bounds.minX; y += lineH + lineSpacing; lineH = 0
            }
            sv.place(at: CGPoint(x: x, y: y), proposal: .unspecified)
            x += size.width + spacing
            lineH = max(lineH, size.height)
        }
    }
}

struct SeverityChip: View {
    let severity: Severity
    var body: some View {
        Text(severity.rawValue.uppercased())
            .font(.caption2.weight(.bold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.2), in: Capsule())
            .foregroundStyle(color)
    }
    private var color: Color {
        switch severity {
        case .info: return .gray
        case .low: return .blue
        case .medium: return .yellow
        case .high: return .orange
        case .critical: return .red
        }
    }
}
