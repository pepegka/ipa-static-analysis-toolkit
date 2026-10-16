import SwiftUI
import ScannerKit

struct SecretsTab: View {
    let report: ScanReport
    @State private var filter = ""
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Filter by type / binary …", text: $filter)
                    .textFieldStyle(.roundedBorder)
            }
            .padding(10)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    let hits = filtered
                    if report.secrets.isEmpty {
                        ContentUnavailableView("No hardcoded secrets detected",
                            systemImage: "key",
                            description: Text("No strings matched known credential formats. Note: FairPlay-encrypted binaries are not scanned."))
                            .padding(.top, 40)
                    } else {
                        Text("Potential secrets (\(hits.count) of \(report.secrets.count)), values are redacted")
                            .font(.caption).foregroundStyle(.secondary)
                        ForEach(hits) { hit in
                            VStack(alignment: .leading, spacing: 4) {
                                HStack(spacing: 8) {
                                    Text(hit.severity.rawValue.uppercased())
                                        .font(.caption2.bold())
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(severityColor(hit.severity).opacity(0.18), in: Capsule())
                                        .foregroundStyle(severityColor(hit.severity))
                                    Text(hit.type).font(.callout.weight(.semibold))
                                    Spacer()
                                    Text(String(format: "entropy %.1f", hit.entropy))
                                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                                }
                                Text(hit.redactedValue).font(.caption.monospaced())
                                    .textSelection(.enabled)
                                HStack(spacing: 4) {
                                    Text(hit.source).font(.caption2.monospaced()).foregroundStyle(.tertiary)
                                        .lineLimit(1).truncationMode(.middle)
                                    if let sec = hit.section {
                                        Text("· \(sec)").font(.caption2.monospaced()).foregroundStyle(.tertiary)
                                    }
                                }
                            }
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                        }
                    }
                }
                .padding(10)
            }
        }
    }
    private var filtered: [SecretHit] {
        guard !filter.isEmpty else { return report.secrets }
        let q = filter.lowercased()
        return report.secrets.filter { $0.type.lowercased().contains(q) || $0.source.lowercased().contains(q) }
    }
}
