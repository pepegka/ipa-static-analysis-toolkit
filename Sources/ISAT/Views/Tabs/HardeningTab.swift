import SwiftUI
import ScannerKit

func severityColor(_ s: Severity) -> Color {
    switch s {
    case .info: return .secondary
    case .low: return .blue
    case .medium: return .yellow
    case .high: return .orange
    case .critical: return .red
    }
}

private struct PassFailChip: View {
    let label: String
    let state: Bool?
    var body: some View {
        let (color, symbol, text): (Color, String, String) = {
            switch state {
            case .some(true):  return (.green, "checkmark.circle.fill", "\(label)")
            case .some(false): return (.red, "xmark.circle.fill", "\(label)")
            case .none:        return (.secondary, "questionmark.circle", "\(label)?")
            }
        }()
        HStack(spacing: 3) {
            Image(systemName: symbol).font(.caption2)
            Text(text).font(.caption2.weight(.medium))
        }
        .padding(.horizontal, 6).padding(.vertical, 2)
        .background(color.opacity(0.15), in: Capsule())
        .foregroundStyle(color)
    }
}

struct HardeningTab: View {
    let report: ScanReport
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                if report.hardening.isEmpty {
                    ContentUnavailableView("No hardening data",
                        systemImage: "lock.shield",
                        description: Text("Hardening is computed from Mach-O headers and the symbol index. Re-scan with indexing enabled for full coverage."))
                } else {
                    Text("Binary hardening (\(report.hardening.count)) \u{00B7} MASVS-RESILIENCE / MASVS-CODE")
                        .font(.headline)
                    Text("PIE/ASLR and encryption come from the Mach-O header; stack canary and ARC are inferred from the symbol table (\"?\" = not indexed).")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(report.hardening) { h in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack(spacing: 8) {
                                Text(h.name).font(.callout.monospaced().weight(.semibold))
                                Spacer()
                                Text(h.architectures.joined(separator: ", "))
                                    .font(.caption2.monospaced()).foregroundStyle(.secondary)
                            }
                            HStack(spacing: 6) {
                                PassFailChip(label: "PIE", state: h.hasPIE)
                                PassFailChip(label: "Canary", state: h.hasStackCanary)
                                PassFailChip(label: "ARC", state: h.hasARC)
                                PassFailChip(label: "Encrypted", state: h.isEncrypted)
                            }
                            Text(h.relativePath).font(.caption2.monospaced()).foregroundStyle(.tertiary)
                                .lineLimit(1).truncationMode(.middle)
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                    }
                }
            }
            .padding(16)
        }
    }
}
