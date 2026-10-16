import SwiftUI
import ScannerKit

struct BinariesTab: View {
    let report: ScanReport
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                Text("Mach-O binaries (\(report.metadata.embeddedBinaries.count))").font(.headline)
                ForEach(report.metadata.embeddedBinaries) { bin in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Image(systemName: bin.isFairPlayEncrypted ? "lock.fill" : "cpu")
                                .foregroundStyle(bin.isFairPlayEncrypted ? .orange : .secondary)
                            Text(bin.name).font(.callout.monospaced().weight(.semibold))
                            Spacer()
                            Text(ByteCountFormatter.string(fromByteCount: Int64(bin.sizeBytes), countStyle: .file))
                                .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            Text(bin.architectures.joined(separator: ", "))
                                .font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                        Text(bin.relativePath).font(.caption2.monospaced()).foregroundStyle(.tertiary)
                            .lineLimit(1).truncationMode(.middle)
                        if !bin.linkedDylibs.isEmpty {
                            DisclosureGroup("Linked dylibs (\(bin.linkedDylibs.count))") {
                                VStack(alignment: .leading, spacing: 1) {
                                    ForEach(bin.linkedDylibs, id: \.self) {
                                        Text($0).font(.caption2.monospaced()).foregroundStyle(.secondary)
                                            .textSelection(.enabled)
                                    }
                                }
                                .padding(.leading, 8)
                            }
                            .font(.caption)
                        }
                    }
                    .padding(8)
                    .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                }
            }
            .padding(16)
        }
    }
}
