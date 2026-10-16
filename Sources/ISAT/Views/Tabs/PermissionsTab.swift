import SwiftUI
import ScannerKit

struct PermissionsTab: View {
    let report: ScanReport
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Info.plist usage descriptions (\(report.metadata.permissions.count))").font(.headline)
                VStack(spacing: 6) {
                    ForEach(report.metadata.permissions) { p in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Text(p.key).font(.caption.monospaced().weight(.semibold))
                                Spacer()
                                if let v = p.vectorID, let vec = Vectors.byID[v] {
                                    Text(vec.id).font(.caption2.weight(.bold))
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(.orange.opacity(0.18), in: Capsule())
                                        .foregroundStyle(.orange)
                                }
                            }
                            if let c = p.category {
                                Text(c).font(.caption).foregroundStyle(.secondary)
                            }
                            Text(p.value).font(.caption.italic()).foregroundStyle(.primary)
                                .textSelection(.enabled)
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                    }
                }

                if !report.metadata.queriedURLSchemes.isEmpty {
                    Text("LSApplicationQueriesSchemes (\(report.metadata.queriedURLSchemes.count))").font(.headline)
                    let cols = [GridItem(.adaptive(minimum: 160), spacing: 4)]
                    LazyVGrid(columns: cols, alignment: .leading, spacing: 4) {
                        ForEach(report.metadata.queriedURLSchemes, id: \.self) { s in
                            Text(s).font(.caption.monospaced())
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(.background.secondary, in: Capsule())
                                .textSelection(.enabled)
                        }
                    }
                }

                if !report.metadata.backgroundModes.isEmpty {
                    Text("UIBackgroundModes").font(.headline)
                    HStack {
                        ForEach(report.metadata.backgroundModes, id: \.self) { m in
                            Text(m).font(.caption.monospaced())
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(.orange.opacity(0.18), in: Capsule())
                        }
                    }
                }

                if let prov = report.metadata.provisioning {
                    Text("Provisioning entitlements (\(prov.entitlements.count))").font(.headline)
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(prov.entitlements.sorted(by: { $0.key < $1.key }), id: \.key) { kv in
                            HStack(alignment: .top) {
                                Text(kv.key).font(.caption.monospaced()).foregroundStyle(.secondary)
                                Spacer(minLength: 12)
                                Text(kv.value).font(.caption.monospaced())
                                    .textSelection(.enabled)
                            }
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
