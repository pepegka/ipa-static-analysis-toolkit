import SwiftUI
import ScannerKit

struct PrivacyManifestTab: View {
    let report: ScanReport
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if let p = report.metadata.privacyManifestPath {
                    Text("Privacy manifest").font(.headline)
                    Text(p).font(.caption.monospaced()).foregroundStyle(.secondary)
                } else {
                    Text("No PrivacyInfo.xcprivacy found in the bundle.").foregroundStyle(.secondary)
                }

                if !report.metadata.privacyAccessedAPIs.isEmpty {
                    Text("Declared accessed APIs (\(report.metadata.privacyAccessedAPIs.count))").font(.headline)
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(report.metadata.privacyAccessedAPIs, id: \.self) { api in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(api).font(.caption.monospaced().weight(.semibold))
                                if let m = PrivacyAPIMapping.table[api] {
                                    Text(m.description).font(.caption).foregroundStyle(.secondary)
                                }
                            }
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                        }
                    }
                }

                if !report.metadata.privacyTrackingDomains.isEmpty {
                    Text("Declared tracking domains (\(report.metadata.privacyTrackingDomains.count))").font(.headline)
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(report.metadata.privacyTrackingDomains, id: \.self) {
                            Text($0).font(.caption.monospaced()).textSelection(.enabled)
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
