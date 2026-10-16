import SwiftUI
import ScannerKit

struct SDKsTab: View {
    let report: ScanReport
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                let sdks = report.network.detectedSDKs
                if !sdks.isEmpty {
                    Text("Detected SDKs (\(sdks.count))").font(.headline)
                    VStack(spacing: 6) {
                        ForEach(sdks) { sdk in
                            DetectedSDKRow(sdk: sdk)
                        }
                    }
                }
                if report.metadata.embeddedFrameworks.isEmpty {
                    Text("No embedded Frameworks/ found.").foregroundStyle(.secondary)
                } else {
                    Divider().padding(.vertical, 6)
                    Text("Embedded frameworks (\(report.metadata.embeddedFrameworks.count))")
                        .font(.headline)
                    let cols = [GridItem(.adaptive(minimum: 220), spacing: 6)]
                    LazyVGrid(columns: cols, alignment: .leading, spacing: 6) {
                        ForEach(report.metadata.embeddedFrameworks, id: \.self) { fw in
                            HStack(spacing: 6) {
                                Image(systemName: "shippingbox").foregroundStyle(.secondary)
                                Text(fw).font(.caption.monospaced()).textSelection(.enabled)
                                    .lineLimit(1).truncationMode(.middle)
                            }
                            .padding(6)
                            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 6))
                        }
                    }
                }
            }
            .padding(16)
        }
    }
}

struct DetectedSDKRow: View {
    let sdk: DetectedSDK
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(sdk.name).font(.callout.weight(.semibold))
                CountryChip(country: sdk.country)
                CategoryChip(category: sdk.category)
                if sdk.isTracker {
                    Text("TRACKER").font(.caption2.bold())
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(.red.opacity(0.15), in: Capsule())
                        .foregroundStyle(.red)
                }
                Spacer()
                Text("\(sdk.evidenceCount) hits").font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 4) {
                Text("owner:").font(.caption2).foregroundStyle(.tertiary)
                Text(sdk.owner).font(.caption2)
            }
            if !sdk.endpoints.isEmpty {
                VStack(alignment: .leading, spacing: 1) {
                    Text("endpoints (\(sdk.endpoints.count)):").font(.caption2).foregroundStyle(.tertiary)
                    ForEach(sdk.endpoints, id: \.self) { ep in
                        Text(ep).font(.caption2.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            if !sdk.frameworks.isEmpty {
                VStack(alignment: .leading, spacing: 1) {
                    Text("frameworks:").font(.caption2).foregroundStyle(.tertiary)
                    ForEach(sdk.frameworks, id: \.self) { fw in
                        Text(fw).font(.caption2.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
    }
}

struct CountryChip: View {
    let country: String
    var body: some View {
        Text(country).font(.caption2.monospaced().bold())
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(.gray.opacity(0.15), in: Capsule())
            .foregroundStyle(.secondary)
    }
}

struct CategoryChip: View {
    let category: String
    var body: some View {
        Text(category).font(.caption2.monospaced())
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(.gray.opacity(0.15), in: Capsule())
            .foregroundStyle(.secondary)
    }
}
