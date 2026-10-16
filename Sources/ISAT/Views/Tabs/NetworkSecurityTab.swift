import SwiftUI
import ScannerKit

struct NetworkSecurityTab: View {
    let report: ScanReport
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                let ats = report.ats

                Text("App Transport Security \u{00B7} MASVS-NETWORK").font(.headline)
                VStack(spacing: 6) {
                    PassFailChipRow(label: "Arbitrary loads (global)", risky: ats.allowsArbitraryLoads)
                    PassFailChipRow(label: "Arbitrary loads in web content", risky: ats.allowsArbitraryLoadsInWebContent)
                    PassFailChipRow(label: "Arbitrary loads for media", risky: ats.allowsArbitraryLoadsForMedia)
                    PassFailChipRow(label: "Local networking allowed", risky: ats.allowsLocalNetworking)
                }
                .padding(8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))

                if !ats.exceptionDomains.isEmpty {
                    Text("ATS exception domains (\(ats.exceptionDomains.count))").font(.headline)
                    ForEach(ats.exceptionDomains) { d in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(d.domain).font(.callout.monospaced().weight(.semibold))
                                    .textSelection(.enabled)
                                Spacer()
                                if d.allowsInsecureHTTPLoads {
                                    Text("CLEARTEXT").font(.caption2.bold())
                                        .padding(.horizontal, 6).padding(.vertical, 2)
                                        .background(.red.opacity(0.18), in: Capsule()).foregroundStyle(.red)
                                }
                            }
                            HStack(spacing: 10) {
                                if d.includesSubdomains { Text("subdomains").font(.caption2).foregroundStyle(.secondary) }
                                Text("min TLS: \(d.minimumTLSVersion ?? "default")").font(.caption2).foregroundStyle(.secondary)
                                if let fs = d.requiresForwardSecrecy {
                                    Text("forward secrecy: \(fs ? "yes" : "no")").font(.caption2).foregroundStyle(.secondary)
                                }
                            }
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
                    }
                }

                Divider().padding(.vertical, 4)

                Text("URL-scheme attack surface").font(.headline)
                if report.metadata.urlSchemes.isEmpty {
                    Text("The app declares no custom URL schemes of its own.").foregroundStyle(.secondary)
                } else {
                    Text("Own schemes (\(report.metadata.urlSchemes.count)): entry points other apps can invoke. Queried schemes are listed under Permissions.")
                        .font(.caption).foregroundStyle(.secondary)
                    SchemeGrid(schemes: report.metadata.urlSchemes, tint: .orange)
                }
            }
            .padding(16)
        }
    }
}

private struct PassFailChipRow: View {
    let label: String
    let risky: Bool
    var body: some View {
        HStack {
            Image(systemName: risky ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(risky ? .orange : .green)
            Text(label).font(.callout)
            Spacer()
            Text(risky ? "weakened" : "default/secure")
                .font(.caption2.weight(.medium))
                .foregroundStyle(risky ? .orange : .green)
        }
    }
}

private struct SchemeGrid: View {
    let schemes: [String]
    let tint: Color
    var body: some View {
        let cols = [GridItem(.adaptive(minimum: 150), spacing: 4)]
        LazyVGrid(columns: cols, alignment: .leading, spacing: 4) {
            ForEach(schemes, id: \.self) { s in
                Text(s).font(.caption.monospaced())
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(tint.opacity(0.15), in: Capsule())
                    .textSelection(.enabled)
            }
        }
    }
}
