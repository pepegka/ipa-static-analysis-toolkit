import SwiftUI
import ScannerKit
import AppKit

struct SidebarView: View {
    @EnvironmentObject var store: ScanStore
    @EnvironmentObject var appStore: AppStoreStore

    var body: some View {
        List(selection: Binding(get: { store.selectedReportID },
                                set: { store.selectedReportID = $0 })) {
            if !store.pending.isEmpty {
                Section("Scanning") {
                    ForEach(store.pending) { p in
                        VStack(alignment: .leading, spacing: 6) {
                            Text(p.url.lastPathComponent).font(.callout).lineLimit(1).truncationMode(.middle)
                            if let err = p.error {
                                Text(err).font(.caption2).foregroundStyle(.red)
                            } else {
                                ProgressView(value: p.fraction).controlSize(.mini)
                                Text(p.phase).font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
            if !appStore.downloaded.isEmpty {
                Section("Downloaded") {
                    ForEach(appStore.downloaded) { item in
                        DownloadedRow(item: item)
                    }
                }
            }
            if !store.reports.isEmpty {
                Section("Scanned apps") {
                    ForEach(store.reports) { r in
                        SidebarRow(report: r)
                            .tag(r.id as ScanReport.ID?)
                            .contextMenu {
                                Button("Remove", role: .destructive) { store.removeReport(r.id) }
                            }
                    }
                }
            }
        }
        .listStyle(.sidebar)
    }
}

struct DownloadedRow: View {
    let item: AppStoreStore.DownloadedIPA
    @EnvironmentObject var store: ScanStore
    @EnvironmentObject var appStore: AppStoreStore

    private var isScanning: Bool {
        store.pending.contains { $0.url == item.url }
    }

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "shippingbox.fill").foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.name).font(.callout).lineLimit(1).truncationMode(.middle)
                Text(AppStoreStore.bytes(item.sizeBytes)).font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
            if isScanning {
                ProgressView().controlSize(.mini)
            } else {
                Button {
                    store.enqueue(item.url)
                } label: {
                    Image(systemName: "play.circle")
                }
                .buttonStyle(.borderless).help("Scan this app")
            }
        }
        .padding(.vertical, 2)
        .contextMenu {
            Button("Scan") { store.enqueue(item.url) }
            Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([item.url]) }
            Divider()
            Button("Delete", role: .destructive) { appStore.deleteDownload(item) }
        }
    }
}

struct SidebarRow: View {
    let report: ScanReport
    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(severityDotColor(report.findings.map(\.severity).max() ?? .info))
                .frame(width: 10, height: 10)
            VStack(alignment: .leading, spacing: 2) {
                Text(report.metadata.displayName ?? report.metadata.bundleName)
                    .font(.callout).lineLimit(1)
                Text(report.metadata.bundleID)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text("\(report.findings.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
        }
        .padding(.vertical, 2)
    }

}
