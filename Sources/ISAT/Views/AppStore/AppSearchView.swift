import SwiftUI
import AppKit

struct AppSearchView: View {
    @EnvironmentObject var appStore: AppStoreStore
    @EnvironmentObject var scanStore: ScanStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
        }
        .frame(width: 720, height: 520)
    }

    private var header: some View {
        VStack(spacing: 8) {
            HStack {
                Text("App Store").font(.headline)
                Spacer()
                Button {
                    dismiss()
                } label: {
                    Label("Close", systemImage: "xmark.circle.fill")
                }
                .buttonStyle(.borderless)
                .keyboardShortcut(.cancelAction)
                .help("Close")
            }
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search the App Store…", text: $appStore.searchTerm)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { runSearch() }
                Picker("", selection: $appStore.platform) {
                    Text("iPhone").tag("iphone")
                    Text("iPad").tag("ipad")
                    Text("Apple TV").tag("appletv")
                }
                .pickerStyle(.menu).frame(width: 110).labelsHidden()
                Button("Search") { runSearch() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(appStore.isSearching)
            }
            HStack(spacing: 6) {
                if let acc = appStore.account {
                    Image(systemName: "checkmark.seal.fill").font(.caption2).foregroundStyle(.green)
                    Text("Signed in as \(acc.email)").font(.caption2).foregroundStyle(.secondary)
                } else {
                    Image(systemName: "exclamationmark.triangle.fill").font(.caption2).foregroundStyle(.orange)
                    Text("Not signed in, log in to search and download.").font(.caption2).foregroundStyle(.secondary)
                }
                Spacer()
                if appStore.isSearching { ProgressView().controlSize(.small) }
            }
        }
        .padding(12)
    }

    @ViewBuilder
    private var content: some View {
        if let err = appStore.searchError, appStore.results.isEmpty {
            VStack(spacing: 8) {
                Image(systemName: "magnifyingglass").font(.largeTitle).foregroundStyle(.secondary)
                Text(err).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if appStore.results.isEmpty {
            Text("Search for an app to download and scan.")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            List(appStore.results) { app in
                AppResultRow(app: app, onDownload: { download(app, thenScan: false) },
                             onDownloadAndScan: { download(app, thenScan: true) })
            }
            .listStyle(.inset)
            if let err = appStore.actionError {
                Text(err).font(.caption).foregroundStyle(.red)
                    .padding(.horizontal, 12).padding(.bottom, 6)
            }
        }
    }

    private func runSearch() {
        Task { await appStore.search() }
    }

    private func download(_ app: IpatoolApp, thenScan: Bool) {
        Task {
            let dir = AppStoreStore.defaultDownloadDirectory()
            guard let url = await appStore.download(app, into: dir) else { return }
            if thenScan {
                scanStore.enqueue(url)
                dismiss()
            } else {
                NSWorkspace.shared.activateFileViewerSelecting([url])
            }
        }
    }
}

private struct AppResultRow: View {
    let app: IpatoolApp
    let onDownload: () -> Void
    let onDownloadAndScan: () -> Void
    @EnvironmentObject var appStore: AppStoreStore

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(app.name).font(.callout.weight(.medium)).lineLimit(1)
                Text(app.bundleID).font(.caption2.monospaced()).foregroundStyle(.secondary).lineLimit(1)
                HStack(spacing: 8) {
                    Text("v\(app.version)").font(.caption2).foregroundStyle(.tertiary)
                    Text(app.price == 0 ? "Free" : String(format: "$%.2f", app.price))
                        .font(.caption2).foregroundStyle(.tertiary)
                    Text("ID \(String(app.id))").font(.caption2.monospaced()).foregroundStyle(.tertiary)
                }
            }
            Spacer()
            if appStore.isDownloading(app) {
                VStack(alignment: .trailing, spacing: 3) {
                    Text(appStore.downloadStatus[app.id] ?? "Downloading…")
                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                    if let frac = appStore.downloadProgress[app.id] {
                        ProgressView(value: frac).controlSize(.small).frame(width: 160)
                    } else {
                        ProgressView().controlSize(.small).frame(width: 160)
                    }
                }
                .frame(minWidth: 160, alignment: .trailing)
            } else {
                Button("Download", action: onDownload)
                    .controlSize(.small)
                Button("Download & Scan", action: onDownloadAndScan)
                    .controlSize(.small).buttonStyle(.borderedProminent)
            }
        }
        .padding(.vertical, 4)
        .disabled(!appStore.isLoggedIn)
    }
}
