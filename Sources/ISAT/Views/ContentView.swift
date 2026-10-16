import SwiftUI
import ScannerKit
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject var store: ScanStore
    @EnvironmentObject var appStore: AppStoreStore
    @State private var isDropTargeted = false
    @State private var showLogin = false
    @State private var showSearch = false

    var body: some View {
        NavigationSplitView {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 240, ideal: 280, max: 360)
        } detail: {
            ZStack {
                if let report = store.selectedReport {
                    ReportDetailView(report: report)
                } else {
                    EmptyDropView(onLogin: { showLogin = true }, onSearch: { openSearch() })
                }
                if isDropTargeted {
                    Color.accentColor.opacity(0.10).overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 3, dash: [10]))
                            .padding(12)
                    ).allowsHitTesting(false)
                }
            }
            .onDrop(of: [UTType.fileURL], isTargeted: $isDropTargeted) { providers in
                handleDrop(providers)
            }
        }
        .sheet(isPresented: $showLogin) { LoginView() }
        .sheet(isPresented: $showSearch) { AppSearchView() }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                if let acc = appStore.account {
                    Menu {
                        Text(acc.email)
                        Button("Sign Out") { Task { await appStore.logout() } }
                    } label: {
                        Label(acc.name.isEmpty ? acc.email : acc.name, systemImage: "person.crop.circle.fill")
                    }
                } else {
                    Button { showLogin = true } label: {
                        Label("Log In", systemImage: "person.crop.circle")
                    }
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button { openSearch() } label: {
                    Label("Search App Store…", systemImage: "magnifyingglass")
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    store.openPanel()
                } label: {
                    Label("Open IPA…", systemImage: "tray.and.arrow.down")
                }
            }
            ToolbarItem(placement: .primaryAction) {
                if let report = store.selectedReport {
                    Menu {
                        Button("Export HTML…") { exportReport(report, format: .html) }
                        Button("Export Markdown…") { exportReport(report, format: .markdown) }
                        Button("Export JSON…") { exportReport(report, format: .json) }
                        Button("Export SARIF…") { exportReport(report, format: .sarif) }
                        Divider()
                        Button("Update rule pack…") { promptForRuleUpdate() }
                    } label: {
                        Label("Export…", systemImage: "square.and.arrow.up")
                    }
                }
            }
        }
    }

    private func exportReport(_ report: ScanReport, format: ReportExporter.Format) {
        let panel = NSSavePanel()
        let contentType: UTType = {
            switch format {
            case .html: return .html
            case .json, .sarif: return .json
            case .markdown: return .plainText
            }
        }()
        panel.allowedContentTypes = [contentType]
        let stem = (report.metadata.displayName ?? report.metadata.bundleName)
            .replacingOccurrences(of: "/", with: "-")
        panel.nameFieldStringValue = "\(stem).\(format.fileExtension)"
        if panel.runModal() == .OK, let url = panel.url {
            do {
                try ReportExporter.write(report, format: format, to: url)
            } catch {
                let a = NSAlert(); a.messageText = "Export failed"; a.informativeText = "\(error)"
                a.runModal()
            }
        }
    }

    private func promptForRuleUpdate() {
        let a = NSAlert()
        a.messageText = "Update rule pack"
        a.informativeText = "Enter the URL of a .yaml file or .tar.gz pack to install into Application Support."
        let field = NSTextField(frame: NSRect(x: 0, y: 0, width: 360, height: 22))
        field.placeholderString = "https://…/rules.tar.gz"
        a.accessoryView = field
        a.addButton(withTitle: "Install")
        a.addButton(withTitle: "Cancel")
        guard a.runModal() == .alertFirstButtonReturn else { return }
        guard let url = URL(string: field.stringValue), !field.stringValue.isEmpty else { return }
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let dir = try RuleUpdater.downloadAndInstall(from: url)
                DispatchQueue.main.async {
                    let ok = NSAlert(); ok.messageText = "Rule pack installed"
                    ok.informativeText = "Installed at \(dir.path).\nRestart the app or rescan to pick up the new rules."
                    ok.runModal()
                }
            } catch {
                DispatchQueue.main.async {
                    let fail = NSAlert(); fail.messageText = "Update failed"; fail.informativeText = "\(error)"
                    fail.runModal()
                }
            }
        }
    }

    private func openSearch() {
        Task { await appStore.refreshAccount() }
        showSearch = true
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
        var anyAccepted = false
        for p in providers {
            _ = p.loadObject(ofClass: URL.self) { url, _ in
                guard let url, url.pathExtension.lowercased() == "ipa" else { return }
                Task { @MainActor in store.enqueue(url) }
            }
            anyAccepted = true
        }
        return anyAccepted
    }
}

struct EmptyDropView: View {
    @EnvironmentObject var appStore: AppStoreStore
    var onLogin: () -> Void
    var onSearch: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "tray.and.arrow.down.fill")
                .font(.system(size: 64, weight: .light))
                .foregroundStyle(.secondary)
            Text("Drop an .ipa file here")
                .font(.title2)
            Text("or use ⌘O. The scanner runs locally and stays on your machine.")
                .font(.callout)
                .foregroundStyle(.secondary)

            Divider().frame(width: 280).padding(.vertical, 4)

            Text("…or pull an app straight from the App Store:")
                .font(.callout).foregroundStyle(.secondary)
            HStack(spacing: 12) {
                if appStore.isLoggedIn {
                    Label("Signed in as \(appStore.account?.email ?? "")", systemImage: "checkmark.seal.fill")
                        .font(.caption).foregroundStyle(.green)
                } else {
                    Button {
                        onLogin()
                    } label: {
                        Label("Log In with Apple ID", systemImage: "person.crop.circle")
                    }
                    .controlSize(.large)
                }
                Button {
                    onSearch()
                } label: {
                    Label("Search & Download", systemImage: "magnifyingglass")
                }
                .controlSize(.large).buttonStyle(.borderedProminent)
            }
        }
        .padding(40)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
