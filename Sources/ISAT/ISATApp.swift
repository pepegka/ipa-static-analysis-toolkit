import SwiftUI

struct ISATApp: App {
    @StateObject private var store = ScanStore()
    @StateObject private var appStore = AppStoreStore()

    var body: some Scene {
        WindowGroup("IPA Static Analysis Toolkit (ISAT)") {
            ContentView()
                .environmentObject(store)
                .environmentObject(appStore)
                .frame(minWidth: 1100, minHeight: 700)
                .task {
                    appStore.refreshDownloads()
                    await appStore.refreshAccount()
                }
                .onReceive(NotificationCenter.default.publisher(
                    for: NSApplication.willTerminateNotification)) { _ in
                    store.cleanupExtractions()
                }
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open IPA…") { store.openPanel() }
                    .keyboardShortcut("o", modifiers: .command)
            }
        }
    }
}
