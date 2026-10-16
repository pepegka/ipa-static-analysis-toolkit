import SwiftUI
import ScannerKit

struct StringsTab: View {
    let report: ScanReport
    @EnvironmentObject var store: ScanStore
    @State private var selectedBinary: String?
    @State private var query: String = ""
    @State private var isRegex: Bool = false
    @State private var caseSensitive: Bool = false
    @State private var enabledSections: Set<String> = []

    var body: some View {
        let indices = store.indices(for: report.id)
        if indices.isEmpty {
            ProgressView("Indexing binaries…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            HStack(spacing: 0) {
                BinaryListColumn(indices: indices, selection: $selectedBinary)
                    .frame(width: 280)
                Divider()
                if let key = selectedBinary ?? indices.keys.sorted().first,
                   let bi = indices[key] {
                    StringSearchPane(index: bi,
                                     query: $query,
                                     isRegex: $isRegex,
                                     caseSensitive: $caseSensitive,
                                     enabledSections: $enabledSections)
                } else {
                    Text("Select a binary").foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
    }
}

struct BinaryListColumn: View {
    let indices: [String: BinaryIndex]
    @Binding var selection: String?

    var body: some View {
        let sorted = indices.values.sorted { lhs, rhs in
            if lhs.isMainExecutable != rhs.isMainExecutable { return lhs.isMainExecutable }
            return lhs.totalStrings > rhs.totalStrings
        }
        List(selection: $selection) {
            ForEach(sorted, id: \.relativePath) { bi in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 4) {
                            if bi.isMainExecutable {
                                Image(systemName: "star.fill")
                                    .foregroundStyle(.yellow).font(.caption2)
                            }
                            Text(URL(fileURLWithPath: bi.relativePath).lastPathComponent)
                                .font(.callout.weight(.medium))
                                .lineLimit(1).truncationMode(.middle)
                        }
                        Text(bi.relativePath).font(.caption2.monospaced())
                            .foregroundStyle(.tertiary)
                            .lineLimit(1).truncationMode(.middle)
                    }
                    Spacer()
                    Text("\(bi.totalStrings)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                .tag(bi.relativePath as String?)
            }
        }
        .listStyle(.sidebar)
    }
}

struct StringSearchPane: View {
    let index: BinaryIndex
    @Binding var query: String
    @Binding var isRegex: Bool
    @Binding var caseSensitive: Bool
    @Binding var enabledSections: Set<String>

    @State private var compileError: String?

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("Filter (literal or regex)…", text: $query)
                        .textFieldStyle(.roundedBorder)
                    Toggle("regex", isOn: $isRegex).toggleStyle(.button).controlSize(.small)
                    Toggle("Aa", isOn: $caseSensitive).toggleStyle(.button).controlSize(.small)
                }
                if let err = compileError {
                    Text(err).font(.caption2).foregroundStyle(.red)
                }
                let allSections = index.perSectionStrings.map(\.section.qualifiedName)
                if !allSections.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            ForEach(allSections, id: \.self) { name in
                                let on = enabledSections.isEmpty || enabledSections.contains(name)
                                Toggle(isOn: Binding(
                                    get: { on },
                                    set: { v in
                                        if enabledSections.isEmpty { enabledSections = Set(allSections) }
                                        if v { enabledSections.insert(name) } else { enabledSections.remove(name) }
                                        if enabledSections.count == allSections.count { enabledSections.removeAll() }
                                    })) {
                                        Text(name).font(.caption2.monospaced())
                                    }
                                    .toggleStyle(.button).controlSize(.small)
                            }
                        }
                    }
                }
                HStack(spacing: 8) {
                    Label("\(index.totalStrings) strings", systemImage: "text.alignleft")
                        .font(.caption2).foregroundStyle(.secondary)
                    if !index.encryptedSectionsSkipped.isEmpty {
                        Label("\(index.encryptedSectionsSkipped.count) FairPlay-encrypted sections skipped",
                              systemImage: "lock.fill")
                            .font(.caption2).foregroundStyle(.orange)
                    }
                    if index.stringCountCapped {
                        Label("capped", systemImage: "exclamationmark.triangle")
                            .font(.caption2).foregroundStyle(.orange)
                    }
                    Spacer()
                    Label("\(index.importedSymbols.count) imported / \(index.definedSymbols.count) defined symbols",
                          systemImage: "function")
                        .font(.caption2).foregroundStyle(.secondary)
                }
            }
            .padding(10)
            Divider()
            ResultsList(index: index, query: query, isRegex: isRegex,
                        caseSensitive: caseSensitive,
                        enabledSections: enabledSections,
                        compileError: $compileError)
        }
    }
}

struct ResultsList: View {
    let index: BinaryIndex
    let query: String
    let isRegex: Bool
    let caseSensitive: Bool
    let enabledSections: Set<String>
    @Binding var compileError: String?

    struct Row: Identifiable, Hashable, Sendable {
        let id: Int
        let section: String
        let offset: UInt64
        let isUTF16: Bool
        let value: String
    }

    @State private var rows: [Row] = []
    @State private var computing = false

    private struct SearchKey: Equatable {
        let query: String
        let isRegex: Bool
        let caseSensitive: Bool
        let enabledSections: Set<String>
        let binary: String
    }
    private var searchKey: SearchKey {
        SearchKey(query: query, isRegex: isRegex, caseSensitive: caseSensitive,
                  enabledSections: enabledSections, binary: index.relativePath)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                Text("\(rows.count) match\(rows.count == 1 ? "" : "es")")
                    .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                if computing {
                    ProgressView().controlSize(.small).scaleEffect(0.6)
                }
                Spacer()
            }
            .padding(.horizontal, 10).padding(.vertical, 4)
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(rows) { r in
                        HStack(alignment: .top, spacing: 8) {
                            Text(r.section).font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                                .frame(width: 200, alignment: .leading)
                                .lineLimit(1).truncationMode(.middle)
                            Text(String(format: "0x%llx", r.offset))
                                .font(.caption2.monospaced())
                                .foregroundStyle(.tertiary)
                                .frame(width: 90, alignment: .leading)
                            if r.isUTF16 {
                                Text("u16").font(.caption2.monospaced())
                                    .foregroundStyle(.tertiary)
                                    .frame(width: 32)
                            } else {
                                Color.clear.frame(width: 32)
                            }
                            Text(r.value).font(.caption.monospaced())
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .padding(.vertical, 2).padding(.horizontal, 10)
                        Divider().opacity(0.4)
                    }
                }
            }
        }
        .task(id: searchKey) {
            await runSearch(key: searchKey)
        }
    }

    private func runSearch(key: SearchKey) async {
        computing = true
        do { try await Task.sleep(nanoseconds: 200_000_000) }
        catch { return }
        if Task.isCancelled { return }

        let index = self.index
        let result = await Task.detached(priority: .userInitiated) {
            Self.computeRows(index: index, query: key.query, isRegex: key.isRegex,
                             caseSensitive: key.caseSensitive, enabledSections: key.enabledSections)
        }.value
        if Task.isCancelled { return }
        rows = result.rows
        compileError = result.error
        computing = false
    }

    nonisolated private static func computeRows(index: BinaryIndex, query: String, isRegex: Bool,
                                                caseSensitive: Bool,
                                                enabledSections: Set<String>) -> (rows: [Row], error: String?) {
        let q = query.trimmingCharacters(in: .whitespaces)
        let regex: Regex<AnyRegexOutput>?
        if isRegex && !q.isEmpty {
            do {
                let r = try Regex(q)
                regex = caseSensitive ? r : r.ignoresCase()
            } catch {
                return ([], "Regex: \(error.localizedDescription)")
            }
        } else {
            regex = nil
        }
        let needle = caseSensitive ? q : q.lowercased()

        var out: [Row] = []
        out.reserveCapacity(2048)
        let cap = 1_000_000
        var counter = 0
        for ss in index.perSectionStrings {
            let qname = ss.section.qualifiedName
            if !enabledSections.isEmpty && !enabledSections.contains(qname) { continue }
            for s in ss.strings {
                if !q.isEmpty {
                    if let regex {
                        if (try? regex.firstMatch(in: s.value)) == nil { continue }
                    } else {
                        let hay = caseSensitive ? s.value : s.value.lowercased()
                        if !hay.contains(needle) { continue }
                    }
                }
                out.append(Row(id: counter, section: qname, offset: s.offset,
                               isUTF16: s.isUTF16, value: s.value))
                counter += 1
                if out.count >= cap { return (out, nil) }
            }
        }
        return (out, nil)
    }
}
