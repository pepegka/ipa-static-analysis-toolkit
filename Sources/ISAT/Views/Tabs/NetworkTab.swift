import SwiftUI
import ScannerKit

struct NetworkTab: View {
    let report: ScanReport
    @State private var filter: String = ""
    @State private var showOnlyTrackers = false
    @State private var countryFilter: String = "All"

    var body: some View {
        let countries = Array(Set(report.network.endpoints.compactMap(\.country))).sorted()

        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Filter by host / owner …", text: $filter)
                    .textFieldStyle(.roundedBorder)
                Toggle("Trackers only", isOn: $showOnlyTrackers)
                    .toggleStyle(.button).controlSize(.small)
                Picker("Country", selection: $countryFilter) {
                    Text("All").tag("All")
                    ForEach(countries, id: \.self) { Text($0).tag($0) }
                }
                .pickerStyle(.menu).controlSize(.small)
            }
            .padding(10)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    let filtered = filteredEndpoints
                    Text("Endpoints (\(filtered.count) of \(report.network.endpoints.count))")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(filtered) { ep in
                        EndpointRow(endpoint: ep)
                    }
                    if report.network.endpoints.isEmpty {
                        Text("No endpoints extracted yet. Drop a non-FairPlay-encrypted dump to get full coverage of the main binary's strings.")
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(10)
            }
        }
    }

    private var filteredEndpoints: [ClassifiedEndpoint] {
        report.network.endpoints.filter { e in
            if showOnlyTrackers && !e.isTracker { return false }
            if countryFilter != "All" && e.country != countryFilter { return false }
            if !filter.isEmpty {
                let q = filter.lowercased()
                if !e.host.lowercased().contains(q)
                    && !(e.owner ?? "").lowercased().contains(q)
                    && !(e.category ?? "").lowercased().contains(q) { return false }
            }
            return true
        }
    }
}

struct EndpointRow: View {
    let endpoint: ClassifiedEndpoint
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                if endpoint.isTracker {
                    Image(systemName: "antenna.radiowaves.left.and.right")
                        .foregroundStyle(.red).font(.caption)
                } else if endpoint.trackerID != nil {
                    Image(systemName: "checkmark.seal").foregroundStyle(.green).font(.caption)
                } else {
                    Image(systemName: "questionmark.circle").foregroundStyle(.secondary).font(.caption)
                }
                Text(endpoint.host).font(.callout.monospaced())
                    .textSelection(.enabled)
                Spacer()
                if let c = endpoint.country { CountryChip(country: c) }
                if let cat = endpoint.category { CategoryChip(category: cat) }
                Text("×\(endpoint.occurrenceCount)").font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
                Image(systemName: expanded ? "chevron.down" : "chevron.right")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
            .onTapGesture { expanded.toggle() }

            if expanded {
                VStack(alignment: .leading, spacing: 3) {
                    if let owner = endpoint.owner {
                        Text("owner: \(owner)").font(.caption2)
                    }
                    Text("eTLD+1: \(endpoint.registrableDomain)").font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                    if !endpoint.samplePaths.isEmpty {
                        Text("paths:").font(.caption2.bold()).foregroundStyle(.secondary)
                        ForEach(endpoint.samplePaths, id: \.self) {
                            Text($0).font(.caption2.monospaced())
                                .textSelection(.enabled).foregroundStyle(.secondary)
                        }
                    }
                    if !endpoint.sources.isEmpty {
                        Text("found in:").font(.caption2.bold()).foregroundStyle(.secondary)
                        ForEach(endpoint.sources, id: \.self) {
                            Text($0).font(.caption2.monospaced())
                                .foregroundStyle(.tertiary)
                                .lineLimit(1).truncationMode(.middle)
                        }
                    }
                }
                .padding(.leading, 12)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
    }
}
