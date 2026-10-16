import Foundation

public enum ChildSafetyAnalyzer {

    public static func analyze(metadata: BundleMetadata,
                               network: NetworkInventory,
                               indices: [String: BinaryIndex]) -> [Finding] {
        var out: [Finding] = []

        let genre = metadata.storeGenre?.lowercased() ?? ""
        let rating = metadata.contentRating ?? ""
        let isKidsGenre = genre.contains("kid") || genre.contains("children")
        let trackers = network.detectedSDKs.filter(\.isTracker)
        let adTrackers = trackers.filter { ["advertising", "attribution", "identity"].contains($0.category.lowercased()) }

        func anySymbolOrString(_ needles: [String]) -> Bool {
            for idx in indices.values {
                for s in idx.importedSymbols + idx.definedSymbols where needles.contains(where: { s.contains($0) }) { return true }
                for ss in idx.perSectionStrings {
                    for st in ss.strings where needles.contains(where: { st.value.contains($0) }) { return true }
                }
            }
            return false
        }
        let hasDeclaredAgeRange = anySymbolOrString(["DeclaredAgeRange", "AgeRangeService", "requestAgeRange"])
        let hasAgeGate = hasDeclaredAgeRange || anySymbolOrString(["ageGate", "AgeGate", "ageVerification", "birthdayPicker", "dateOfBirthField"])
        let coppaFlagPresent = anySymbolOrString(["tagForChildDirectedTreatment", "coppaCompliant", "setIsAgeRestrictedUser",
                                                  "child_directed", "COPPACompliant", "isChildDirected"])

        if isKidsGenre, !adTrackers.isEmpty {
            let copy = Messages.entry("TGAP-03.kids_category_trackers", [
                "genre": metadata.storeGenre ?? "Kids",
                "count": String(adTrackers.count),
                "sdks": adTrackers.map(\.name).prefix(6).joined(separator: ", "),
            ])
            out.append(Finding(
                ruleID: "TGAP-03.kids_category_trackers", vectorID: "TGAP-03",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("TGAP-03.kids_category_trackers", "TGAP-03"), evidences: adTrackers.prefix(8).map { Evidence(kind: .symbol, value: $0.name, source: $0.frameworks.first ?? "(main)") }).with(metrics: copy.values))
        }

        if isKidsGenre, coppaFlagPresent {
            out.append(Finding(
                ruleID: "TGAP-03.coppa_flag_mismatch", vectorID: "TGAP-03",
                title: Messages.entry("TGAP-03.coppa_flag_mismatch").title,
                explanation: Messages.entry("TGAP-03.coppa_flag_mismatch").explanation,
                severity: .derived("TGAP-03.coppa_flag_mismatch", "TGAP-03"), evidences: [Evidence(kind: .stringMatch, value: "child-directed SDK flag", source: "(main)")]))
        }

        if hasDeclaredAgeRange {
            out.append(Finding(
                ruleID: "TGAP-03.declared_age_range_api", vectorID: "TGAP-03",
                title: Messages.entry("TGAP-03.declared_age_range_api").title,
                explanation: Messages.entry("TGAP-03.declared_age_range_api").explanation,
                severity: .derived("TGAP-03.declared_age_range_api", "TGAP-03"), evidences: [Evidence(kind: .symbol, value: "DeclaredAgeRange", source: "(main)")]))
        }

        if isKidsGenre, !hasAgeGate {
            let copy = Messages.entry("TGAP-03.age_gate_absent", [
                "genre": metadata.storeGenre ?? "Kids",
                "ratingNote": rating.isEmpty ? "" : ", rated \(rating)",
            ])
            out.append(Finding(
                ruleID: "TGAP-03.age_gate_absent", vectorID: "TGAP-03",
                title: copy.title,
                explanation: copy.explanation,
                severity: .derived("TGAP-03.age_gate_absent", "TGAP-03"), evidences: [Evidence(kind: .plistValue, value: metadata.storeGenre ?? "Kids", source: "iTunes metadata")]).with(metrics: copy.values))
        }

        return out
    }
}
