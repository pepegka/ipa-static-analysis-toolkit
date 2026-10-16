import Foundation

public struct RuleInput: Sendable {
    public let metadata: BundleMetadata
    public let indices: [String: BinaryIndex]
    public let provisioningEntitlements: [String]
    public let codesignEntitlements: [String]
    public init(metadata: BundleMetadata,
                indices: [String: BinaryIndex],
                provisioningEntitlements: [String],
                codesignEntitlements: [String]) {
        self.metadata = metadata
        self.indices = indices
        self.provisioningEntitlements = provisioningEntitlements
        self.codesignEntitlements = codesignEntitlements
    }
}

private struct BinaryHit {
    let binaryRelPath: String
    let owningFramework: String
    var stringMatches: [(section: String, offset: UInt64, value: String, isUTF16: Bool)]
    var symbolMatches: [(kind: String, name: String)]
    var dylibMatches: [String]
}

public struct RuleEngine: Sendable {

    private let rules: [Rule]

    public init(rules: [Rule]) { self.rules = rules }

    public func evaluate(_ input: RuleInput) -> [Finding] {
        return evaluateBatched(input)
    }


    private final class CompiledMatcher: @unchecked Sendable {
        let pattern: String
        let nsregex: NSRegularExpression?
        let isLiteral: Bool
        let caseSensitive: Bool
        let needles: [String]

        init(pattern: String, nsregex: NSRegularExpression?, isLiteral: Bool,
             caseSensitive: Bool, needles: [String]) {
            self.pattern = pattern
            self.nsregex = nsregex
            self.isLiteral = isLiteral
            self.caseSensitive = caseSensitive
            self.needles = needles
        }

        func matches(_ s: String) -> Bool {
            if s.utf8.count > 4096 { return false }

            if !needles.isEmpty {
                let opt: String.CompareOptions = caseSensitive ? [] : [.caseInsensitive]
                var hit = false
                for n in needles {
                    if s.range(of: n, options: opt) != nil { hit = true; break }
                }
                if !hit { return false }
                if isLiteral { return true }
            } else if isLiteral && nsregex == nil {
                return false
            }

            guard let re = nsregex else { return true }
            let range = NSRange(location: 0, length: (s as NSString).length)
            return re.firstMatch(in: s, options: [], range: range) != nil
        }
    }

    private static func compile(_ search: Rule.Search) -> CompiledMatcher {
        return compile(pattern: search.pattern, caseSensitive: search.caseSensitive)
    }
    private static func compile(pattern: String, caseSensitive: Bool) -> CompiledMatcher {
        let needles = Self.literalNeedles(from: pattern)
        let looksRegex = pattern.contains(where: { "\\^$.|?*+()[]{}".contains($0) })
        if !looksRegex {
            return CompiledMatcher(pattern: pattern, nsregex: nil, isLiteral: true,
                                   caseSensitive: caseSensitive,
                                   needles: needles.isEmpty ? [pattern] : needles)
        }
        var opts: NSRegularExpression.Options = []
        if !caseSensitive { opts.insert(.caseInsensitive) }
        let re = try? NSRegularExpression(pattern: pattern, options: opts)
        return CompiledMatcher(pattern: pattern, nsregex: re, isLiteral: false,
                               caseSensitive: caseSensitive, needles: needles)
    }

    private static func literalNeedles(from pattern: String) -> [String] {
        var p = pattern
        for prefix in ["(?i)", "\\b", "^", "(", "(?:"] { if p.hasPrefix(prefix) { p.removeFirst(prefix.count) } }
        for suffix in ["\\b", "$", ")"] { if p.hasSuffix(suffix) { p.removeLast(suffix.count) } }
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-:/|@ ")
        guard p.allSatisfy({ allowed.contains($0) }) else { return requiredLiterals(from: pattern) }
        let parts = p.split(separator: "|").map { String($0) }.filter { !$0.isEmpty }
        if parts.isEmpty || parts.count > 64 { return [] }
        return parts
    }

    static func requiredLiterals(from pattern: String) -> [String] {
        var p = Substring(pattern)
        if p.hasPrefix("(?i)") { p = p.dropFirst(4) }
        var alternatives: [String] = []
        var current = ""
        var depth = 0
        var escaped = false
        var inClass = false
        for ch in p {
            if escaped { current.append("\\"); current.append(ch); escaped = false; continue }
            if ch == "\\" { escaped = true; continue }
            if inClass { current.append(ch); if ch == "]" { inClass = false }; continue }
            if ch == "[" { inClass = true }
            if ch == "(" { depth += 1 }
            if ch == ")" { depth -= 1 }
            if ch == "|" && depth == 0 { alternatives.append(current); current = ""; continue }
            current.append(ch)
        }
        alternatives.append(current)
        guard alternatives.count <= 64 else { return [] }
        var out: [String] = []
        for a in alternatives {
            let lit = longestRequiredRun(a)
            guard lit.count >= 3 else { return [] }
            out.append(lit)
        }
        return out
    }

    private static func longestRequiredRun(_ alternative: String) -> String {
        let chars = Array(alternative)
        let literalEscapes = Set("$.-/:_@|()[]{}?*+^\\")
        var best = ""
        var run = ""
        var depth = 0
        var inClass = false
        var i = 0
        func flush() { if run.count > best.count { best = run }; run = "" }
        while i < chars.count {
            let c = chars[i]
            if inClass { if c == "]" { inClass = false }; i += 1; continue }
            if depth > 0 {
                if c == "\\" { i += 2; continue }
                if c == "(" { depth += 1 } else if c == ")" { depth -= 1 }
                i += 1; continue
            }
            switch c {
            case "\\":
                if i + 1 < chars.count, literalEscapes.contains(chars[i + 1]) {
                    run.append(chars[i + 1]); i += 2
                } else { flush(); i += 2 }
                continue
            case "[": flush(); inClass = true
            case "(": flush(); depth = 1
            case "?", "*", "{":
                if !run.isEmpty { run.removeLast() }
                flush()
                if c == "{" { while i < chars.count && chars[i] != "}" { i += 1 } }
            case "+", "^", "$", ".", ")": flush()
            default: run.append(c)
            }
            i += 1
        }
        flush()
        return best
    }

    private func evaluateGlobal(matcher: CompiledMatcher,
                                kind: Rule.SearchKind,
                                input: RuleInput) -> [Evidence] {
        switch kind {
        case .urlScheme:
            var out: [Evidence] = []
            for s in input.metadata.queriedURLSchemes where matcher.matches(s) {
                out.append(Evidence(kind: .plistValue, value: s, source: "Info.plist:LSApplicationQueriesSchemes"))
            }
            for s in input.metadata.urlSchemes where matcher.matches(s) {
                out.append(Evidence(kind: .plistValue, value: s, source: "Info.plist:CFBundleURLTypes"))
            }
            return out
        case .backgroundMode:
            return input.metadata.backgroundModes.filter(matcher.matches).map {
                Evidence(kind: .plistValue, value: $0, source: "Info.plist:UIBackgroundModes")
            }
        case .entitlement:
            var out: [Evidence] = []
            out.append(contentsOf: input.provisioningEntitlements.filter(matcher.matches).map {
                Evidence(kind: .entitlement, value: $0, source: "embedded.mobileprovision")
            })
            out.append(contentsOf: input.codesignEntitlements.filter(matcher.matches).map {
                Evidence(kind: .entitlement, value: $0, source: "codesign")
            })
            return out
        case .bundleID:
            return matcher.matches(input.metadata.bundleID)
                ? [Evidence(kind: .plistValue, value: input.metadata.bundleID, source: "Info.plist:CFBundleIdentifier")]
                : []
        case .frameworkName:
            return input.metadata.embeddedFrameworks.filter(matcher.matches).map {
                Evidence(kind: .file, value: "\($0).framework", source: "Frameworks/\($0).framework")
            }
        case .plistKey, .plistValue:
            var out: [Evidence] = []
            let perms = input.metadata.permissions
            for p in perms {
                if kind == .plistKey, matcher.matches(p.key) {
                    out.append(Evidence(kind: .plistKey, value: p.key, source: "Info.plist"))
                }
                if kind == .plistValue, matcher.matches(p.value) {
                    out.append(Evidence(kind: .plistValue, value: p.value, source: "Info.plist:\(p.key)"))
                }
            }
            for api in input.metadata.privacyAccessedAPIs {
                if matcher.matches(api) {
                    out.append(Evidence(kind: .plistValue, value: api, source: "PrivacyInfo.xcprivacy"))
                }
            }
            for reason in input.metadata.privacyAccessedAPIReasons ?? [] where kind == .plistValue {
                if matcher.matches(reason) {
                    out.append(Evidence(kind: .plistValue, value: reason, source: "PrivacyInfo.xcprivacy",
                                        context: "NSPrivacyAccessedAPITypeReasons"))
                }
            }
            for d in input.metadata.privacyTrackingDomains {
                if matcher.matches(d) {
                    out.append(Evidence(kind: .url, value: d, source: "PrivacyInfo.xcprivacy"))
                }
            }
            return out
        default:
            return []
        }
    }

    private static func buildEvidences(from hits: [BinaryHit], max: Int) -> [Evidence] {
        var out: [Evidence] = []
        out.reserveCapacity(max)
        var seen: Set<Evidence> = []
        func push(_ e: Evidence) -> Bool {
            if seen.contains(e) { return true }
            seen.insert(e); out.append(e)
            return out.count < max
        }
        let sortedHits = hits.sorted { $0.binaryRelPath < $1.binaryRelPath }
        for hit in sortedHits {
            for m in hit.stringMatches {
                if !push(Evidence(kind: .stringMatch, value: m.value,
                                  source: hit.binaryRelPath,
                                  section: m.section, offset: m.offset)) { return out }
            }
            for m in hit.symbolMatches {
                let kind: Evidence.Kind = (m.name.hasPrefix("$s") || m.name.hasPrefix("_$s"))
                    ? .symbol
                    : (m.name.contains("OBJC_") || m.name.contains("[") ? .objcSelector : .symbol)
                if !push(Evidence(kind: kind, value: m.name, source: hit.binaryRelPath)) { return out }
            }
            for d in hit.dylibMatches {
                if !push(Evidence(kind: .linkedDylib, value: d, source: hit.binaryRelPath)) { return out }
            }
        }
        return out
    }

    private func evaluateBatched(_ input: RuleInput) -> [Finding] {
        struct CompiledRule {
            let rule: Rule
            let searches: [(matcher: CompiledMatcher, search: Rule.Search, kind: Rule.SearchKind)]
        }
        @Sendable func compileRule(_ r: Rule) -> CompiledRule {
            let s = r.search.map { (Self.compile($0), $0, $0.kind) }
            return CompiledRule(rule: r, searches: s)
        }
        let compiled: [CompiledRule]
        if rules.count >= 24 {
            final class CBox: @unchecked Sendable {
                var map: [Int: CompiledRule] = [:]
                let lock = NSLock()
            }
            let cbox = CBox()
            DispatchQueue.concurrentPerform(iterations: rules.count) { i in
                let cr = compileRule(rules[i])
                cbox.lock.lock(); cbox.map[i] = cr; cbox.lock.unlock()
            }
            compiled = (0..<rules.count).map { cbox.map[$0]! }
        } else {
            compiled = rules.map(compileRule)
        }

        struct StringMatcher {
            let ruleIdx: Int
            let m: CompiledMatcher
            let allowedSections: [String]?
        }
        var _stringMatchers: [StringMatcher] = []
        var _importedSymMatchers: [(ruleIdx: Int, m: CompiledMatcher)] = []
        var _definedSymMatchers: [(ruleIdx: Int, m: CompiledMatcher)] = []
        var _symbolMatchers: [(ruleIdx: Int, m: CompiledMatcher)] = []
        var _dylibMatchers: [(ruleIdx: Int, m: CompiledMatcher)] = []
        for (i, cr) in compiled.enumerated() {
            for (m, sr, k) in cr.searches {
                switch k {
                case .string:
                    _stringMatchers.append(StringMatcher(ruleIdx: i, m: m, allowedSections: sr.sections))
                case .symbol:
                    _symbolMatchers.append((i, m))
                case .importedSymbol:
                    _importedSymMatchers.append((i, m))
                case .definedSymbol:
                    _definedSymMatchers.append((i, m))
                case .dylib:
                    _dylibMatchers.append((i, m))
                default: break
                }
            }
        }
        let stringMatchers = _stringMatchers
        let importedSymMatchers = _importedSymMatchers
        let definedSymMatchers = _definedSymMatchers
        let symbolMatchers = _symbolMatchers
        let dylibMatchers = _dylibMatchers

        var _symbolNeedleUnion: Set<String> = []
        var anyEmptyNeedleSymbolMatcher = false
        for (_, m) in importedSymMatchers { if m.needles.isEmpty { anyEmptyNeedleSymbolMatcher = true }; for n in m.needles { _symbolNeedleUnion.insert(n.lowercased()) } }
        for (_, m) in definedSymMatchers  { if m.needles.isEmpty { anyEmptyNeedleSymbolMatcher = true }; for n in m.needles { _symbolNeedleUnion.insert(n.lowercased()) } }
        for (_, m) in symbolMatchers      { if m.needles.isEmpty { anyEmptyNeedleSymbolMatcher = true }; for n in m.needles { _symbolNeedleUnion.insert(n.lowercased()) } }
        let symbolNeedleUnion = Array(_symbolNeedleUnion)
        let symbolHasUnionPrefilter = !symbolNeedleUnion.isEmpty && !anyEmptyNeedleSymbolMatcher

        final class Collector: @unchecked Sendable {
            var batches: [[Int: BinaryHit]] = []
            let lock = NSLock()
            func add(_ b: [Int: BinaryHit]) { lock.lock(); batches.append(b); lock.unlock() }
        }
        let collector = Collector()

        let pairs = Array(input.indices)
        DispatchQueue.concurrentPerform(iterations: pairs.count) { idx in
            let (rel, bi) = pairs[idx]
            let owner = FrameworkAttribution.framework(forRelativePath: rel)

            var local: [Int: BinaryHit] = [:]
            func hit(_ i: Int) -> Int {
                if local[i] == nil {
                    local[i] = BinaryHit(binaryRelPath: rel, owningFramework: owner,
                                         stringMatches: [], symbolMatches: [], dylibMatches: [])
                }
                return i
            }

            if !stringMatchers.isEmpty {
                for ss in bi.perSectionStrings {
                    let qname = ss.section.qualifiedName
                    for s in ss.strings {
                        let val = s.value
                        if val.utf8.count > 4096 { continue }
                        for sm in stringMatchers {
                            if let allow = sm.allowedSections,
                               !allow.contains(where: { qname.contains($0) }) {
                                continue
                            }
                            if compiled[sm.ruleIdx].rule.attribution.benignInFrameworks.contains(owner) { continue }
                            if sm.m.matches(val) {
                                local[hit(sm.ruleIdx)]!.stringMatches.append(
                                    (qname, s.offset, val, s.isUTF16))
                            }
                        }
                    }
                }
            }

            func scanSymbols(_ list: [String], kindTag: String,
                             matchersA: [(ruleIdx: Int, m: CompiledMatcher)],
                             matchersB: [(ruleIdx: Int, m: CompiledMatcher)]) {
                if matchersA.isEmpty && matchersB.isEmpty { return }
                for sym in list {
                    let utf8c = sym.utf8.count
                    if utf8c > 4096 { continue }
                    let lower = sym.lowercased()
                    if symbolHasUnionPrefilter {
                        var anyHit = false
                        for n in symbolNeedleUnion {
                            if lower.contains(n) { anyHit = true; break }
                        }
                        if !anyHit { continue }
                    }
                    func tryMatchers(_ ms: [(ruleIdx: Int, m: CompiledMatcher)]) {
                        for (i, m) in ms {
                            if compiled[i].rule.attribution.benignInFrameworks.contains(owner) { continue }
                            if !m.needles.isEmpty {
                                var matched = false
                                for n in m.needles {
                                    let h = m.caseSensitive ? sym.contains(n) : lower.contains(n.lowercased())
                                    if h { matched = true; break }
                                }
                                if !matched { continue }
                                if m.isLiteral {
                                    local[hit(i)]!.symbolMatches.append((kindTag, sym))
                                    continue
                                }
                            }
                            if let re = m.nsregex {
                                let r = NSRange(location: 0, length: (sym as NSString).length)
                                if re.firstMatch(in: sym, options: [], range: r) != nil {
                                    local[hit(i)]!.symbolMatches.append((kindTag, sym))
                                }
                            }
                        }
                    }
                    tryMatchers(matchersA)
                    tryMatchers(matchersB)
                }
            }
            scanSymbols(bi.importedSymbols, kindTag: "imp",
                        matchersA: importedSymMatchers, matchersB: symbolMatchers)
            scanSymbols(bi.definedSymbols, kindTag: "def",
                        matchersA: definedSymMatchers, matchersB: symbolMatchers)

            if !dylibMatchers.isEmpty {
                for d in bi.linkedDylibs {
                    for (i, m) in dylibMatchers {
                        if compiled[i].rule.attribution.benignInFrameworks.contains(owner) { continue }
                        if m.matches(d) {
                            local[hit(i)]!.dylibMatches.append(d)
                        }
                    }
                }
            }

            if !local.isEmpty { collector.add(local) }
        }

        var perRuleMerged: [[String: BinaryHit]] = Array(repeating: [:], count: rules.count)
        for batch in collector.batches {
            for (i, h) in batch { perRuleMerged[i][h.binaryRelPath] = h }
        }

        var findings: [Finding] = []
        for (i, cr) in compiled.enumerated() {
            var globalEvidences: [Evidence] = []
            for (m, _, k) in cr.searches {
                globalEvidences.append(contentsOf: evaluateGlobal(matcher: m, kind: k, input: input))
            }

            let perBinary = perRuleMerged[i]

            if globalEvidences.isEmpty && perBinary.isEmpty { continue }

            if !globalEvidences.isEmpty {
                let attr = cr.rule.attribution.primaryFramework ?? "(main)"
                findings.append(makeFinding(rule: cr.rule,
                                            owningFramework: attr,
                                            owningFrameworks: [attr],
                                            affectedBinaries: [],
                                            evidences: Array(globalEvidences.prefix(cr.rule.maxEvidence))))
            }

            if !perBinary.isEmpty {
                let allHits = Array(perBinary.values)
                let evidences = Self.buildEvidences(from: allHits, max: cr.rule.maxEvidence)
                if !evidences.isEmpty {
                    let frameworks = Array(Set(allHits.map(\.owningFramework))).sorted()
                    let binaries = Array(Set(allHits.map(\.binaryRelPath))).sorted()
                    findings.append(makeFinding(rule: cr.rule,
                                                owningFramework: frameworks.count == 1 ? frameworks[0] : nil,
                                                owningFrameworks: frameworks,
                                                affectedBinaries: binaries,
                                                evidences: evidences))
                }
            }
        }
        return findings
    }

    private func makeFinding(rule: Rule, owningFramework: String?,
                             owningFrameworks: [String], affectedBinaries: [String],
                             evidences: [Evidence]) -> Finding {
        var f = Finding(
            ruleID: rule.id,
            vectorID: rule.vector,
            title: rule.title,
            explanation: rule.description,
            severity: SeverityDerivation.severity(ruleID: rule.id, vectorID: rule.vector) ?? rule.severity,
            evidences: evidences,
            owningFramework: owningFramework,
            owningFrameworks: owningFrameworks,
            affectedBinaries: affectedBinaries,
            mitre: rule.mitre,
            references: rule.references,
            masvs: rule.masvs,
            remediation: rule.remediation,
            mastg: rule.mastg ?? [],
            maswe: rule.maswe ?? [],
            boundByRule: rule.maswe != nil || rule.mastg != nil
        )
        f.polarity = rule.polarity
        return f
    }
}
