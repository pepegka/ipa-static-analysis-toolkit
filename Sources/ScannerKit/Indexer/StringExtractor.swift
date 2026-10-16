import Foundation

public struct ExtractedString: Sendable, Hashable {
    public let value: String
    public let offset: UInt64
    public let isUTF16: Bool

    public init(value: String, offset: UInt64, isUTF16: Bool) {
        self.value = value; self.offset = offset; self.isUTF16 = isUTF16
    }
}

public enum StringExtractor {

    public static let maxStringLength = 2048

    public static func scan(data: Data,
                            rangeStart: Int,
                            rangeEnd: Int,
                            minASCII: Int = 4,
                            minUTF16: Int = 4,
                            maxResults: Int = .max) -> [ExtractedString] {
        guard rangeEnd > rangeStart, rangeStart >= 0, rangeEnd <= data.count else { return [] }
        var out: [ExtractedString] = []
        out.reserveCapacity(1024)

        data.withUnsafeBytes { (rawBuf: UnsafeRawBufferPointer) in
            guard let base = rawBuf.baseAddress else { return }
            let ptr = base.assumingMemoryBound(to: UInt8.self)

            var runStart = -1
            var i = rangeStart
            while i < rangeEnd {
                let b = ptr[i]
                let printable = (b >= 0x20 && b < 0x7F) || b == 0x09
                if printable {
                    if runStart < 0 { runStart = i }
                } else {
                    if runStart >= 0 && (i - runStart) >= minASCII && (i - runStart) <= Self.maxStringLength {
                        if let s = String(bytes: UnsafeBufferPointer(start: ptr + runStart, count: i - runStart),
                                          encoding: .ascii) {
                            out.append(ExtractedString(value: s,
                                                       offset: UInt64(runStart),
                                                       isUTF16: false))
                            if out.count >= maxResults { return }
                        }
                    }
                    runStart = -1
                }
                i += 1
            }
            if runStart >= 0 && (rangeEnd - runStart) >= minASCII && (rangeEnd - runStart) <= Self.maxStringLength {
                if let s = String(bytes: UnsafeBufferPointer(start: ptr + runStart, count: rangeEnd - runStart),
                                  encoding: .ascii) {
                    out.append(ExtractedString(value: s,
                                               offset: UInt64(runStart),
                                               isUTF16: false))
                }
            }
            if out.count >= maxResults { return }

            guard (rangeEnd - rangeStart) >= 2 * minUTF16 else { return }
            var j = rangeStart
            var u16Start = -1
            while j + 1 < rangeEnd {
                let lo = ptr[j]
                let hi = ptr[j + 1]
                let printable = ((lo >= 0x20 && lo < 0x7F) || lo == 0x09) && hi == 0x00
                if printable {
                    if u16Start < 0 { u16Start = j }
                    j += 2
                } else {
                    if u16Start >= 0 {
                        let chars = (j - u16Start) / 2
                        if chars >= minUTF16 {
                            var bytes = [UInt8]()
                            bytes.reserveCapacity(chars)
                            var k = u16Start
                            while k < j { bytes.append(ptr[k]); k += 2 }
                            if let s = String(bytes: bytes, encoding: .ascii) {
                                out.append(ExtractedString(value: s,
                                                           offset: UInt64(u16Start),
                                                           isUTF16: true))
                                if out.count >= maxResults { return }
                            }
                        }
                    }
                    u16Start = -1
                    j += 1
                }
            }
            if u16Start >= 0 {
                let chars = (j - u16Start) / 2
                if chars >= minUTF16 {
                    var bytes = [UInt8]()
                    bytes.reserveCapacity(chars)
                    var k = u16Start
                    while k < j { bytes.append(ptr[k]); k += 2 }
                    if let s = String(bytes: bytes, encoding: .ascii) {
                        out.append(ExtractedString(value: s,
                                                   offset: UInt64(u16Start),
                                                   isUTF16: true))
                    }
                }
            }
        }
        return out
    }
}
