import XCTest
@testable import ScannerKit

final class ClusterRollupTests: XCTestCase {

    private func finding(_ vectorID: String, _ sev: Severity = .medium) -> Finding {
        Finding(ruleID: "\(vectorID).x", vectorID: vectorID, title: "t", explanation: "e",
                severity: sev, evidences: []).annotatedWithCrosswalk()
    }

    func testUnboundFindingsAreIndicators() {
        let unbound = Finding(ruleID: "SURV-01.x", vectorID: "SURV-01", title: "t", explanation: "e",
                              severity: .low, evidences: [], boundByRule: true)
        XCTAssertEqual(FindingCluster.of(unbound), .indicators)
        let policy = Finding(ruleID: "TGAP-03.x", vectorID: "TGAP-03", title: "t", explanation: "e",
                             severity: .low, evidences: [], boundByRule: true)
        XCTAssertEqual(FindingCluster.of(policy), .applePolicy)
    }

    func testEveryVectorLandsInExactlyOneCluster() {
        for v in Vectors.all {
            let clusters = [finding(v.id)].clusterRollup()
            XCTAssertEqual(clusters.count, 1, "\(v.id) produced \(clusters.count) clusters")
        }
    }

    func testTGAPVectorsClusterAsApplePolicyAndNothingElseDoes() {
        for v in Vectors.all {
            let id = [finding(v.id)].clusterRollup().first?.id
            if v.construct == .TGAP {
                XCTAssertEqual(id, FindingCluster.applePolicy.id, "\(v.id) should be Apple policy")
            } else {
                XCTAssertEqual(id, v.group.rawValue, "\(v.id) should cluster as its MASVS group")
            }
        }
    }

    func testCountsAndSeverityTallyMatchTheInput() {
        let fs = [finding("SECH-01", .high), finding("SECH-01", .medium), finding("SECH-01", .medium)]
        let clusters = fs.clusterRollup()
        XCTAssertEqual(clusters.count, 1)
        let network = clusters[0]
        XCTAssertEqual(network.id, MASVSGroup.network.rawValue)
        XCTAssertEqual(network.findingCount, 3)
        XCTAssertEqual(network.count(.high), 1)
        XCTAssertEqual(network.count(.medium), 2)
        XCTAssertEqual(network.count(.low), 0)
        XCTAssertEqual(network.maxSeverity, .high)
    }

    func testEveryBoundMASWEExistsInTheCatalogue() {
        let catalogue = MASWECatalog.allIDs
        XCTAssertEqual(catalogue.count, 78, "MASWE v1.0.0 has 78 weaknesses")
        for v in Vectors.all {
            for id in FrameworkCrosswalk.for(vectorID: v.id).maswe {
                XCTAssertTrue(catalogue.contains(id),
                              "\(v.id) binds \(id), which is not in MASWE \(MASWECatalog.version)")
                XCTAssertNotNil(MASWECatalog.title(id))
                XCTAssertNotNil(MASWECatalog.url(id))
            }
        }
    }

    func testEveryVectorBindsAtLeastOneWeakness() {
        for v in Vectors.all {
            XCTAssertFalse(FrameworkCrosswalk.for(vectorID: v.id).maswe.isEmpty,
                           "\(v.id) binds no MASWE weakness")
        }
    }

    func testChildrenNeverSumBelowTheParent() {
        let fs = Vectors.all.map { finding($0.id) }
        for c in fs.clusterRollup() where c.id != FindingCluster.indicators.id {
            let childSum = c.children.reduce(0) { $0 + $1.findingCount }
            XCTAssertGreaterThanOrEqual(childSum, c.findingCount,
                                        "\(c.id) children sum \(childSum) < \(c.findingCount)")
        }
    }

    func testEmptyFindingsProduceNoClusters() {
        XCTAssertTrue([Finding]().clusterRollup().isEmpty)
    }
}
