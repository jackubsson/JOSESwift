import XCTest
@testable import JOSESwift

final class SignatureAlgorithmTests: XCTestCase {

    func testAllJWSAlgorithmIdentifiers() {
        let algorithms: [SignatureAlgorithm] = [
            .HS256, .HS384, .HS512,
            .RS256, .RS384, .RS512,
            .ES256, .ES384, .ES512,
            .PS256, .PS384, .PS512
        ]

        XCTAssertEqual(algorithms.count, 12)

        for algorithm in algorithms {
            XCTAssertEqual(
                SignatureAlgorithm(rawValue: algorithm.rawValue),
                algorithm
            )
        }
    }
}
