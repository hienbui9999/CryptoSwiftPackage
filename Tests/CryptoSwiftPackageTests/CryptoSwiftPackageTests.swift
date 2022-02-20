import XCTest
import CryptoKit
@testable import CryptoSwiftPackage

final class CryptoSwiftPackageTests: XCTestCase {
    func testExample() throws {
        XCTAssertEqual(CryptoSwiftPackage().text, "Hello, World!")
        let csp : CryptoSwiftPackage = CryptoSwiftPackage();
        csp.Ed25519GenerateKey();
        csp.secp256k1GenerateKey()
        csp.Ed25519BuiltInSwift();
    }
}
