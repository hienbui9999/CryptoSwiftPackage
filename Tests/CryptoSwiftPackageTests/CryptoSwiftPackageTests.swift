import XCTest
import CryptoKit
@testable import CryptoSwiftPackage

final class CryptoSwiftPackageTests: XCTestCase {
    func testExample() throws {
        XCTAssertEqual(CryptoSwiftPackage().text, "Hello, World!")
        let csp : CryptoSwiftPackage = CryptoSwiftPackage();
        csp.GenerateKey();
        csp.secp256k1GenerateKey()
        
    }
}
