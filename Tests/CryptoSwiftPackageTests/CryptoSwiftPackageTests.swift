import XCTest
import CryptoKit
@testable import CryptoSwiftPackage

final class CryptoSwiftPackageTests: XCTestCase {
    func testExample() throws {
        let ed25519Swift:Ed25519Swift = Ed25519Swift();
        ed25519Swift.generateKey()
        do {
            try ed25519Swift.writePrivateKeyToPemFile(privateKeyToWrite: ed25519Swift.privateKey, fileName: "SwiftPrivateKeyEd25519.pem");
            try ed25519Swift.writePublicKeyToPemFile(publicKeyToWrite: ed25519Swift.publicKey, fileName: "SwiftPublicKeyEd25519.pem");
        } catch {
            
        }
        do {
            let privateKey = try ed25519Swift.readPrivateKeyFromPemFile(pemFileName:"SwiftPrivateKeyEd25519.pem")// "ED25519_secret_keyScala.pem")// "Ed25519SecretKeyPHP.pem")
            let privateKeyFullBytes = prefixPrivateKeyData +  privateKey.rawRepresentation
            print("private key full base 64: \(privateKeyFullBytes.base64EncodedString())");
            
            let publicKey = try ed25519Swift.readPublicKeyFromPemFile(pemFileName:"SwiftPublicKeyEd25519.pem")// "ED25519_public_keyScala.pem")// "Ed25519PublicKeyPHP.pem")
            let publicKeyFullBytes = prefixPublicKeyData + publicKey.rawRepresentation
            print("public key full base 64:\(publicKeyFullBytes.base64EncodedString())")
            let message:[UInt8] = [123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,3,2,144,42,3,4,3,5];
            let message2:String = "Hello world!. Welcome all abroad!"
            do {
                let signedMessage = try ed25519Swift.signMessage(messageToSign: Data(message))//privateKey.signature(for: message)
                let isSignCorrect = ed25519Swift.verify(signedMessage: signedMessage, pulicKeyToVerify: publicKey, originalMessage: Data(message))
                
                print("isSign2 correct:\(isSignCorrect)")
                
                let signedMessage2 = try ed25519Swift.signMessage(messageToSign: Data(message2.bytes))//privateKey.signature(for: message)
                let isSignCorrect2 = ed25519Swift.verify(signedMessage: signedMessage2, pulicKeyToVerify: publicKey, originalMessage: Data(message2.bytes))
                
                print("isSign2 correct:\(isSignCorrect2)")
            } catch {
                print("Error :\(error)")
            }
            
        } catch {
            print("Error:\(error)")
        }
        
    }
}
