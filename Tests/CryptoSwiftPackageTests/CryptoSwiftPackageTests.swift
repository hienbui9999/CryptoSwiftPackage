import XCTest
import CryptoKit
@testable import CryptoSwiftPackage

final class CryptoSwiftPackageTests: XCTestCase {
    func testExample() throws {
        let blake:Blake2b = Blake2b();
        blake.test();
        let sepc256:CryptoSwiftPackage = CryptoSwiftPackage()
        sepc256.secp256k1GenerateKey()
        /*let ed25519Swift:Ed25519Swift = Ed25519Swift();
        ed25519Swift.generateKey()
        do {
            try ed25519Swift.writePrivateKeyToPemFile(privateKeyToWrite: ed25519Swift.privateKey, fileName: "SwiftPrivateKeyEd25519.pem");
            try ed25519Swift.writePublicKeyToPemFile(publicKeyToWrite: ed25519Swift.publicKey, fileName: "SwiftPublicKeyEd25519.pem");
        } catch {
            
        }
        do {
            let privateKey = try ed25519Swift.readPrivateKeyFromPemFile(pemFileName:"Ed25519SecretKeyPHP.pem")// "ED25519_secret_keyScala.pem")// "Ed25519SecretKeyPHP.pem")
            let privateKeyFullBytes = prefixPrivateKeyData +  privateKey.rawRepresentation
            print("private key full base 64: \(privateKeyFullBytes.base64EncodedString())");
            
            let publicKey = try ed25519Swift.readPublicKeyFromPemFile(pemFileName:"Ed25519PublicKeyPHP.pem")// "ED25519_public_keyScala.pem")// "Ed25519PublicKeyPHP.pem")
            let publicKeyFullBytes = prefixPublicKeyData + publicKey.rawRepresentation
            print("public key full base 64:\(publicKeyFullBytes.base64EncodedString())")
            let message:[UInt8] = [123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,3,2,144,42,3,4,3,5];
            let message2:String = "0203f3f44c9e80e2cedc1a2909631a3adea8866ee32187f74d0912387359b0ff36a2"
            do {
                let signedMessage = try ed25519Swift.signMessage(messageToSign: Data(message),withPrivateKey: privateKey)//privateKey.signature(for: message)
                print("sigedMessage:\(signedMessage)")
                let isSignCorrect = ed25519Swift.verify(signedMessage: signedMessage, pulicKeyToVerify: publicKey, originalMessage: Data(message))
                
                print("isSign2 correct:\(isSignCorrect)")
                print("message2 bytes:\(message2.bytes)")
                let signedMessage2 = try ed25519Swift.signMessage(messageToSign: Data(message2.bytes),withPrivateKey: privateKey)//privateKey.signature(for: message)
                let message2InHex = signedMessage2.toHexString();
                print("message2InHex:")
                print(message2InHex)
                let isSignCorrect2 = ed25519Swift.verify(signedMessage: signedMessage2, pulicKeyToVerify: publicKey, originalMessage: Data(message2.bytes))
                
                print("isSign2 correct:\(isSignCorrect2)")
            } catch {
                print("Error :\(error)")
            }
            
        } catch {
            print("Error:\(error)")
        }*/
        
    }
}
