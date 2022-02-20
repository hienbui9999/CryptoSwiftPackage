import Foundation
import CryptoKit
public class ED25519 {
    public func keyGenerate() {
        //key generation
        let privateKey = Curve25519.Signing.PrivateKey.init();
        let publicKey = privateKey.publicKey;
        let message:[UInt8] = [123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,3,2,144,42,3,4,3,5];
        do {
            //sign message and verify message
            let signMessage = try privateKey.signature(for: message);
            if publicKey.isValidSignature(signMessage, for: message) {
                print("Mac check for Mac signuture success")
            } else {
                print("Mac check for Mac signature fail")
            }
        } catch {
            
        }
    }
}
