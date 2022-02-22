import Foundation
import CryptoKit
import ed25519swift
public class ED25519BuiltInSwift {
    public func generateBytes() {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)

        if status == errSecSuccess { // Always test the status.
            print("bytes generated from random bytes:\(bytes)")
            print("base 64Encoding of bytes:\(bytes.toBase64())")
            let base64 = bytes.toBase64()
            print("base 64Encoding of bytes again2:\(base64)")
            let bytes2 = base64.bytes;
            print("bytes2 from base64:\(bytes2)")
            // Prints something different every time you run.
        }
    }
    public func base64ToHex(base64Str:String) {
        var data = Data(base64Encoded: base64Str, options: .ignoreUnknownCharacters)
        print("Data in hex:\(data?.toHexString())")
        print("Data in bytes:\(data?.bytes)")
    }
    public func keyGenerate3() {
        base64ToHex(base64Str: "MCowBQYDK2VuAyEA")
        print("-----")
        base64ToHex(base64Str: "MC4CAQAwBQYDK2VwBCIEI")
        let privateKey = Curve25519.Signing.PrivateKey.init();
        let publicKey = privateKey.publicKey;
        //private key to PEM
        let prefixPublicKey = Data([0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00])
        let prefixPrivateKey = Data([0x30, 0x22, 0x48, 0x12, 0x0A, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00, 0x33, 0x30])
        print("prefixPublicKey to hexa string:\(prefixPublicKey.toHexString())")
        print("prefixPublicKey to bytes:\(prefixPublicKey.bytes)")
        print("prefixPublicKey to base64:\(prefixPublicKey.base64EncodedString())")
        //private and public to hexa string
        print("privateKey in hexastring:\(privateKey.rawRepresentation.hexEncodedString())")
        print("publicKey in hexastring:\(publicKey.rawRepresentation.hexEncodedString())")
        
        let subjectPublicKeyInfo = prefixPublicKey + publicKey.rawRepresentation
        print("subjectPublicKeyInfo in hexastring:\(subjectPublicKeyInfo.toHexString())")
        let pemPublicKeyString = subjectPublicKeyInfo.base64EncodedString();
        let subjectPrivateKeyInfo = prefixPrivateKey + privateKey.rawRepresentation
        let pemPrivateKeyString = subjectPrivateKeyInfo.base64EncodedString()
        let pemPublicKeyStringHexa = subjectPublicKeyInfo.hexEncodedString()
        print("pemPublicKeyStringHexa:\(pemPublicKeyStringHexa)")
        //let pemPublicKeyStringBytes = subjectPublicKeyInfo.bytes;
        print("publicKeyBase64Str:\(publicKey.rawRepresentation.base64EncodedString())")
        print("pemPublicKeyString:\(pemPublicKeyString)")
        let privateBase64 = privateKey.rawRepresentation.base64EncodedString();
        let pemPrivateKeyStr = "MC4CAQAwBQYDK2VwBCIEI" + privateBase64
        
        print("privateKeyBase64:\(privateBase64)")
        print("pemPrivateKey:\(pemPrivateKeyStr)")
        print("pemPrivateKeyString:\(pemPrivateKeyString)")
        let index = pemPublicKeyString.index(pemPublicKeyString.startIndex,offsetBy: 16);
        let subPem = pemPublicKeyString[index..<pemPublicKeyString.endIndex];
        
        print("subPem:\(subPem)");
        //from subPem of base64String to public key of rawRespresentation
        let publicKey2Data = subPem.base64Decoded!;
        print("publicKey2 bytes:\(publicKey2Data.bytes)")
        print("pubLickKey bytes:\(publicKey.rawRepresentation.bytes)")
       
        let message:[UInt8] = [123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,3,2,144,42,3,4,3,5];
        do {
            //sign message and verify message
            let signMessage = try privateKey.signature(for: message);
            if publicKey.isValidSignature(signMessage, for: message) {
                print("Mac check for Mac signuture success")
            } else {
                print("Mac check for Mac signature fail")
            }
            let publicKey2 = try Curve25519.Signing.PublicKey.init(rawRepresentation: publicKey2Data.bytes);
            if publicKey2.isValidSignature(signMessage, for: message) {
                print("Mac check for Mac signuture success with public key2")
            } else {
                print("Mac check for Mac signature fail with public key2")
            }
        } catch {
            
        }
    }
    public func keyGenerate2() {
        let privateKey = Curve25519.Signing.PrivateKey.init();
        let publicKey = privateKey.publicKey;
        //private key to PEM
        let prefix1 = Data([0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00])
        let subjectPublicKeyInfo = prefix1 + publicKey.rawRepresentation
        let pemPublicKeyString = subjectPublicKeyInfo.base64EncodedString();
        let pemPublicKeyString2 = subjectPublicKeyInfo.string?.base64Encoded;        //publicKey rawRepresentation
        let pemToBase64 = pemPublicKeyString.base64Decoded;
        print("pemTOBase64:\(pemToBase64)")
        print("publicKey raw resprentation:\(publicKey.rawRepresentation)")
        print("publicKey bytes:\(publicKey.rawRepresentation.bytes)")
        print("publicKey base64 string:\(publicKey.rawRepresentation.base64EncodedString())")
        print("publicKey base64 data");
        print(publicKey.rawRepresentation.base64EncodedData(options: .lineLength64Characters))
        print("hex publicKey:");
        print(publicKey.rawRepresentation.toHexString())
        print("pemPublicKeyString:\(pemPublicKeyString)")
        print("base64 to String:")
        let base64 = publicKey.rawRepresentation.base64EncodedString();
       // print(base64.fromBase64())
    }
    public func keyGenerate() {
        //key generation
        let privateKey = Curve25519.Signing.PrivateKey.init();
        let publicKey = privateKey.publicKey;
        //key display in different way
        //base64EncodedString
        print("privateKey base64EncodedString:\(privateKey.rawRepresentation.base64EncodedString())")
        let privateKeyBase64 = privateKey.rawRepresentation.base64EncodedString();
        let bytesPrivatekeyFromBase64 = privateKeyBase64.bytes;
        print("private key bytes from base 64:\(bytesPrivatekeyFromBase64)")
        //bytes
        print("privateKey bytes:\(privateKey.rawRepresentation.bytes)")
        //rawPresentation
        print("privateKey rawpresentation:\(privateKey.rawRepresentation)")
        //NSData
        print("privateKey NSData:\(privateKey.rawRepresentation as NSData)")
        debugPrint(publicKey.rawRepresentation as NSData)
        let prefix1 = Data([0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00])
        let prefix2 = Data([0x20, 0x2B, 0x35, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00])
        let subjectPublicKeyInfo = prefix1 + publicKey.rawRepresentation
        let pemPublicKeyString = subjectPublicKeyInfo.base64EncodedString();
        print("pemPublicKeyString:\(pemPublicKeyString)")
        
        let privateKeyChange = prefix2 + privateKey.rawRepresentation
        let pemPrivateKeyString = privateKeyChange.base64EncodedString();
        print("PemPrivateKeyString:\(pemPrivateKeyString)")
        
        let publicKeyPem:String = "MCowBQYDK2VwAyEA2MlSwH0IxuvstH1WCGFtXXomJaEFPIzKosRgWxUzjMc=";
        let SubjectPublicKeyInfo = publicKeyPem.base64Decoded;
        print("SubjectPublicKeyInfo:\(SubjectPublicKeyInfo)")
        //test with base 64 and bytes
        let bytes:[UInt8] =  [226, 70, 236, 124, 209, 125, 116, 164, 119, 213, 135, 1, 34, 12, 121, 143, 218, 30, 102, 68, 167, 224, 248, 239, 5, 206, 199, 166, 55, 21, 94, 99];
        print("base 64 for bytes:\(bytes.toBase64())")
        print("bytes from base 64:\(bytes.toBase64().bytes)")
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
        //create key from PEM file
    }
}
extension StringProtocol {
    var data: Data { Data(utf8) }
    var base64Encoded: Data { data.base64EncodedData() }
    var base64Decoded: Data? { Data(base64Encoded: string) }
}
extension LosslessStringConvertible {
    var string: String { .init(self) }
}
extension Sequence where Element == UInt8 {
    var data: Data { .init(self) }
    var base64Decoded: Data? { Data(base64Encoded: data) }
    var string: String? { String(bytes: self, encoding: .utf8) }
}

extension Data {
  /// A hexadecimal string representation of the bytes.
  func hexEncodedString() -> String {
    let hexDigits = Array("0123456789abcdef".utf16)
    var hexChars = [UTF16.CodeUnit]()
    hexChars.reserveCapacity(count * 2)

    for byte in self {
      let (index1, index2) = Int(byte).quotientAndRemainder(dividingBy: 16)
      hexChars.append(hexDigits[index1])
      hexChars.append(hexDigits[index2])
    }

    return String(utf16CodeUnits: hexChars, count: hexChars.count)
  }
}

extension String {
  /// A data representation of the hexadecimal bytes in this string.
  func hexDecodedData() -> Data {
    // Get the UTF8 characters of this string
    let chars = Array(utf8)

    // Keep the bytes in an UInt8 array and later convert it to Data
    var bytes = [UInt8]()
    bytes.reserveCapacity(count / 2)

    // It is a lot faster to use a lookup map instead of strtoul
    let map: [UInt8] = [
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
      0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
      0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // HIJKLMNO
    ]

    // Grab two characters at a time, map them and turn it into a byte
    for i in stride(from: 0, to: count, by: 2) {
      let index1 = Int(chars[i] & 0x1F ^ 0x10)
      let index2 = Int(chars[i + 1] & 0x1F ^ 0x10)
      bytes.append(map[index1] << 4 | map[index2])
    }

    return Data(bytes)
  }
}
