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
    public func readPrivateKeyFromFile(fileName:String) {
        if let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
           // let file = "scalaEd25519SecretKey.pem"
            let fileURL = dir.appendingPathComponent(fileName)
            print("File url:\(fileURL)");
            //reading
            do {
                let text2 = try String(contentsOf: fileURL, encoding: .utf8)
                print("Text from Pem file is:\n \(text2)")
                let element = text2.components(separatedBy: "-----BEGIN PRIVATE KEY-----")
               // print("eleemnt1:\(element[1])")
                let text1 = element[1];
                let textE = text1.components(separatedBy:"-----END PRIVATE KEY-----")
               // print("element0:\(textE[0])")
                var pemStr = textE[0];
                if pemStr.count > 64 {
                    let index = pemStr.index(pemStr.startIndex,offsetBy:65);
                    let realPemStr = String(pemStr[..<index]);
                    pemStr = realPemStr;
                }
                print("pemStr:\(pemStr)")
                //pemStr if parse from Swift can return as privateKeyBase64String
                //but if generate from scala we need to replace the first 22 character
                //with the other character in order to generate the right key
                let pemIndex = pemStr.index(pemStr.startIndex,offsetBy: 22);
                let privateBase64:String = String(pemStr[pemIndex..<pemStr.endIndex])
                print("privateBase64:\(privateBase64)")
                //base64ToPrivateKey(base64String: privateBase64)
                print("privateBase64Extension:")
                let privateBase64Extension = prefixPrivateKeyStr + privateBase64
               // base64ToPrivateKey(base64String: privateBase64Extension)
                print("done")
            }
            catch {/* error handling here */}
        }
    }
    public func fromPemFileToPrivateKeyBase64String(pemFileName:String)throws -> String {
        if let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
           // let file = "scalaEd25519SecretKey.pem"
            let fileURL = dir.appendingPathComponent(pemFileName)
            print("File url:\(fileURL)");
            //reading
            do {
                let text2 = try String(contentsOf: fileURL, encoding: .utf8)
                let element = text2.components(separatedBy: "-----BEGIN PRIVATE KEY-----")
                if !text2.contains("-----BEGIN PRIVATE KEY-----") {
                    throw PemFileHandlerError.InvalidPemKeyFormat
                }
                if !text2.contains("-----END PRIVATE KEY-----") {
                    throw PemFileHandlerError.InvalidPemKeyFormat
                }
                let text1 = element[1];
                let textE = text1.components(separatedBy:"-----END PRIVATE KEY-----")
                var pemStr = textE[0];
                if pemStr.count > 64 {
                    let index = pemStr.index(pemStr.startIndex,offsetBy:65);
                    let realPemStr = String(pemStr[..<index]);
                    pemStr = realPemStr;
                }
                let pemIndex = pemStr.index(pemStr.startIndex,offsetBy: 22);
                let privateBase64:String = String(pemStr[pemIndex..<pemStr.endIndex])
                //return prefixPrivateKeyStr + privateBase64
                return privateBase64
            }
            catch {
                throw error
            }
        } else {
            throw PemFileHandlerError.ReadPemFileNotFound
        }
    }
    
    public func fromBase64StringToPrivateKey(from:String) throws -> Curve25519.Signing.PrivateKey {
        print("fromBase64StringToPrivateKey func, base 64 str: \( from)")
        let fullPemKeyBase64 = prefixPrivateKeyStr + from;
        let hexaStr = fullPemKeyBase64.hexDecodedData();
        let base64ToBytes = fullPemKeyBase64.base64Decoded!.bytes
        print("base64ToBytes")
        print(base64ToBytes)
        let privateBytes = base64ToBytes[prefixPrivateKeyData.count..<base64ToBytes.count];
        print("privateByets:\(privateBytes)")
        do {
            if let base64 = from.base64Decoded {
                let privateKey = try Curve25519.Signing.PrivateKey.init(rawRepresentation: base64.bytes)
                print("privateKey after init, base 64 str:")
                print(privateKey.rawRepresentation.base64EncodedString())
                print("privateKEy success, value in bytes:\(privateKey.rawRepresentation.bytes)")
                print("done")
            } else {
                print("Generate from key:\(from) failed!")
            }
        } catch {
            throw GenerateKeyError.PrivateKeyGenerateError
        }
        do {
            let privateKey = try Curve25519.Signing.PrivateKey.init(rawRepresentation: privateBytes)
            print("privateKEy success, value in bytes:\(privateKey.rawRepresentation.bytes)")
            print("privateKey after init, base 64 str:")
            print(privateKey.rawRepresentation.base64EncodedString())
            let subjectPrivateKeyInfo = prefixPrivateKeyData + privateKey.rawRepresentation
            
            print("privateKey after init and add prefix, base 64 str:")
            print(subjectPrivateKeyInfo.base64EncodedString())
            print("done")
            return privateKey
        } catch {
            throw GenerateKeyError.PrivateKeyGenerateError
        }
        
    }
    public func writePrivateKeyToFile(privateKeyInBase64:String) {
        let dirPath = NSTemporaryDirectory()
        print("dirPath:\(dirPath)")
        let bundleMainPath = Bundle.main.bundlePath
        print("bundleMainPath is:\(bundleMainPath)")
        let canCreate = FileManager.default.isWritableFile(atPath:dirPath)
        if (canCreate) {
            print("Can create at dirpath");
        }
        let file = "ed25519SwiftSecretKey.pem"
        var text = "-----BEGIN PRIVATE KEY-----" //just a text
        text = text + "\n" + privateKeyInBase64
        text = text + "\n" + "-----END PRIVATE KEY-----"

        if let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {

            let fileURL = dir.appendingPathComponent(file)
            
            print("File url:\(fileURL)");

            //writing
            do {
                try text.write(to: fileURL, atomically: false, encoding: .utf8)
            }
            catch {/* error handling here */}

            //reading
            do {
                let text2 = try String(contentsOf: fileURL, encoding: .utf8)
                print("Text from Pem file is:\n\(text2)")
               
            }
            catch {
                print("Error:\(error)")
            }
        }
    }
    public func keyGenerate5() {
        let privateKey = Curve25519.Signing.PrivateKey.init();
        let publicKey = privateKey.publicKey;
        
    }
    public func keyGenerate3() {
        //readPrivateKeyFromFile(fileName: "scalaEd25519SecretKey.pem");
        //readPrivateKeyFromFile(fileName: "ed25519SwiftSecretKey.pem");
        do {
            let private1 = try fromPemFileToPrivateKeyBase64String(pemFileName: "scalaEd25519SecretKey.pem")
            print("private 1:\(private1)")
            let privateKeyReal1 = try fromBase64StringToPrivateKey(from: private1)
        } catch {
            print("Error:\(error)")
        }
        do {
            let private2 = try fromPemFileToPrivateKeyBase64String(pemFileName: "ed25519SwiftSecretKey.pem")
            print("private 2:\(private2)")
            let privateKeyReal2 = try fromBase64StringToPrivateKey(from: private2)
        } catch {
            print("Error:\(error)")
        }
        base64ToHex(base64Str: "MCowBQYDK2VuAyEA")
        print("-----")
        base64ToHex(base64Str: "MC4CAQAwBQYDK2VwBCIEI")
       // base64ToHex(base64Str: "MFECAQEwBQYDK2VwBCIEIPKrYesu4to9hvMQ/vx6IRn9erMVZx1OANgJK3RxxOAsgSEA3sD0ugHBfA5Agv1AW2rlP3NpMJ0C0DSNhURfG3HzHrI=");
        base64ToHex(base64Str: "MC4CAQAwBQYDK2VwBCIEIEboFx3ESggkPbLzvNLlu8ZKHhltdRfxAlocKbW0SEv3")
        base64ToHex(base64Str: "MC4CAQAwBQYDK2VwBCIEINRjlbiAvFJvucKQAmvDatlOviXQg9bU+yh1dw8+Mexs")
        let privateKey = Curve25519.Signing.PrivateKey.init();
        let publicKey = privateKey.publicKey;
        //private key to PEM
        
        print("prefixPublicKey to hexa string:\(prefixPublicKeyData.toHexString())")
        print("prefixPublicKey to bytes:\(prefixPublicKeyData.bytes)")
        print("prefixPublicKey to base64:\(prefixPublicKeyData.base64EncodedString())")
        //private and public to hexa string
        
     //   print("privateKey in hexastring:\(privateKey.rawRepresentation.hexEncodedString())")
        
    //    print("publicKey in hexastring:\(publicKey.rawRepresentation.hexEncodedString())")
        
        print("privateKey Bytes:\(privateKey.rawRepresentation.bytes)")
        print("publicKey bytes:\(publicKey.rawRepresentation.bytes)")
        
        let subjectPublicKeyInfo = prefixPublicKeyData + publicKey.rawRepresentation
   //     print("subjectPublicKeyInfo in hexastring:\(subjectPublicKeyInfo.toHexString())")
        let pemPublicKeyString = subjectPublicKeyInfo.base64EncodedString();
        let subjectPrivateKeyInfo = prefixPrivateKeyData + privateKey.rawRepresentation
   //     print("subjectPrivateKeyInfo in hexastring:\(subjectPrivateKeyInfo.toHexString())")
        
        print("subjectPrivateKeyInfo bytes:\(subjectPrivateKeyInfo.bytes)")

        print("subjectPublicKeyInfo bytes:\(subjectPublicKeyInfo.bytes)")
        let pemPrivateKeyString = subjectPrivateKeyInfo.base64EncodedString()
        writePrivateKeyToFile(privateKeyInBase64: pemPrivateKeyString);
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
    
}

