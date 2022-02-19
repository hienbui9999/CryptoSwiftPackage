import ed25519swift
import CryptoKit
import secp256k1
import libsecp256k1

//https://cocoapods.org/pods/secp256k1.swift
public class CryptoSwiftPackage {
    
    public private(set) var text = "Hello, World!"

    public init() {
    }
    //https://developer.apple.com/documentation/cryptokit/curve25519/signing
    public func BuildInGenerateKey() {
       // let privateKey = Curve25519.KeyAgreement.PrivateKey()
        //let publicKey = Curve25519.KeyAgreement.PublicKey()
    }
    public func secp256k1GenerateKey() {
        print("-------------------------secp256k1GenerateKey----------------------------------------")
        //ECDSASignature.init(rawRepresentation: <#T##D#>)
       /*
        SECP256K1_API secp256k1_context* secp256k1_context_create(
            unsigned int flags
        ) SECP256K1_WARN_UNUSED_RESULT;
        */
        /*
         #define SECP256K1_CONTEXT_SIGN (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
         
         #define SECP256K1_FLAGS_TYPE_CONTEXT (1 << 0)
         
         #define SECP256K1_FLAGS_BIT_CONTEXT_SIGN (1 << 9)
         seckey
         pubkey
         */
        ///private generation using Swift built in library
        let privateKey = P256.Signing.PrivateKey.init(compactRepresentable: true).rawRepresentation;
        print("private key for P256 is:\(privateKey.base64EncodedString())")
        ///context for handling public key generation and  signing
        let ctx = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN));
        let signature : UnsafeMutablePointer<secp256k1_ecdsa_signature> = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1);
        let messageToSignArray:[UInt8] = [1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8,1,2,3,3,3,4,5,3,4,5,3,4,5,4,4,2];
        var messageToSign : UnsafePointer<UInt8> = UnsafePointer(messageToSignArray);
        ///public key generation
          var pk_secp256k1_pubkey : UnsafeMutablePointer<secp256k1_pubkey> = UnsafeMutablePointer<secp256k1_pubkey>.allocate(capacity: 1);
        if ctx != nil {
            print("Context created,ctx:\(ctx), ctxHashValue:\(ctx?.hashValue)")
            privateKey.withUnsafeBytes { (unsafeBytes) in
                let privateKeyBytes = unsafeBytes.bindMemory(to: UInt8.self).baseAddress!
              //  do_something(bytes, unsafeBytes.count)
                //var public_Key :[UInt8] = [];
                //UnsafeMutablePointer pK: secp256k1_pubkey
             
                ///check private key valid
                let validPrivateKey = secp256k1_ec_seckey_verify(ctx!,privateKeyBytes);
                print("validPrivateKey:\(validPrivateKey)")
                ///make the public key available through the call function
                let result = secp256k1_ec_pubkey_create(ctx!,pk_secp256k1_pubkey,privateKeyBytes);
                print("Publick kEy is:\(pk_secp256k1_pubkey.pointee), result:\(result)")
                ///print the public key back, now in tuple type
                let publicKey = pk_secp256k1_pubkey.pointee.data;
                print("PublicKey:\(publicKey)");
                ///public key from tuple to array
                var array :[UInt8] = withUnsafeBytes(of:publicKey) {
                    buf in
                    [UInt8] (buf)
                }
                print("Public key in Array:\(array)")
                ///sign a message
               // let signature : UnsafeMutablePointer<secp256k1_ecdsa_signature> = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1);
                
                print("signature at first:\(signature.pointee.data)");
                var signatureSForm : UnsafeMutablePointer<secp256k1_ecdsa_signature> = UnsafeMutablePointer<secp256k1_ecdsa_signature>.allocate(capacity: 1);
               
                let resultSign = secp256k1_ecdsa_sign(ctx!,signature,messageToSign,privateKeyBytes,nil,nil);
                print("resultSign:\(resultSign)")
                print("signature:\(signature.pointee.data)");
                let changeSignatureToSFormSuccess =  secp256k1_ecdsa_signature_normalize(ctx!,signatureSForm,signature);
                 print("changeSignatureToSFormSuccess:\(changeSignatureToSFormSuccess)");
                 print("signatureSForm:\(signatureSForm.pointee.data)")
                ///verify a message
                //secp256k1_ecdsa_verify
                //let resultVerifyMessage = secp256k1_ecdsa_verify(ctx!,signature,messageToSign,pk_secp256k1_pubkey);
               // print("The message is verify with result:\(resultVerifyMessage)");
            }
            
        } else {
            print("Context creation failed")
        }
        let ctx2 = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))
        if ctx2 != nil {
            print("Signature in context 2:\(signature.pointee.data)")
            let resultVerifyMessage = secp256k1_ecdsa_verify(ctx2!,signature,messageToSign,pk_secp256k1_pubkey);
            print("The message is verify with result:\(resultVerifyMessage)");
        }
        
    }
    public func GenerateKey() {
        let (publicKey,secretKey) = Ed25519.generateKeyPair();
        print("publicKey:\(publicKey), secreteKey:\(secretKey)")
        let publicKey2 = Ed25519.calcPublicKey(secretKey: secretKey)
        print("PublicKey2:\(publicKey2)")
        if publicKey == publicKey2 {
            print("fit")
        }
        if Ed25519.isValidKeyPair(publicKey: publicKey, secretKey: secretKey) {
            print("Key pair valid")
        } else {
            print("Key pair invalid")
        }
        let message:[UInt8] = [123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,123,13,31,44,55,23,1,45,24,243,111,22,3,2,144,42,3,4,3,5];
        let signedMessage = Ed25519.sign(message: message, secretKey: secretKey);
        print("signed Message:\(signedMessage)")
        if Ed25519.verify(signature: signedMessage, message: message, publicKey: publicKey) {
            print("Sign validate success")
        } else {
            print("Sign valideate fail!")
        }
    }
}
