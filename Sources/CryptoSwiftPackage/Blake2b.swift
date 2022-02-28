import Foundation
import Blake2
public class Blake2b {
    public func test() {
        let data = Data("01d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900ca856a4d37501000080ee36000000000001000000000000004811966d37fe5674a8af4001884ea0d9042d1c06668da0c963769c3a01ebd08f0100000001010101010101010101010101010101010101010101010101010101010101010e0000006361737065722d6578616d706c65".utf8)

        // Simple hash api. 64 byte Blake2b hash.
        let hash = try! Blake2.hash(.b2b, size: 32, data: data)
        print("Hash", hash.hexEncodedString())
        
        let data2 = Data("020e0000006361737065722d6578616d706c65130000006578616d706c652d656e7472792d706f696e7401000000080000007175616e7469747904000000e803000001050100000006000000616d6f756e7404000000e8030000010100000001d9bf2148748a85c89da5aad8ee0b0fc2d105fd39d41a4c796536354f0ae2900c012dbf03817a51794a8e19e0724884075e6d1fbec326b766ecfa6658b41f81290da85e23b24e88b1c8d9761185c961daee1adab0649912a6477bcd2e69bd91bd08".utf8);
        let hash2 = try! Blake2.hash(.b2b, size: 32, data: data2)
        print("Hash2", hash2.hexEncodedString())
        // Streaming hash api. 64 byte Blake2b hash.
        // Create hasher object
        var hasher = try! Blake2(.b2b, size: 32)
        // insert data by chunks
        hasher.update(data)
        // and then finalize hasher
        let hash3 = try! hasher.finalize()
        print("Hash", hash3)
      
    }
}
