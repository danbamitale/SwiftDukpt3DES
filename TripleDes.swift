//
//  TripleDes.swift
//
//  Created by Ayodeji Bamitale on 30/08/2021.
//  Remember to add '#include <CommonCrypto/CommonCryptor.h>' to your bridging-header

import Foundation

extension Data {
    private func tripleDesKey() -> Data? {
        if self.count == 24 {
            return self
        }
        
        var key = Data(capacity: 24)
        if self.count == 16 {
            key.append(self.subdata(in: 0..<16))
            key.append(self.subdata(in: 0..<8))
            return key
        }
                
        if self.count == 8 {
            for _ in 0...2 {
                key.append(self)
            }
            return key
        }
        
        return nil
    }
    
    private func tripleDesOp(key: Data, operation: CCOperation, options: CCOptions) -> Data? {
        guard let tempKey = key.tripleDesKey() else {
            return nil
        }
        let keyData = NSData(data: tempKey)
        let valueData = NSData(data: self)
        
        let bufferSize = valueData.length +  (UInt32(kCCEncrypt) == operation ? kCCBlockSize3DES : kCCBlockSizeAES128)
        let buffer =  UnsafeMutablePointer<NSData>.allocate(capacity: bufferSize)
        var bytes_encrypted: size_t = 0
        
        let algoritm:  CCAlgorithm = UInt32(kCCAlgorithm3DES)
        let keyLength              = size_t(kCCKeySize3DES)

        let ccStatus: CCCryptorStatus = CCCrypt(operation, algoritm, options, keyData.bytes, keyLength, nil, valueData.bytes, valueData.length, buffer, bufferSize, &bytes_encrypted)
        
        guard ccStatus == CCCryptorStatus(kCCSuccess) else {
            free(buffer)
            return nil
        }
        
        let dataOut = Data(bytes: buffer, count: bytes_encrypted)
        free(buffer)
        return dataOut
    }
    
    func tripleDesEncrypt(with key: Data) -> Data? {
        return tripleDesOp(key: key,operation: UInt32(kCCEncrypt), options: UInt32(kCCOptionECBMode))
    }
    
    func tripleDesDecrypt(with key: Data) -> Data?{
        return tripleDesOp(key: key, operation: UInt32(kCCDecrypt), options: UInt32(kCCOptionECBMode))
    }
    
    func tripleDesEncryptCBC(with key: Data) -> Data? {
        return tripleDesOp(key: key,operation: UInt32(kCCEncrypt), options: UInt32(0))
    }
    
    func tripleDesDecryptCBC(with key: Data) -> Data?{
        return tripleDesOp(key: key, operation: UInt32(kCCDecrypt), options: UInt32(0))
    }

}

extension String {
    func tripleDesEncrypt(with key: String) -> Data? {
        return self.dataFromHexString()?.tripleDesEncrypt(with: key.dataFromHexString()!)
    }
    
    func tripleDesDecrypt(with key: String) -> Data? {
        return self.dataFromHexString()?.tripleDesDecrypt(with: key.dataFromHexString()!)
    }
}




