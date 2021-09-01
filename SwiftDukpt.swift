//
//  SwiftDukpt.swift
//
//  Created by Ayodeji Bamitale on 30/08/2021.
//

import Foundation
import CommonCrypto

class SwiftDukpt {
    private var KSN: Data
    private var IPEK: Data
    
    required init(IPEK: Data, KSN: Data) {
        self.IPEK = IPEK
        self.KSN = KSN
    }
    
    convenience init(IPEK: String, KSN: String) {
        self.init(IPEK: IPEK.dataFromHexString()!, KSN: KSN.dataFromHexString()!)
    }
    
    convenience init (BDK: Data, KSN: Data) {
        self.init(IPEK: SwiftDukpt.generateIPEK(ksn: KSN, bdk: BDK), KSN: KSN)
    }
    
    convenience init (BDK: String, KSN: String) {
        self.init(BDK: BDK.dataFromHexString()!, KSN: KSN.dataFromHexString()!)
    }
    
   /// <summary>
  /// Non Reversible Key Generatino Procedure
  /// private function used by GetDUKPTKey
  /// </summary>
   private func NRKGP(key: inout Data, ksn: Data) {
        var temp = Data(count: 8)
        var keyTemp = Data(capacity: 8)
        
        keyTemp.append(key.subdata(in: 0..<8))
    
        for i in 0..<8 {
            temp[i] = ksn[i] ^ key[8 + i]
        }
        
        var keyRight = temp.tripleDesEncrypt(with: keyTemp)!
        for i in 0..<8 {
            keyRight[i] ^= key[8 + i];
        }
        
        keyTemp[0] ^= 0xC0
        keyTemp[1] ^= 0xC0
        keyTemp[2] ^= 0xC0
        keyTemp[3] ^= 0xC0
        key[8] ^= 0xC0
        key[9] ^= 0xC0
        key[10] ^= 0xC0
        key[11] ^= 0xC0
        
        for i in 0..<8 {
            temp[i] = ksn[i] ^ key[8 + i]
        }
        
        let keyLeft = temp.tripleDesEncrypt(with: keyTemp)!
        for i in 0..<8 {
            key[i] = keyLeft[i] ^ key[8 + i]
        }
        
        key[8..<key.count] = keyRight
    }
    

    func getDukptKey() -> Data {
        var key = Data(IPEK)
        var temp = Data(capacity: 8)
        var cnt = Data(count: 3)
        
        cnt[0] = KSN[7] & 0x1F
        cnt[1] = KSN[8]
        cnt[2] = KSN[9]
        
        temp.append(KSN.subdata(in: 2..<8))
        temp.append(contentsOf:[0x00, 0x00])
        temp[5] &= 0xE0
        
        var shift:UInt8 = 0x10
        while (shift > 0) {
            if ((cnt[0] & shift) > 0) {
                temp[5] |= shift;
                NRKGP(key: &key, ksn: temp)
            }
            shift >>= 1
        }
        shift = 0x80;
        while (shift > 0) {
            if ((cnt[1] & shift) > 0) {
                temp[6] |= shift
                NRKGP(key: &key, ksn: temp);
            }
            shift >>= 1
        }
        shift = 0x80;
        while (shift > 0) {
            if ((cnt[2] & shift) > 0) {
                temp[7] |= shift
                NRKGP(key: &key, ksn: temp);
            }
            shift >>= 1;
        }

        return key;
    }
    /// <summary>
    /// Get current PIN Key variant
    /// PIN Key variant is XOR DUKPT Key with 0000 0000 0000 00FF 0000 0000 0000 00FF
    /// </summary>
    /// <param name="ksn">Key serial number(KSN). A 10 bytes data. Which use to determine which BDK will be used and calculate IPEK. With different KSN, the DUKPT system will ensure different IPEK will be generated.
    /// Normally, the first 4 digit of KSN is used to determine which BDK is used. The last 21 bit is a counter which indicate the current key.</param>
    /// <param name="ipek">IPEK (16 byte).</param>
    /// <returns>PIN Key variant (16 byte)</returns>
    func getPinVariant() -> Data {
        var key =  getDukptKey()
        key[7] ^= 0xFF
        key[15] ^= 0xFF

        return key
    }
    
    /// <summary>
    /// Get current Data Key variant
    /// Data Key variant is XOR DUKPT Key with 0000 0000 00FF 0000 0000 0000 00FF 0000
    /// </summary>
    /// <param name="ksn">Key serial number(KSN). A 10 bytes data. Which use to determine which BDK will be used and calculate IPEK. With different KSN, the DUKPT system will ensure different IPEK will be generated.
    /// Normally, the first 4 digit of KSN is used to determine which BDK is used. The last 21 bit is a counter which indicate the current key.</param>
    /// <param name="ipek">IPEK (16 byte).</param>
    /// <returns>Data Key variant (16 byte)</returns>
    func getDataKeyVariant() -> Data {
        var key =  getDukptKey()
        key[5] ^= 0xFF
        key[13] ^= 0xFF

        return key
    }
    
    func getMacKeyVariant() -> Data {
        var key =  getDukptKey()
        key[6] ^= 0xFF
        key[14] ^= 0xFF

        return key
    }
    
    func getDataKey() -> Data {
        let key = getDataKeyVariant()
        return key.tripleDesEncrypt(with: key)!
    }
    
    func decryptPinblock(_ pinBlock: Data) -> Data? {
        return pinBlock.tripleDesDecrypt(with: getPinVariant())
    }
    
    func encryptPinblock(_ pinBlock: Data) -> Data? {
        return pinBlock.tripleDesEncrypt(with: getPinVariant())
    }
    
    func decryptData(_ data: Data) -> Data? {
       return data.tripleDesDecryptCBC(with: getDataKey())
    }
    
    func encryptData(_ data: Data) -> Data? {
        return data.tripleDesEncryptCBC(with: getDataKey())
    }
    
    func decryptMac(_ mac: Data) -> Data? {
       return mac.tripleDesDecryptCBC(with: getDataKey())
    }
    
    func encryptMac(_ mac: Data) -> Data? {
        return mac.tripleDesEncryptCBC(with: getDataKey())
    }
    
    static func generateIPEK(ksn: Data, bdk: Data) -> Data{
        var result = Data(capacity: 16)
        var temp = Data(capacity: 8)
        var keyTemp = Data(bdk)
                
        temp.append(ksn.subdata(in: 0..<8))
        temp[7] &= 0xE0
        
        var temp2 = temp.tripleDesEncrypt(with: keyTemp)!
        result.append(temp2.subdata(in: 0..<8))
        
        keyTemp[0] = keyTemp[0] ^ 0xC0
        keyTemp[1] = keyTemp[1] ^ 0xC0
        keyTemp[2] = keyTemp[2] ^ 0xC0
        keyTemp[3] = keyTemp[3] ^ 0xC0
        keyTemp[8] = keyTemp[8] ^ 0xC0
        keyTemp[9] = keyTemp[9] ^ 0xC0
        keyTemp[10] = keyTemp[10] ^ 0xC0
        keyTemp[11] = keyTemp[11] ^ 0xC0
        
        temp2 = temp.tripleDesEncrypt(with: keyTemp)!
        result.append(temp2.subdata(in: 0..<8))
        
        
        return result
    }
}
