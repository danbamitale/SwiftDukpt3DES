# SwiftDukpt3DES
A 3DES DUKPT Swift implementation 

!! Need to add '#include <CommonCrypto/CommonCryptor.h>' to your bridging header

## Usage

```
func testPinBlockDecryption() throws {
    let bdk = "............................"
    let ksn = "..................."
    
    let dukpt = SwiftDukpt(BDK: bdk, KSN: ksn)
    let clearPinblock =  dukpt.decryptPinblock("50F95A4F044ABCD7".dataFromHexString()!)!
    print(clearPinblock.hexEncodedString())
}

func testPinBlockEncryption() throws {
    let bdk = "............................"
    let ksn = "..................."
    
    let dukpt = SwiftDukpt(BDK: bdk, KSN: ksn)
    let clearPinblock =  dukpt.encryptPinblock("0412346E7ECA8677".dataFromHexString()!)!
    print(clearPinblock.hexEncodedString())
}

func testDataDecryption() throws {
    let bdk = "............................"
    let ksn = "..................."
    
    let dukpt = SwiftDukpt(BDK: bdk, KSN: ksn)
    
    let data = "........................"
    
    let clearData =  dukpt.decryptData(data.dataFromHexString()!)!
    print(clearData.hexEncodedString())
}
```
