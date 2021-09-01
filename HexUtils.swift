//
//  HextUtils.swift
//
//  Created by Ayodeji Bamitale on 30/08/2021.
//

import Foundation


extension Data {
    //From https://gist.github.com/vincent-peng/07897b760c9e27573957a4cf7d10b5ee
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined().uppercased()
    }
}

extension String {
    func dataFromHexString() -> Data? {
        let string = self
        let data = NSMutableData()

        var fromIndex = string.startIndex
        while let toIndex = string.index(fromIndex, offsetBy: 2, limitedBy: string.endIndex) {

            // Extract hex code at position fromIndex ..< toIndex:
            let byteString = string[fromIndex..<toIndex]
            var num = UInt8(byteString.withCString { strtoul($0, nil, 16) })
            data.append(&num, length: 1)

            // Advance to next position:
            fromIndex = toIndex
        }

        return data as Data
    }
}
