//
//  extentions.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/13.
//

import Foundation

extension Array where Element == UInt8 {
    func toBase64() -> String {
        let data = Data(self)
        return data.base64EncodedString()
    }
}

extension String {
    func toUInt8() -> [UInt8] {
        return Array(self.utf8)
    }
}
