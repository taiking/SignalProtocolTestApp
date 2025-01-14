//
//  KeyManager.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/13.
//

import LibSignalClient

class KeyManager {
    
    static let shared = KeyManager()
    
    private init() {}
    
    // IdentityKeyPairの生成
    func generateIdentityKeyPair() -> IdentityKeyPair {
        return IdentityKeyPair.generate()
    }
    
    // RegistrationIdの生成
    func generateRegistrationId() -> UInt32 {
        return UInt32.random(in: 0...0x3FFF)
    }
    
    // SignedPreKeyRecordの生成
    func generateSignedPreKey(identityKeyPair: IdentityKeyPair, signedPreKeyId: UInt32) throws -> SignedPreKeyRecord {
        let privateKey = PrivateKey.generate()
        let signature = identityKeyPair.privateKey.generateSignature(message: privateKey.publicKey.serialize())
        return try SignedPreKeyRecord(id: signedPreKeyId, timestamp: UInt64(Date().timeIntervalSince1970), privateKey: privateKey, signature: signature)
    }
    
    // PreKeysの生成
    func generatePreKeys(start: UInt32, count: UInt32) throws -> [PreKeyRecord] {
        var results = [PreKeyRecord]()
        for i in start..<start + count {
            let id = ((start + i) % (KeyManager.maxPreKeyValue - 1)) + 1
            let privateKey = PrivateKey.generate()
            results.append(try PreKeyRecord(id: UInt32(id), publicKey: privateKey.publicKey, privateKey: privateKey))
        }
        return results
    }
    
    // 登録情報の生成
    func generateKeys() throws -> Registration {
        let identityKeyPair = generateIdentityKeyPair()
        let registrationId = generateRegistrationId()
        let signedPreKey = try generateSignedPreKey(identityKeyPair: identityKeyPair, signedPreKeyId: UInt32.random(in: 1...KeyManager.maxPreKeyValue - 1))
        let start = UInt32.random(in: 1...KeyManager.maxPreKeyValue - 101)
        let preKeys = try generatePreKeys(start: start, count: 100)
        
        return Registration(identityKeyPair: identityKeyPair, registrationId: registrationId, preKeys: preKeys, signedPreKeyRecord: signedPreKey)
    }
    
    // 最大値の定義（PreKey生成時に使用）
    static let maxPreKeyValue: UInt32 = 16777215
}
