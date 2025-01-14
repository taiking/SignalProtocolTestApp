//
//  Registration.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/13.
//

import LibSignalClient

struct Registration {
    
    init(identityKeyPair: IdentityKeyPair, registrationId: UInt32, preKeys: [PreKeyRecord], signedPreKeyRecord: SignedPreKeyRecord) {
        self.identityKeyPair = identityKeyPair
        self.registrationId = registrationId
        self.preKeys = preKeys
        self.signedPreKeyRecord = signedPreKeyRecord
    }
    
    // Mark: - String values are BASE64
    init(identityKeyPair: String, registrationId: UInt32, preKeys: [String], signedPreKeyRecord: String) throws {
        self.identityKeyPair = try IdentityKeyPair(bytes: identityKeyPair.toUInt8())
        self.registrationId = registrationId
        self.preKeys = try preKeys.map({ item in
            try PreKeyRecord(bytes: item.toUInt8())
        })
        self.signedPreKeyRecord = try SignedPreKeyRecord(bytes: signedPreKeyRecord.toUInt8())
    }
    
    let identityKeyPair : IdentityKeyPair
    let registrationId : UInt32
    let preKeys : [PreKeyRecord]
    let signedPreKeyRecord : SignedPreKeyRecord
    
    
    public func identityKeyPairBase64() -> String {
        return identityKeyPair.serialize().toBase64()
    }
    
    public func identityKeyPublicBase64() -> String {
        return identityKeyPair.publicKey.serialize().toBase64()
    }
    
    public func preKeyIdsBase64() -> [String] {
        preKeys.map { preKeyRecord in
            preKeyRecord.serialize().toBase64()
        }
    }
    
    public func signedPreKeyRecordBase64() -> String {
        return signedPreKeyRecord.serialize().toBase64()
    }
    
    public func publicIdentityKeyBase64() -> String {
        return identityKeyPair.publicKey.serialize().toBase64()
    }
    
    public func signedPreKeyPublicKeyBase64() throws -> String {
        return try signedPreKeyRecord.publicKey().serialize().toBase64()
    }
    
    public func signedPreKeyId() -> UInt32 {
        return signedPreKeyRecord.id
    }
    
    public func signedPreKeyRecordSignatureBase64() -> String {
        return signedPreKeyRecord.signature.toBase64()
    }
}
