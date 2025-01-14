//
//  LocalUser.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/13.
//

import LibSignalClient

struct LocalUser {
    let identitykey : IdentityKeyPair
    let registrationId : UInt32
    let preKeys : [PreKeyRecord]
    let signedPreKey : SignedPreKeyRecord
    let address : ProtocolAddress
    
    public init(identitykey: IdentityKeyPair,
                registrationId: UInt32,
                preKeys: [PreKeyRecord],
                signedPreKey: SignedPreKeyRecord,
                deviceId : UInt32, // pass static deviceId from KeyHelper
                name : String // pass user Id
    ) throws {
        self.identitykey = identitykey
        self.registrationId = registrationId
        self.preKeys = preKeys
        self.signedPreKey = signedPreKey
        self.address = try ProtocolAddress(name: name, deviceId: deviceId)
    }
    
    public init(identitykey: [UInt8],
                registrationId: UInt32,
                preKeys: [[UInt8]],
                signedPreKey: [UInt8],
                deviceId : UInt32, // pass static deviceId from KeyHelper
                name : String // pass user Id
    ) throws {
        self.identitykey = try IdentityKeyPair(bytes: identitykey)
        self.registrationId = registrationId
        self.preKeys = try preKeys.map({ bytes in
            try PreKeyRecord(bytes: bytes)
        })
        self.signedPreKey = try SignedPreKeyRecord(bytes: signedPreKey)
        self.address = try ProtocolAddress(name: name, deviceId: deviceId)
    }
}
