//
//  RemoteUser.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/13.
//

import LibSignalClient

struct RemoteUser {
    
    internal init(preKeyId: UInt32, preKeyPublicKey: PublicKey, signedPreKeyId: UInt32, signedPreKeyPublicKey: PublicKey, signedPreKeySignature: [UInt8], identityKeyPairPublicKey: IdentityKey,deviceId : UInt32, name : String,registrationId : UInt32) throws {
        self.preKeyId = preKeyId
        self.preKeyPublicKey = preKeyPublicKey
        self.signedPreKeyId = signedPreKeyId
        self.signedPreKeyPublicKey = signedPreKeyPublicKey
        self.signedPreKeySignature = signedPreKeySignature
        self.identityKeyPairPublicKey = identityKeyPairPublicKey
        self.protocolAddress = try ProtocolAddress(name: name, deviceId: deviceId)
        self.registrationId = registrationId
    }
    
    
    internal init(preKeyId: UInt32, preKeyPublicKey: [UInt8], signedPreKeyId: UInt32, signedPreKeyPublicKey: [UInt8], signedPreKeySignature: [UInt8], identityKeyPairPublicKey: [UInt8],deviceId : UInt32, name : String,registrationId : UInt32) throws {
        self.preKeyId = preKeyId
        self.preKeyPublicKey = try PublicKey(preKeyPublicKey)
        self.signedPreKeyId = signedPreKeyId
        self.signedPreKeyPublicKey = try PublicKey(signedPreKeyPublicKey)
        self.signedPreKeySignature = signedPreKeySignature
        self.identityKeyPairPublicKey = IdentityKey(publicKey: try PublicKey(identityKeyPairPublicKey))
        self.protocolAddress = try ProtocolAddress(name: name, deviceId: deviceId)
        self.registrationId = registrationId
        
    }
    let preKeyId : UInt32
    let preKeyPublicKey : PublicKey
    let signedPreKeyId : UInt32
    let signedPreKeyPublicKey : PublicKey
    let signedPreKeySignature : [UInt8]
    let identityKeyPairPublicKey : IdentityKey
    let protocolAddress : ProtocolAddress
    let registrationId : UInt32
}
