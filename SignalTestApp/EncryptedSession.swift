//
//  EncryptedSession.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/13.
//

import LibSignalClient

class EncryptedSession {
    
    final let localUser : LocalUser
    final let remoteUser : RemoteUser?
    final let remoteUserProtocolAddress : ProtocolAddress
    
    private final let protocolStore : InMemorySignalProtocolStore
    
    init(localUser : LocalUser, remoteUser : RemoteUser) throws {
        self.localUser = localUser
        self.remoteUser = remoteUser
        self.remoteUserProtocolAddress = remoteUser.protocolAddress
        self.protocolStore = InMemorySignalProtocolStore(identity: localUser.identitykey, registrationId: localUser.registrationId)
        try initProtocolStore()
    }
    
    init(localUser : LocalUser,remoteUserProtocolAddress : ProtocolAddress) throws {
        remoteUser = nil
        self.localUser = localUser
        self.remoteUserProtocolAddress = remoteUserProtocolAddress
        self.protocolStore = InMemorySignalProtocolStore(identity: localUser.identitykey, registrationId: localUser.registrationId)
        try initProtocolStore()
    }
    
    
    public func encrypt(message : String) throws -> String {
       let buf = [UInt8](message.utf8)
       let cipherTextMessage =  try signalEncrypt(message: buf, for: remoteUserProtocolAddress, sessionStore: protocolStore, identityStore: protocolStore, context: NullContext())
        let preSignalMessage = try PreKeySignalMessage(bytes: cipherTextMessage.serialize())
        return try preSignalMessage.serialize().toBase64()
    }
    
    public func decrypt(message : String) throws -> String? {
        let bytes = try signalDecryptPreKey(message: PreKeySignalMessage(bytes: message.toUInt8()), from: remoteUserProtocolAddress, sessionStore: protocolStore, identityStore: protocolStore, preKeyStore: protocolStore, signedPreKeyStore: protocolStore, kyberPreKeyStore: protocolStore, context: NullContext())
        
        return String(bytes: bytes, encoding: String.Encoding.utf8)
    }
    
    private func initProtocolStore() throws {
        
        for preKey in localUser.preKeys {
            try protocolStore.storePreKey(preKey, id: preKey.id, context: NullContext())
        }
        
        try protocolStore.storeSignedPreKey(localUser.signedPreKey, id: localUser.signedPreKey.id, context: NullContext())
        
        if let remoteUser = self.remoteUser {
            
            let preKeyBundle = try PreKeyBundle(registrationId: remoteUser.registrationId, deviceId: remoteUser.protocolAddress.deviceId, prekeyId: remoteUser.preKeyId, prekey: remoteUser.preKeyPublicKey, signedPrekeyId: remoteUser.signedPreKeyId, signedPrekey: remoteUser.signedPreKeyPublicKey, signedPrekeySignature: remoteUser.signedPreKeySignature, identity: remoteUser.identityKeyPairPublicKey)
            try processPreKeyBundle(preKeyBundle, for: remoteUser.protocolAddress, sessionStore: protocolStore, identityStore: protocolStore, context: NullContext())
            
        }
    }
}
enum Operation {
    case encrypt, decrypt
}
