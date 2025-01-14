//
//  ContentViewModel.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/13.
//

import Foundation
import LibSignalClient

final class ContentViewModel: ObservableObject {
    
    init() {
        print("111111111111111")
        do {
            
            let alice_address = try! ProtocolAddress(name: "+14151111111", deviceId: 1)
            let bob_address = try! ProtocolAddress(name: "+14151111112", deviceId: 1)

            let alice_store = InMemorySignalProtocolStore()
            let bob_store = InMemorySignalProtocolStore()
            
            let bob_pre_key = PrivateKey.generate()
            let bob_signed_pre_key = PrivateKey.generate()

            let bob_signed_pre_key_public = bob_signed_pre_key.publicKey.serialize()

            let bob_identity_key = try! bob_store.identityKeyPair(context: NullContext()).identityKey
            let bob_signed_pre_key_signature = try! bob_store.identityKeyPair(context: NullContext()).privateKey.generateSignature(message: bob_signed_pre_key_public)

            let prekey_id: UInt32 = 4570
            let signed_prekey_id: UInt32 = 3006

            let bob_bundle = try! PreKeyBundle(
                registrationId: bob_store.localRegistrationId(context: NullContext()),
                deviceId: 9,
                prekeyId: prekey_id,
                prekey: bob_pre_key.publicKey,
                signedPrekeyId: signed_prekey_id,
                signedPrekey: bob_signed_pre_key.publicKey,
                signedPrekeySignature: bob_signed_pre_key_signature,
                identity: bob_identity_key
            )

            // Alice processes the bundle:
            try! processPreKeyBundle(
                bob_bundle,
                for: bob_address,
                sessionStore: alice_store,
                identityStore: alice_store,
                context: NullContext()
            )

            // Bob does the same:
            try! bob_store.storePreKey(
                PreKeyRecord(id: prekey_id, privateKey: bob_pre_key),
                id: prekey_id,
                context: NullContext()
            )

            try! bob_store.storeSignedPreKey(
                SignedPreKeyRecord(
                    id: signed_prekey_id,
                    timestamp: 42000,
                    privateKey: bob_signed_pre_key,
                    signature: bob_signed_pre_key_signature
                ),
                id: signed_prekey_id,
                context: NullContext()
            )
            
            
            
            let ptext_a: [UInt8] = "hellow workd!! go!!".toUInt8()
            
            let ctext_a = try! signalEncrypt(
                message: ptext_a,
                for: bob_address,
                sessionStore: alice_store,
                identityStore: alice_store,
                context: NullContext()
            )

            let ctext_b = try! PreKeySignalMessage(bytes: ctext_a.serialize())
            
            print(try ctext_b.serialize().toBase64())

            let ptext_b = try! signalDecryptPreKey(
                message: ctext_b,
                from: alice_address,
                sessionStore: bob_store,
                identityStore: bob_store,
                preKeyStore: bob_store,
                signedPreKeyStore: bob_store,
                kyberPreKeyStore: bob_store,
                context: NullContext()
            )
            
            print(String(bytes: ptext_b, encoding: String.Encoding.utf8))
        } catch {
            print("error")
            print(error)
        }
    }

}
