//
//  ContentViewModel.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/13.
//

import Foundation
import LibSignalClient

final class ContentViewModel: ObservableObject {
    
    // 初期メッセージをアリスから、ボブに送り、それをボブが復号する。そしてボブが返事を送り、アリスが複合するまでのサンプル
    init() {
        
        demoSignalProtocol()
        
        return
        
        do {
            // 初期セットアップ
            let aliceAddress = try! ProtocolAddress(name: "+14151111111", deviceId: 1)
            let bobAddress = try! ProtocolAddress(name: "+14151111112", deviceId: 1)

            let aliceStore = InMemorySignalProtocolStore()
            let bobStore = InMemorySignalProtocolStore()
            
            let bobPreKey = PrivateKey.generate()
            let bobSignedPreKey = PrivateKey.generate()

            let bobSignedPreKeyPublic = bobSignedPreKey.publicKey.serialize()

            let bobIdentityKey = try bobStore.identityKeyPair(context: NullContext()).identityKey
            let bobSignedPreKeySignature = try bobStore.identityKeyPair(context: NullContext()).privateKey.generateSignature(message: bobSignedPreKeyPublic)

            let prekeyId: UInt32 = 4570
            let signedPrekeyId: UInt32 = 3006

            let bobBundle = try PreKeyBundle(
                registrationId: bobStore.localRegistrationId(context: NullContext()),
                deviceId: 9,
                prekeyId: prekeyId,
                prekey: bobPreKey.publicKey,
                signedPrekeyId: signedPrekeyId,
                signedPrekey: bobSignedPreKey.publicKey,
                signedPrekeySignature: bobSignedPreKeySignature,
                identity: bobIdentityKey
            )

            // アリスがボブのPublic KeyからSessionを確立
            try processPreKeyBundle(
                bobBundle,
                for: bobAddress,
                sessionStore: aliceStore,
                identityStore: aliceStore,
                context: NullContext()
            )
            
            let initialMessage = "Hello Bob! How are you?"
            print("Alice Message: \(initialMessage)")
            let initialMessageData: [UInt8] = initialMessage.toUInt8()
            
            let encrypted = try signalEncrypt(
                message: initialMessageData,
                for: bobAddress,
                sessionStore: aliceStore,
                identityStore: aliceStore,
                context: NullContext()
            )
            
            print("Encrypted Message: \(encrypted.serialize().toBase64())")
            
            // ここからはボブの処理。受け取ったメッセージからアリスの公開鍵とボブの秘密鍵で復号
            // ボブがアリスのPublic KeyからSessionを確立
            try bobStore.storePreKey(
                PreKeyRecord(id: prekeyId, privateKey: bobPreKey),
                id: prekeyId,
                context: NullContext()
            )
            try bobStore.storeSignedPreKey(
                SignedPreKeyRecord(
                    id: signedPrekeyId,
                    timestamp: 42000,
                    privateKey: bobSignedPreKey,
                    signature: bobSignedPreKeySignature
                ),
                id: signedPrekeyId,
                context: NullContext()
            )

            let decryptedBytes = try signalDecryptPreKey(
                message: try PreKeySignalMessage(bytes: encrypted.serialize()),
                from: aliceAddress,
                sessionStore: bobStore,
                identityStore: bobStore,
                preKeyStore: bobStore,
                signedPreKeyStore: bobStore,
                kyberPreKeyStore: bobStore,
                context: NullContext()
            )
            
            let decrypted = String(bytes: decryptedBytes, encoding: String.Encoding.utf8)!
            print("Decrypted Message: \(decrypted)")
            
            // ボブが返事する
            let bobReplyMessage = "Long time no see, Alice. I'm fine."
            print("Bob Reply Message: \(bobReplyMessage)")
            let encryptedReply = try signalEncrypt(
                message: bobReplyMessage.toUInt8(),
                for: aliceAddress,
                sessionStore: bobStore,
                identityStore: bobStore,
                context: NullContext()
            )
            print("Encrypted Reply Message: \(encryptedReply.serialize().toBase64())")
            
            // アリスが復号する
            let decryptedReplyBytes = try! signalDecrypt(
                message: try SignalMessage(bytes: encryptedReply.serialize()),
                from: bobAddress,
                sessionStore: aliceStore,
                identityStore: aliceStore,
                context: NullContext()
            )
            let decryptedReply = String(bytes: decryptedReplyBytes, encoding: String.Encoding.utf8)!
            print("Decrypted Reply Message: \(decryptedReply)")
        } catch {
            print("error")
            print(error)
        }
    }

}
