//
//  demo.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/19.
//

import Foundation
import CryptoKit

func demoSignalProtocol() {
    // --- Bobが初期設定 ---
    let bobIdentity = generateIdentityKeyPair()
    let bobSignedPreKey = generateSignedPreKeyPair(identityKeyPair: bobIdentity)
    let bobOneTimePreKeys = generateOneTimePreKeys(count: 5)
    let bobUser = SignalUser(userID: "Bob",
                             identityKeyPair: bobIdentity,
                             signedPreKeyPair: bobSignedPreKey,
                             oneTimePreKeys: bobOneTimePreKeys)

    // サーバに bobUser.publishedKeys() を保存したと想定

    // --- AliceがBobの情報を取得して初期セッション ---
    let aliceIdentity = generateIdentityKeyPair()
    let bobKeysFromServer = bobUser.publishedKeys()

    // One-Time PreKeyのどれを使うか(ここでは0番目を使用とする)
    let (aliceSession, aliceEphemeralPrivateKey) =
        initiateX3DHSession(aliceIdentityKeyPair: aliceIdentity,
                            bobPublishedKeys: bobKeysFromServer,
                            bobOneTimePreKeyIndex: 0)

    var aliceSessionState = aliceSession

    // --- Bob側も同じ鍵を復元する想定 ---
    // Bobは、Aliceから送られた ephemeralPublicKey や AliceのIdentityPublicKey などを受け取り、
    // 同じ計算を行って同じ rootKey を導出する。
    // ここでは「Aliceの ephemeral private key」を使ってDHする代わりにBob側の計算を直接書くサンプル
    func bobRestoreSession(aliceEphemeralPublicKey: Curve25519.KeyAgreement.PublicKey,
                           aliceIdentityPublicKey: Curve25519.KeyAgreement.PublicKey,
                           bobUser: SignalUser,
                           usedPreKeyIndex: Int) -> SessionState {
        
        let bobIdentityPriv = bobUser.identityKeyPair.privateKey
        let bobSignedPreKeyPriv = bobUser.signedPreKeyPair.keyPair.privateKey
        let bobOneTimePreKeyPriv = bobUser.oneTimePreKeys[usedPreKeyIndex].privateKey

        // 1. DH(IKB, SPKA) -> ここではAliceのSignedPreKeyがあれば計算するが、今回は省略
        //    実際にはAliceのSignedPreKeyが不要で、AliceはEphemeralKeyを使うのでここはシンプルに書き換えます。

        // 1. DH(IKB, EKA)
        let dh1 = try! bobIdentityPriv.sharedSecretFromKeyAgreement(with: aliceEphemeralPublicKey).withUnsafeBytes { Data($0) }
        // 2. DH(SPKB, IKA)
        let dh2 = try! bobSignedPreKeyPriv.sharedSecretFromKeyAgreement(with: aliceIdentityPublicKey).withUnsafeBytes { Data($0) }
        // 3. DH(SPKB, EKA)
        let dh3 = try! bobSignedPreKeyPriv.sharedSecretFromKeyAgreement(with: aliceEphemeralPublicKey).withUnsafeBytes { Data($0) }
        // 4. DH(OPKB, EKA)
        let dh4 = try! bobOneTimePreKeyPriv.sharedSecretFromKeyAgreement(with: aliceEphemeralPublicKey).withUnsafeBytes { Data($0) }

        let masterSecret = dh1 + dh2 + dh3 + dh4
        let rootKey = kdf(key: Data(repeating: 0, count: 32), data: masterSecret)

        // Double Ratchet用にチェーン鍵を生成
        let sendChainKey = kdf(key: rootKey, data: bobUser.identityKeyPair.publicKey.rawRepresentation)
        let receiveChainKey = kdf(key: rootKey, data: aliceEphemeralPublicKey.rawRepresentation)

        return SessionState(
            rootKey: rootKey,
            sendChainKey: sendChainKey,
            receiveChainKey: receiveChainKey,
            sendRatchetPublicKey: bobUser.identityKeyPair.publicKey,
            receiveRatchetPublicKey: nil
        )
    }

    var bobSessionState = bobRestoreSession(
        aliceEphemeralPublicKey: aliceSessionState.sendRatchetPublicKey,
        aliceIdentityPublicKey: aliceIdentity.publicKey,
        bobUser: bobUser,
        usedPreKeyIndex: 0
    )

    // --- Double Ratchetでメッセージ送受信 ---
    // Alice → Bob
    let messageFromAlice = "Hello Bob!".data(using: .utf8)!
    let (ciphertext, aliceNewPubKey) =
        aliceSessionState.ratchetEncrypt(plaintext: messageFromAlice,
                                         receiverRatchetPublicKey: bobUser.identityKeyPair.publicKey)

    // Bobが受け取る
    if let decrypted = bobSessionState.ratchetDecrypt(ciphertext: ciphertext,
                                                      senderNewPubKey: aliceNewPubKey,
                                                      myPrivateKey: bobUser.identityKeyPair.privateKey) {
        print("Bob received:", String(data: decrypted, encoding: .utf8) ?? "decode error")
    }

    // Bob → Alice
    let messageFromBob = "Hello Alice!".data(using: .utf8)!
    let (bobCiphertext, bobNewPubKey) =
        bobSessionState.ratchetEncrypt(plaintext: messageFromBob,
                                       receiverRatchetPublicKey: aliceIdentity.publicKey)

    // Aliceが受け取る
    if let decrypted2 = aliceSessionState.ratchetDecrypt(ciphertext: bobCiphertext,
                                                         senderNewPubKey: bobNewPubKey,
                                                         myPrivateKey: aliceEphemeralPrivateKey) {
        print("Alice received:", String(data: decrypted2, encoding: .utf8) ?? "decode error")
    }
}
