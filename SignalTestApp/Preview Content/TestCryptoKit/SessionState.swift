//
//  SessionState.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/19.
//

import Foundation
import CryptoKit

/// Alice/Bob間のセッションを表すための状態
/// DoubleRatchet で使う鍵やラチェット情報も持つ。
struct SessionState {
    var rootKey: Data
    var sendChainKey: Data
    var receiveChainKey: Data
    var sendRatchetPublicKey: Curve25519.KeyAgreement.PublicKey
    var receiveRatchetPublicKey: Curve25519.KeyAgreement.PublicKey?
}

extension SessionState {
    mutating func ratchetEncrypt(plaintext: Data,
                                 receiverRatchetPublicKey: Curve25519.KeyAgreement.PublicKey) -> (ciphertext: Data, newPubKey: Curve25519.KeyAgreement.PublicKey) {
        // 新しいDHペア（Aliceが送る場合を想定）
        let newPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let newPublicKey = newPrivateKey.publicKey

        // DHを計算
        let sharedSecret = try! newPrivateKey.sharedSecretFromKeyAgreement(with: receiverRatchetPublicKey).withUnsafeBytes { Data($0) }
        let (newRootKey, newSendChainKey) = kdfRootAndChainKey(oldRootKey: self.rootKey, dhData: sharedSecret)
        
        // メッセージ鍵をチェーン鍵から派生
        let (messageKey, updatedChainKey) = kdfChainKey(chainKey: newSendChainKey)

        // 暗号化 (associatedDataに送信者の新しいラチェット公開鍵などを含める)
        let ad = newPublicKey.rawRepresentation
        let ciphertext = encryptMessage(messageKey: messageKey, plaintext: plaintext, associatedData: ad)

        // セッション更新
        self.rootKey = newRootKey
        self.sendChainKey = updatedChainKey
        self.sendRatchetPublicKey = newPublicKey
        
        return (ciphertext, newPublicKey)
    }

    mutating func ratchetDecrypt(ciphertext: Data,
                                 senderNewPubKey: Curve25519.KeyAgreement.PublicKey,
                                 myPrivateKey: Curve25519.KeyAgreement.PrivateKey) -> Data? {
        // 送信側の新しい公開鍵を受け取った場合はDHを計算してRatchetを進める
        let sharedSecret = try! myPrivateKey.sharedSecretFromKeyAgreement(with: senderNewPubKey).withUnsafeBytes { Data($0) }
        
        let (newRootKey, newReceiveChainKey) = kdfRootAndChainKey(oldRootKey: self.rootKey, dhData: sharedSecret)

        // メッセージ鍵をチェーン鍵から派生
        let (messageKey, updatedChainKey) = kdfChainKey(chainKey: newReceiveChainKey)

        // 復号 (associatedDataに送信者の公開鍵情報)
        let plaintext = decryptMessage(messageKey: messageKey, ciphertext: ciphertext, associatedData: senderNewPubKey.rawRepresentation)

        // セッション更新
        self.rootKey = newRootKey
        self.receiveChainKey = updatedChainKey
        self.receiveRatchetPublicKey = senderNewPubKey

        return plaintext
    }
}
