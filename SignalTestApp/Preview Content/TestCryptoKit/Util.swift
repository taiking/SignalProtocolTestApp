//
//  Util.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/19.
//

import Foundation
import CryptoKit

/// シンプルなKDF: HMAC-SHA256で (key, data) から 32byte 派生
/// 必要に応じて HKDF を使う等、要件に応じて実装を変えること
func kdf(key: Data, data: Data) -> Data {
    let symmetricKey = SymmetricKey(data: key)
    let mac = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)
    return Data(mac)
}

/// AliceがBobのPublishedKeysを使ってセッションを初期化する想定の例
/// - Parameters:
///   - aliceIdentityKeyPair: AliceのIdentity Key
///   - bobPublishedKeys: Bobがサーバに公開している鍵情報
///   - bobOneTimePreKeyIndex: 使用するOne-Time PreKeyのインデックス(実際にはサーバが配布してくれる想定)
/// - Returns: 初期化されたセッション
func initiateX3DHSession(aliceIdentityKeyPair: IdentityKeyPair,
                         bobPublishedKeys: PublishedKeys,
                         bobOneTimePreKeyIndex: Int) -> (SessionState, Curve25519.KeyAgreement.PrivateKey) {

    // AliceのEphemeral Keyペアを生成
    let aliceEphemeralKeyPrivate = Curve25519.KeyAgreement.PrivateKey()
    let aliceEphemeralKeyPublic = aliceEphemeralKeyPrivate.publicKey

    // BobのOne-Time PreKey
    let bobOTPK = bobPublishedKeys.preKeys[bobOneTimePreKeyIndex]

    // 1. DH(IKA, SPKB)
    let dh1 = try! aliceIdentityKeyPair.privateKey.sharedSecretFromKeyAgreement(with: bobPublishedKeys.signedPreKey).withUnsafeBytes { Data($0) }

    // 2. DH(EKA, IKB)
    let dh2 = try! aliceEphemeralKeyPrivate.sharedSecretFromKeyAgreement(with: bobPublishedKeys.identityKey).withUnsafeBytes { Data($0) }

    // 3. DH(EKA, SPKB)
    let dh3 = try! aliceEphemeralKeyPrivate.sharedSecretFromKeyAgreement(with: bobPublishedKeys.signedPreKey).withUnsafeBytes { Data($0) }

    // 4. DH(EKA, OPKB)
    let dh4 = try! aliceEphemeralKeyPrivate.sharedSecretFromKeyAgreement(with: bobOTPK).withUnsafeBytes { Data($0) }

    // それぞれの共有秘密を連結し、KDFにかける (シンプルに連結 → KDFしてるだけの例)
    let masterSecret = dh1 + dh2 + dh3 + dh4
    let rootKey = kdf(key: Data(repeating: 0, count: 32), data: masterSecret)

    // Double Ratchet開始
    // 最初のratchet public key = AliceのEphemeral Key
    // ここでは送信チェーン鍵と受信チェーン鍵をシンプルに派生
    let sendChainKey = kdf(key: rootKey, data: aliceEphemeralKeyPublic.rawRepresentation)
    let receiveChainKey = kdf(key: rootKey, data: bobPublishedKeys.identityKey.rawRepresentation)

    let sessionState = SessionState(
        rootKey: rootKey,
        sendChainKey: sendChainKey,
        receiveChainKey: receiveChainKey,
        sendRatchetPublicKey: aliceEphemeralKeyPublic,
        receiveRatchetPublicKey: nil
    )

    return (sessionState, aliceEphemeralKeyPrivate)
}

/// 32byteをさらに2つに分割して (rootKey, chainKey) を得る簡易例
func kdfRootAndChainKey(oldRootKey: Data, dhData: Data) -> (Data, Data) {
    let newRootKey = kdf(key: oldRootKey, data: dhData)
    let newChainKey = kdf(key: newRootKey, data: dhData)
    return (newRootKey, newChainKey)
}

/// チェーン鍵からメッセージ鍵を導出し、次のチェーン鍵を更新する
func kdfChainKey(chainKey: Data) -> (messageKey: Data, nextChainKey: Data) {
    let messageKey = kdf(key: chainKey, data: Data("messageKey".utf8))
    let nextChainKey = kdf(key: chainKey, data: Data("chainKey".utf8))
    return (messageKey, nextChainKey)
}

/// AES-GCMで暗号化
func encryptMessage(messageKey: Data, plaintext: Data, associatedData: Data?) -> Data {
    let symmetricKey = SymmetricKey(data: messageKey)
    let sealedBox = try! AES.GCM.seal(plaintext, using: symmetricKey, nonce: AES.GCM.Nonce(), authenticating: associatedData ?? Data())
    return sealedBox.combined!
}

/// AES-GCMで復号
func decryptMessage(messageKey: Data, ciphertext: Data, associatedData: Data?) -> Data? {
    let symmetricKey = SymmetricKey(data: messageKey)
    guard let sealedBox = try? AES.GCM.SealedBox(combined: ciphertext) else {
        return nil
    }
    return try? AES.GCM.open(sealedBox, using: symmetricKey, authenticating: associatedData ?? Data())
}
