//
//  SignalUser.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/19.
//

import Foundation
import CryptoKit

/// ユーザの長期鍵(Identity Key)ペア
struct IdentityKeyPair {
    let privateKey: Curve25519.KeyAgreement.PrivateKey
    let publicKey: Curve25519.KeyAgreement.PublicKey
}

/// 署名付きPreKey。必要に応じて有効期限なども管理する。
struct SignedPreKeyPair {
    let keyPair: IdentityKeyPair  // ここではシンプルに同じ型を使っているが、本来は別管理でもよい
    let signature: Data
}

/// One-Time PreKey
struct PreKeyPair {
    let privateKey: Curve25519.KeyAgreement.PrivateKey
    let publicKey: Curve25519.KeyAgreement.PublicKey
}

/// ユーザがサーバに登録しておく鍵情報セット (X3DHの際に相手が取得する)
/// - identityKey: ユーザの公開アイデンティティ鍵
/// - signedPreKey: 署名付きPreKey（公開鍵）
/// - preKeys: One-time PreKey（公開鍵）のリスト
struct PublishedKeys {
    let identityKey: Curve25519.KeyAgreement.PublicKey
    let signedPreKey: Curve25519.KeyAgreement.PublicKey
    let preKeys: [Curve25519.KeyAgreement.PublicKey]
}

/// ユーザを表すクラス：IdentityKeyやPreKey等を管理し、サーバに公開する鍵情報をまとめる
class SignalUser {
    let userID: String
    let identityKeyPair: IdentityKeyPair
    let signedPreKeyPair: SignedPreKeyPair
    var oneTimePreKeys: [PreKeyPair]

    init(userID: String,
         identityKeyPair: IdentityKeyPair,
         signedPreKeyPair: SignedPreKeyPair,
         oneTimePreKeys: [PreKeyPair]) {
        self.userID = userID
        self.identityKeyPair = identityKeyPair
        self.signedPreKeyPair = signedPreKeyPair
        self.oneTimePreKeys = oneTimePreKeys
    }

    /// 公開情報をまとめる
    func publishedKeys() -> PublishedKeys {
        return PublishedKeys(
            identityKey: identityKeyPair.publicKey,
            signedPreKey: signedPreKeyPair.keyPair.publicKey,
            preKeys: oneTimePreKeys.map { $0.publicKey }
        )
    }
}
