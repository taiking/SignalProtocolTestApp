//
//  GenerateKey.swift
//  SignalTestApp
//
//  Created by Taiki Tsujibayashi on 2025/01/19.
//

import Foundation
import CryptoKit

/// IdentityKeyの生成例
func generateIdentityKeyPair() -> IdentityKeyPair {
    let privateKey = Curve25519.KeyAgreement.PrivateKey()
    let publicKey = privateKey.publicKey
    return IdentityKeyPair(privateKey: privateKey, publicKey: publicKey)
}

/// SignedPreKeyの生成例（ここではシンプルに署名をECDSAではなくEd25519などで行う場合は別途キーが必要）
/// このサンプルではあくまで擬似的に署名している
func generateSignedPreKeyPair(identityKeyPair: IdentityKeyPair) -> SignedPreKeyPair {
    // ここでは同じ型を使ってしまっているが、本来は署名鍵とDH鍵は別のアルゴリズム(Ed25519とCurve25519)等を使う
    let newPreKey = generateIdentityKeyPair()
    // 擬似的に署名(実際にはEd25519などで署名する)
    let signature = SHA256.hash(data: newPreKey.publicKey.rawRepresentation)
    return SignedPreKeyPair(keyPair: newPreKey, signature: Data(signature))
}

/// One-Time PreKey のリスト生成
func generateOneTimePreKeys(count: Int) -> [PreKeyPair] {
    var preKeys = [PreKeyPair]()
    for _ in 0..<count {
        let privKey = Curve25519.KeyAgreement.PrivateKey()
        let pubKey = privKey.publicKey
        preKeys.append(PreKeyPair(privateKey: privKey, publicKey: pubKey))
    }
    return preKeys
}
