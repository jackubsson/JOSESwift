//
//  AESGCM.swift
//  JOSESwift
//

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

internal enum AESGCM {
    static func encrypt(
        plaintext: Data,
        encryptionKey: Data,
        initializationVector: Data,
        additionalAuthenticatedData: Data
    ) throws -> ContentEncryptionContext {
        #if canImport(CryptoKit)
        let key = CryptoKit.SymmetricKey(data: encryptionKey)
        let nonce = try CryptoKit.AES.GCM.Nonce(data: initializationVector)

        let sealedBox = try CryptoKit.AES.GCM.seal(
            plaintext,
            using: key,
            nonce: nonce,
            authenticating: additionalAuthenticatedData
        )

        return ContentEncryptionContext(
            ciphertext: sealedBox.ciphertext,
            authenticationTag: sealedBox.tag,
            initializationVector: initializationVector
        )
        #elseif canImport(Crypto)
        let key = Crypto.SymmetricKey(data: encryptionKey)
        let nonce = try Crypto.AES.GCM.Nonce(data: initializationVector)

        let sealedBox = try Crypto.AES.GCM.seal(
            plaintext,
            using: key,
            nonce: nonce,
            authenticating: additionalAuthenticatedData
        )

        return ContentEncryptionContext(
            ciphertext: sealedBox.ciphertext,
            authenticationTag: sealedBox.tag,
            initializationVector: initializationVector
        )
        #else
        throw JOSESwiftError.encryptionFailed
        #endif
    }

    static func decrypt(
        cipherText: Data,
        decryptionKey: Data,
        initializationVector: Data,
        authenticationTag: Data,
        additionalAuthenticatedData: Data
    ) throws -> Data {
        #if canImport(CryptoKit)
        let key = CryptoKit.SymmetricKey(data: decryptionKey)
        let nonce = try CryptoKit.AES.GCM.Nonce(data: initializationVector)

        let sealedBox = try CryptoKit.AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: cipherText,
            tag: authenticationTag
        )

        return try CryptoKit.AES.GCM.open(
            sealedBox,
            using: key,
            authenticating: additionalAuthenticatedData
        )
        #elseif canImport(Crypto)
        let key = Crypto.SymmetricKey(data: decryptionKey)
        let nonce = try Crypto.AES.GCM.Nonce(data: initializationVector)

        let sealedBox = try Crypto.AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: cipherText,
            tag: authenticationTag
        )

        return try Crypto.AES.GCM.open(
            sealedBox,
            using: key,
            authenticating: additionalAuthenticatedData
        )
        #else
        throw JOSESwiftError.decryptionFailed
        #endif
    }
}
