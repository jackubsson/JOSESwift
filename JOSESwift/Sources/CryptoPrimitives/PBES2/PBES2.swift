//
//  PBES2.swift
//  JOSESwift
//
//  Created by Tobias Hagemann on 07.12.23.
//
//  ---------------------------------------------------------------------------
//  Copyright 2024 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import Foundation

#if canImport(CommonCrypto)
import CommonCrypto
#else
import CryptoSwift
#endif

internal enum PBES2Error: Error {
    case unknownOrUnsupportedAlgorithm
}

internal struct PBES2 {
    static func deriveWrappingKey(
        password: String,
        algorithm: KeyManagementAlgorithm,
        saltInput: Data,
        iterationCount: Int
    ) throws -> Data {
        let supportedAlgorithms: [KeyManagementAlgorithm] = [
            .PBES2_HS256_A128KW,
            .PBES2_HS384_A192KW,
            .PBES2_HS512_A256KW
        ]

        guard
            supportedAlgorithms.contains(algorithm),
            iterationCount > 0,
            let passwordData = password.data(using: .utf8),
            let algorithmData = algorithm.rawValue.data(using: .utf8),
            let derivedKeyLength = algorithm.derivedKeyLength
        else {
            throw PBES2Error.unknownOrUnsupportedAlgorithm
        }

        let saltData = algorithmData + Data([0x00]) + saltInput

        #if canImport(CommonCrypto)
        guard let hmacAlgorithm = algorithm.hmacAlgorithm else {
            throw HMACError.algorithmNotSupported
        }

        var derivedKey = Data(count: derivedKeyLength)

        let status = derivedKey.withUnsafeMutableBytes { derivedKeyBuffer in
            saltData.withUnsafeBytes { saltBuffer in
                passwordData.withUnsafeBytes { passwordBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.baseAddress,
                        passwordData.count,
                        saltBuffer.baseAddress,
                        saltData.count,
                        hmacAlgorithm.ccPseudoRandomAlgorithm,
                        UInt32(iterationCount),
                        derivedKeyBuffer.bindMemory(to: UInt8.self).baseAddress,
                        derivedKeyLength
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw NSError(
                domain: NSOSStatusErrorDomain,
                code: Int(status),
                userInfo: nil
            )
        }

        return derivedKey
        #else
        let variant: CryptoSwift.HMAC.Variant

        switch algorithm {
        case .PBES2_HS256_A128KW:
            variant = .sha2(.sha256)
        case .PBES2_HS384_A192KW:
            variant = .sha2(.sha384)
        case .PBES2_HS512_A256KW:
            variant = .sha2(.sha512)
        default:
            throw PBES2Error.unknownOrUnsupportedAlgorithm
        }

        let pbkdf2 = try PKCS5.PBKDF2(
            password: Array(passwordData),
            salt: Array(saltData),
            iterations: iterationCount,
            keyLength: derivedKeyLength,
            variant: variant
        )

        return Data(try pbkdf2.calculate())
        #endif
    }
}

#if canImport(CommonCrypto)
private extension HMACAlgorithm {
    var ccPseudoRandomAlgorithm: CCPseudoRandomAlgorithm {
        switch self {
        case .SHA256:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
        case .SHA384:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
        case .SHA512:
            return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        }
    }
}
#endif
