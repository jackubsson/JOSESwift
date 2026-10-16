//
//  HMAC.swift
//  JOSESwift
//
//  Created by Carol Capek on 05.12.17.
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
import Crypto
#endif

enum HMACError: Error {
    case algorithmNotSupported
    case inputMustBeGreaterThanZero
}

internal struct HMAC {
    typealias KeyType = Data

    static func calculate(
        from input: Data,
        with key: Data,
        using algorithm: HMACAlgorithm
    ) throws -> Data {
        guard !input.isEmpty else {
            throw HMACError.inputMustBeGreaterThanZero
        }

        #if canImport(CommonCrypto)
        let ccAlgorithm: CCHmacAlgorithm

        switch algorithm {
        case .SHA256:
            ccAlgorithm = CCHmacAlgorithm(kCCHmacAlgSHA256)
        case .SHA384:
            ccAlgorithm = CCHmacAlgorithm(kCCHmacAlgSHA384)
        case .SHA512:
            ccAlgorithm = CCHmacAlgorithm(kCCHmacAlgSHA512)
        }

        var result = Data(count: algorithm.outputLength)

        result.withUnsafeMutableBytes { resultBuffer in
            key.withUnsafeBytes { keyBuffer in
                input.withUnsafeBytes { inputBuffer in
                    CCHmac(
                        ccAlgorithm,
                        keyBuffer.baseAddress,
                        key.count,
                        inputBuffer.baseAddress,
                        input.count,
                        resultBuffer.baseAddress
                    )
                }
            }
        }

        return result
        #else
        let symmetricKey = Crypto.SymmetricKey(data: key)

        switch algorithm {
        case .SHA256:
            return Data(Crypto.HMAC<Crypto.SHA256>.authenticationCode(for: input, using: symmetricKey))
        case .SHA384:
            return Data(Crypto.HMAC<Crypto.SHA384>.authenticationCode(for: input, using: symmetricKey))
        case .SHA512:
            return Data(Crypto.HMAC<Crypto.SHA512>.authenticationCode(for: input, using: symmetricKey))
        }
        #endif
    }
}
