//
//  SHA256.swift
//  JOSESwift
//
//  Created by Thomas Torp on 08.06.20.
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

enum ThumbprintError: Error {
    case inputMustBeGreaterThanZero
}

internal struct Thumbprint {
    static func calculate(
        from input: Data,
        algorithm: JWKThumbprintAlgorithm
    ) throws -> String {
        guard !input.isEmpty else {
            throw ThumbprintError.inputMustBeGreaterThanZero
        }

        switch algorithm {
        case .SHA256:
            #if canImport(CommonCrypto)
            var digest = Data(count: Int(CC_SHA256_DIGEST_LENGTH))

            digest.withUnsafeMutableBytes { digestBuffer in
                input.withUnsafeBytes { inputBuffer in
                    _ = CC_SHA256(
                        inputBuffer.baseAddress,
                        CC_LONG(input.count),
                        digestBuffer.bindMemory(to: UInt8.self).baseAddress
                    )
                }
            }

            return digest.base64URLEncodedString()
            #else
            return Data(SHA256.hash(data: input)).base64URLEncodedString()
            #endif
        }
    }
}
