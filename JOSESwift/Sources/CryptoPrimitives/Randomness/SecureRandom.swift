//
//  SecureRandom.swift
//  JOSESwift
//
//  Created by Carol Capek on 07.12.17.
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

#if canImport(Security)
import Security
#endif

public enum SecureRandomError: Error {
    #if canImport(Security)
    case failed(status: OSStatus)
    #endif
    case countMustBeGreaterThanZero
}

public struct SecureRandom {
    /// Generates cryptographically secure random data with the requested size.
    ///
    /// - Parameter count: Number of random bytes to generate. Must be greater
    ///   than zero.
    /// - Returns: Cryptographically secure random bytes.
    /// - Throws: `SecureRandomError.countMustBeGreaterThanZero` when `count`
    ///   is zero or negative; on Apple platforms it may also throw
    ///   `SecureRandomError.failed(status:)`.
    public static func generate(count: Int) throws -> Data {
        guard count > 0 else {
            throw SecureRandomError.countMustBeGreaterThanZero
        }

        #if canImport(Security)
        var generatedRandom = Data(count: count)

        let status = generatedRandom.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }

        guard status == errSecSuccess else {
            throw SecureRandomError.failed(status: status)
        }

        return generatedRandom
        #else
        var generator = SystemRandomNumberGenerator()
        var generatedRandom = Data(count: count)

        generatedRandom.withUnsafeMutableBytes { buffer in
            let bytes = buffer.bindMemory(to: UInt8.self)

            for index in bytes.indices {
                bytes[index] = UInt8.random(
                    in: UInt8.min...UInt8.max,
                    using: &generator
                )
            }
        }

        return generatedRandom
        #endif
    }
}
