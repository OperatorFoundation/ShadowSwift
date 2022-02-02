//
//  Cipher.swift
//  Shadow
//
//  Created by Mafalda on 8/17/20.
//  MIT License
//
//  Copyright (c) 2020 Operator Foundation
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import Foundation
import Logging
import Crypto
import Datable
import SwiftHexTools

class Cipher
{
    static let lengthSize = 2
    static let tagSize = 16
    static let maxPayloadSize = 16417
    static let overhead = Cipher.lengthSize + Cipher.tagSize + Cipher.tagSize
    static let maxRead = Cipher.maxPayloadSize + Cipher.overhead
    static let minRead = 1 + Cipher.overhead

    static func generateRandomBytes(count: Int) -> Data
    {
        var bytes = [UInt8]()
        for _ in 1...count
        {
            bytes.append(UInt8.random(in: 0...255))
        }
        
        return Data(bytes)
    }
}

public enum CipherMode: String, Codable
{
    // Old cipher modes were removed due to lack of security

    // New cipher modes
    case DARKSTAR = "DarkStar"
}

