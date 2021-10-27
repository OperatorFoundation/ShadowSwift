//
//  DarkStarCipher.swift
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

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS))
import CryptoKit
#else
import Crypto
#endif

import Datable

class DarkStarCipher
{
    // MARK: Cipher notes from https://github.com/shadowsocks/go-shadowsocks2/blob/master/shadowaead/cipher.go

    // AESGCM creates a new Cipher with a pre-shared key. len(psk) must be
    // one of 16, 24, or 32 to select AES-128/196/256-GCM.

    // Chacha20Poly1305 creates a new Cipher with a pre-shared key. len(psk)
    // must be 32.

    /**
     The first AEAD encrypt/decrypt operation uses a counting nonce starting from 0. After each encrypt/decrypt operation, the nonce is incremented by one as if it were an unsigned little-endian integer. Note that each TCP chunk involves two AEAD encrypt/decrypt operation: one for the payload length, and one for the payload. Therefore each chunk increases the nonce twice.
     */
    let log: Logger
    static let lengthSize = 2
    static let tagSize = 16
    static let maxPayloadSize = 16417
    static let overhead = Cipher.lengthSize + Cipher.tagSize + Cipher.tagSize
    static let maxRead = Cipher.maxPayloadSize + Cipher.overhead
    static let minRead = 1 + Cipher.overhead

    let key: SymmetricKey
    var encryptCounter: UInt64 = 0
    var encryptNonce: AES.GCM.Nonce?
    {
        DatableConfig.endianess = .little
        var counterData = self.encryptCounter.data

        // We have 8 bytes, nonce should be 12
        counterData.append(contentsOf: [0, 0, 0, 0])

        // We increment our counter every time nonce is used (encrypt/decrypt)
        self.encryptCounter += 1

        guard let nonce = try? AES.GCM.Nonce(data: counterData) else {return nil}
        return nonce
    }
    
    var decryptCounter: UInt64 = 0
    var decryptNonce: AES.GCM.Nonce?
    {
        DatableConfig.endianess = .little
        var counterData = self.decryptCounter.data

        // We have 8 bytes, nonce should be 12
        counterData.append(contentsOf: [0, 0, 0, 0])

        // We increment our counter every time nonce is used (encrypt/decrypt)
        self.decryptCounter += 1

        guard let nonce = try? AES.GCM.Nonce(data: counterData) else {return nil}
        return nonce
    }

    init?(key: SymmetricKey, logger: Logger)
    {
        self.key = key
        self.log = logger
    }

    /// [encrypted payload length][length tag][encrypted payload][payload tag]
    func pack(plaintext: Data) -> Data?
    {
        let payloadLength = UInt16(plaintext.count)
        DatableConfig.endianess = .big

        guard payloadLength <= Cipher.maxPayloadSize
        else
        {
            log.error("Requested payload size \(plaintext.count) is greater than the maximum allowed \(Cipher.maxPayloadSize). Unable to send payload.")
            return nil
        }

        guard let (encryptedPayloadLength, lengthTag) = encrypt(plaintext: payloadLength.data)
        else { return nil }
        guard let (encryptedPayload, payloadTag) = encrypt(plaintext: plaintext)
        else { return nil }

        return encryptedPayloadLength + lengthTag + encryptedPayload + payloadTag
    }

    /// Returns [encrypted][payload]
    private func encrypt(plaintext: Data) -> (cipherText: Data, tag: Data)?
    {
        var cipherText = Data()
        var tag = Data()

        do
        {
            guard let nonce = self.encryptNonce else {return nil}
            let sealedBox = try AES.GCM.seal(plaintext, using: self.key, nonce: nonce)
            cipherText = sealedBox.ciphertext
            tag = sealedBox.tag
            print("encrypt Key: \(DarkStar.symmetricKeyToData(key: self.key).hex)")
            print("encrypt nonce: \(Data(nonce).hex)")
            print("encrypt plaintext: \(plaintext.hex)")
            print("encrypt cipherText: \(cipherText.hex)")
            print("encrypt tag: \(tag.hex)")
        }
        catch let encryptError
        {
            log.error("Error running AESGCM encryption: \(encryptError)")
        }

        return (cipherText, tag)
    }

    func unpack(encrypted: Data, expectedCiphertextLength: Int) -> Data?
    {
        let ciphertext = encrypted[0..<expectedCiphertextLength]
        let tag = encrypted[expectedCiphertextLength...]

        // Quality Check
        guard tag.count == Cipher.tagSize
        else
        {
            log.error("Attempted to decrypt a message with an incorrect tag size. \nGot:  \(tag.count)\nExpected: \(Cipher.tagSize)")
            return nil
        }

        return decrypt(encrypted: ciphertext, tag: tag)
    }

    func decrypt(encrypted: Data, tag: Data) -> Data?
    {
        do
        {
            guard let nonce = self.decryptNonce else {return nil}
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: encrypted, tag: tag)
            return try AES.GCM.open(sealedBox, using: self.key)
        }
        catch let decryptError
        {
            log.error("Error running AESGCM decryption: \(decryptError)")
            return nil
        }
    }
}
