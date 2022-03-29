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

import Crypto
import Datable
import Net

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
    let serverIdentifier: Data
    let isServerConnection: Bool

    var encryptCounter: UInt64 = 0
    var encryptNonce: AES.GCM.Nonce?
    {
        var personalizationString = ""
        if isServerConnection
        {
            personalizationString = "client" // client is destination
        }
        else
        {
            personalizationString = "server" // server is destination
        }

        let result = nonce(counter: self.encryptCounter, personalizationString: personalizationString.data)

        let (newCounter, didOverflow) = self.encryptCounter.addingReportingOverflow(1)
        guard !didOverflow else {return nil}

        self.encryptCounter = newCounter

        return result
    }
    
    var decryptCounter: UInt64 = 0
    var decryptNonce: AES.GCM.Nonce?
    {
        var personalizationString = ""
        if isServerConnection
        {
            personalizationString = "server" // server is destination
        }
        else
        {
            personalizationString = "client" // client is destination
        }

        let result = nonce(counter: self.decryptCounter, personalizationString: personalizationString.data)

        let (newCounter, didOverflow) = self.encryptCounter.addingReportingOverflow(1)
        guard !didOverflow else {return nil}

        self.decryptCounter = newCounter

        return result
    }

    func nonce(counter: UInt64, personalizationString: Data) -> AES.GCM.Nonce?
    {
        // NIST Special Publication 800-38D - Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
        // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
        // Section 8.2.1 - Deterministic Construction
        // Applicable to nonces of 96 bytes or less.

        /*
         In the deterministic construction, the IV is the concatenation of two
         fields, called the fixed field and the invocation field. The fixed field
         shall identify the device, or, more generally, the context for the
         instance of the authenticated encryption function. The invocation field
         shall identify the sets of inputs to the authenticated encryption
         function in that particular device.

         For any given key, no two distinct devices shall share the same fixed
         field, and no two distinct sets of inputs to any single device shall
         share the same invocation field. Compliance with these two requirements
         implies compliance with the uniqueness requirement on IVs in Sec. 8.

         If desired, the fixed field itself may be constructed from two or more
         smaller fields. Moreover, one of those smaller fields could consist of
         bits that are arbitrary (i.e., not necessarily deterministic nor unique
         to the device), as long as the remaining bits ensure that the fixed
         field is not repeated in its entirety for some other device with the
         same key.

         Similarly, the entire fixed field may consist of arbitrary bits when
         there is only one context to identify, such as when a fresh key is
         limited to a single session of a communications protocol. In this case,
         if different participants in the session share a common fixed field,
         then the protocol shall ensure that the invocation fields are distinct
         for distinct data inputs.
        */

        let fixedField = Data(repeating: 0x1A, count: 4) // 4 bytes = 32 bits

        /*
         The invocation field typically is either 1) an integer counter or 2) a
         linear feedback shift register that is driven by a primitive polynomial
         to ensure a maximal cycle length. In either case, the invocation field
         increments upon each invocation of the authenticated encryption
         function.

         The lengths and positions of the fixed field and the invocation field
         shall be fixed for each supported IV length for the life of the key. In
         order to promote interoperability for the default IV length of 96 bits,
         this Recommendation suggests, but does not require, that the leading
         (i.e., leftmost) 32 bits of the IV hold the fixed field; and that the
         trailing (i.e., rightmost) 64 bits hold the invocation field.
        */

        guard let invocationField = self.encryptCounter.maybeNetworkData else {return nil}

        let nonceData = fixedField + invocationField

        guard let nonce = try? AES.GCM.Nonce(data: nonceData) else {return nil}
        return nonce
    }

    init?(key: SymmetricKey, endpoint: NWEndpoint, isServerConnection: Bool, logger: Logger)
    {
        self.key = key
        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return nil}
        self.serverIdentifier = serverIdentifier
        self.isServerConnection = isServerConnection
        self.log = logger
    }

    /// [encrypted payload length][length tag][encrypted payload][payload tag]
    func pack(plaintext: Data) -> Data?
    {
        // Check for integer overflow
        guard plaintext.count < UInt16.max else {return nil}
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
            guard let nonce = self.encryptNonce else
            {
                log.error("Failed to encrypt, nonce is nil.")
                return nil
            }
            
            let sealedBox = try AES.GCM.seal(plaintext, using: self.key, nonce: nonce)
            cipherText = sealedBox.ciphertext
            tag = sealedBox.tag
            
            print("Encrypting...")
            print("ciphertext: \(plaintext.hex)")
            print("Tag: \(tag.hex)")
            print("Nonce: \(Data(nonce))")
            print("Key: \(DarkStar.symmetricKeyToData(key: key))")
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
            guard let nonce = self.decryptNonce else
            {
                log.error("DarkStarCipher failed to decrypt the nonce.")
                return nil
            }
            
            print("Decrypting...")
            print("Encrypted data: \(encrypted.hex)")
            print("Tag: \(tag.hex)")
            print("Nonce: \(Data(nonce))")
            print("Key: \(DarkStar.symmetricKeyToData(key: key))")
            
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
