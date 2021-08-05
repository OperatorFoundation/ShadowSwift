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

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS))
import CryptoKit
#else
import Crypto
#endif

import Datable

class Cipher
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
    
    var counter: UInt64 = 0
    var mode: CipherMode
    var key: SymmetricKey
    
    init?(config: ShadowConfig, salt: Data, logger: Logger)
    {
        let presharedKey = Cipher.kdf(shadowConfig: config)
        
        guard let actualKey = Cipher.hkdfSHA1(secret: presharedKey, salt: salt, cipherMode: config.mode)
        else
        {
            logger.error("Failed to gernerate a symmetric key with the provided config.")
            return nil
        }
             
        self.log = logger
        self.key = SymmetricKey(data: actualKey)
        self.mode = config.mode
    }
    
    static func createSalt(mode: CipherMode) -> Data?
    {
        // Salt size shoud be 16 bytes for aes128
        let saltSize: Int
        
        switch mode
        {
        case .AES_128_GCM:
            saltSize = 16
        case .AES_256_GCM:
            saltSize = 32
        case .CHACHA20_IETF_POLY1305:
            saltSize = 32
        }
        
        return generateRandomBytes(count: saltSize)
    }
    
    /*
     var b, prev []byte
     h := md5.New()
     for len(b) < keyLen {
         h.Write(prev)
         h.Write([]byte(password))
         b = h.Sum(b)
         prev = b[len(b)-h.Size():]
         h.Reset()
     }
     return b[:keyLen]
     */
    static func kdf(shadowConfig: ShadowConfig) -> Data
    {
        var keyLength: Int
        var md5Hash = Insecure.MD5()
        var keyBuffer = Data()
        var previous = Data()
        
        switch shadowConfig.mode
        {
        case .AES_128_GCM:
            keyLength = 16
        case .AES_256_GCM:
            keyLength = 32
        case .CHACHA20_IETF_POLY1305:
            keyLength = 32
        }
        
        while keyBuffer.count < keyLength
        {
            md5Hash.update(data: previous)
            md5Hash.update(data: shadowConfig.password.data)
            keyBuffer += Data(md5Hash.finalize())
            previous = keyBuffer[(keyBuffer.count - Insecure.MD5.byteCount)...]
            
            md5Hash = Insecure.MD5()
        }
        
        return keyBuffer[..<keyLength]
    }
    
    static func hkdfSHA1(secret: Data, salt: Data, cipherMode: CipherMode) -> Data?
    {
        print("HKDFSHA1")
        print("\nsecret")
        print(secret.array)
        print("\nsalt")
        print(salt.array)
        let info = Data(string: "ss-subkey")
        let outputSize = secret.count
        
        let iterations = UInt8(ceil(Double(outputSize) / Double(Insecure.SHA1.byteCount)))
        guard iterations <= 255
        else
        {
            print("Key derviation failure: Too many iterations - \(iterations)")
            return nil
        }
        
        let prk = HMAC<Insecure.SHA1>.authenticationCode(for: secret, using: SymmetricKey(data: salt))
        let key = SymmetricKey(data: prk)
        var hkdf = Data()
        var value = Data()
        
        for i in 1...iterations
        {
            value.append(info)
            value.append(i)
            
            let code = HMAC<Insecure.SHA1>.authenticationCode(for: value, using: key)
            hkdf.append(contentsOf: code)
            
            value = Data(code)
        }

        return hkdf.prefix(outputSize)
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
        
        switch mode
        {
        case .AES_128_GCM:
            do
            {
                let aesGCMNonce = try AES.GCM.Nonce(data: nonce())
                let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: aesGCMNonce)
                cipherText = sealedBox.ciphertext
                tag = sealedBox.tag
            }
            catch let encryptError
            {
                print("Error running AESGCM encryption: \(encryptError)")
            }
            
        case .AES_256_GCM:
            do
            {
                let aesGCMNonce = try AES.GCM.Nonce(data: nonce())
                let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: aesGCMNonce)
                cipherText = sealedBox.ciphertext
                tag = sealedBox.tag
            }
            catch let encryptError
            {
                print("Error running AESGCM encryption: \(encryptError)")
            }
            
        case .CHACHA20_IETF_POLY1305:
            do
            {
                let chachaPolyNonce = try ChaChaPoly.Nonce(data: nonce())
                let sealedBox = try ChaChaPoly.seal(plaintext, using: key, nonce: chachaPolyNonce)
                cipherText = sealedBox.ciphertext
                tag = sealedBox.tag
            }
            catch let encryptError
            {
                print("Error running ChaChaPoly encryption: \(encryptError)")
            }
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
        switch mode
        {
        case .AES_128_GCM:
            do
            {
                let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce()), ciphertext: encrypted, tag: tag)
                return try AES.GCM.open(sealedBox, using: key)
            }
            catch let decryptError
            {
                print("Error running AESGCM decryption: \(decryptError)")
                return nil
            }
        case .AES_256_GCM:
            do
            {
                let sealedBox = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce()), ciphertext: encrypted, tag: tag)
                return try AES.GCM.open(sealedBox, using: key)
            }
            catch let decryptError
            {
                print("Error running AESGCM decryption: \(decryptError)")
                return nil
            }
        case .CHACHA20_IETF_POLY1305:
            do
            {
                let sealedBox = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce()), ciphertext: encrypted, tag: tag)
                return try ChaChaPoly.open(sealedBox, using: key)
            }
            catch let decryptError
            {
                print("Error running ChaChaPoly decryption: \(decryptError)")
                return nil
            }
        }
    }
    
    func nonce() -> Data
    {
        DatableConfig.endianess = .little
        var counterData = counter.data
        
        // We have 8 bytes, nonce should be 12
        counterData.append(contentsOf: [0, 0, 0, 0])
        print("Nonce counter data size: \(counterData.count)")
        print("Nonce counter data: \(counterData[0]), \(counterData[11])")
        
        // We increment our counter every time nonce is used (encrypt/decrypt)
        counter += 1

        return counterData
    }
    
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
    // AES 196 is not currently supported by go-shadowsocks2.
    // We are not supporting it at this time either.
    case AES_128_GCM = "AES-128-GCM"
    case AES_256_GCM = "AES-256-GCM"
    case CHACHA20_IETF_POLY1305 = "CHACHA20-IETF-POLY1305"
}

