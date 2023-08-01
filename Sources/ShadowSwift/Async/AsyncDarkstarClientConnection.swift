//
//  AsyncDarkstarClientConnection.swift
//  MIT License
//
//  Copyright (c) 2023 Operator Foundation
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

import Crypto
import Foundation
import Logging

import Chord
import Datable
import Net
import Transmission
import TransmissionAsync
import Transport

open class AsyncDarkstarClientConnection: AsyncChannelConnection<DarkstarClientChannel>
{
    public convenience init(_ host: String, _ port: Int, _ config: ShadowConfig.ShadowClientConfig, _ logger: Logger) async throws
    {
        let network = try await AsyncTcpSocketConnection(host, port, logger)

        try await self.init(network, config, logger)
    }

    public init(_ network: AsyncConnection, _ config: ShadowConfig.ShadowClientConfig, _ logger: Logger) async throws
    {
        let channel = try await DarkstarClientChannel(network, config, logger)

        super.init(channel, logger)
    }
}

public class DarkstarClientChannel: Channel
{
    public typealias R = DarkstarReadable
    public typealias W = DarkstarWritable

    public var readable: DarkstarReadable
    {
        return DarkstarReadable(self.network, self.decryptingCipher)
    }

    public var writable: DarkstarWritable
    {
        return DarkstarWritable(self.network, self.encryptingCipher)
    }

    let encryptingCipher: AsyncDarkstarCipher
    var decryptingCipher: AsyncDarkstarCipher
    let logger: Logger
    let network: AsyncConnection

    public init(_ network: AsyncConnection, _ config: ShadowConfig.ShadowClientConfig, _ logger: Logger) async throws
    {
        self.network = network
        self.logger = logger

        #if os(macOS)
        // Only support Apple devices with secure enclave.
        guard SecureEnclave.isAvailable else
        {
            throw AsyncDarkstarClientConnectionError.keychainUnavailable
        }
        #endif

        guard config.mode == .DARKSTAR else
        {
            self.logger.error("\nDarkStarClientConnection - Attempted a connection with \(config.mode.rawValue), Currently DarkStar is the only supported shadow mode.")
            throw AsyncDarkstarClientConnectionError.badEncryptionMode
        }

        let parts = config.serverAddress.split(separator: ":")
        guard parts.count == 2 else
        {
            throw AsyncDarkstarClientConnectionError.badServerAddress(config.serverAddress)
        }
        let host = String(parts[0])
        guard let port = Int(String(parts[1])) else
        {
            throw AsyncDarkstarClientConnectionError.badServerAddress(config.serverAddress)
        }

        let client = try await AsyncDarkstarClient(serverPersistentPublicKey: config.serverPublicKey, host: host, port: port, connection: self.network)

        let eCipher = try AsyncDarkstarCipher(key: client.clientToServerSharedKey, host: host, port: port, isServerConnection: false, logger: self.logger)
        let dCipher = try AsyncDarkstarCipher(key: client.serverToClientSharedKey, host: host, port: port, isServerConnection: false, logger: self.logger)

        self.encryptingCipher = eCipher
        self.decryptingCipher = dCipher
    }

    public func close() async throws
    {
        try await self.network.close()
    }
}

public class DarkstarReadable: Readable
{
    let network: AsyncConnection
    let cipher: AsyncDarkstarCipher

    public init(_ network: AsyncConnection, _ cipher: AsyncDarkstarCipher)
    {
        self.network = network
        self.cipher = cipher
    }

    public func read() async throws -> Data
    {
        return try await self.read(1024)
    }

    public func read(_ size: Int) async throws -> Data
    {
        // Get our encrypted length first
        let encryptedLengthSize = Cipher.lengthSize + Cipher.tagSize
        let someData = try await self.network.readSize(encryptedLengthSize)

        guard someData.count == encryptedLengthSize else
        {
            throw AsyncDarkstarClientConnectionError.wrongSize(someData.count, encryptedLengthSize)
        }

        guard let lengthData = self.cipher.unpack(encrypted: someData, expectedCiphertextLength: Cipher.lengthSize) else
        {
            throw AsyncDarkstarClientConnectionError.decryptionFailure
        }

        guard let lengthUInt16 = lengthData.maybeNetworkUint16 else
        {
            throw AsyncDarkstarClientConnectionError.numberDecodeFailure
        }

        // Read data of payloadLength + tagSize
        let payloadLength = Int(lengthUInt16)
        let expectedLength = payloadLength + Cipher.tagSize
        let nextData = try await self.network.readSize(expectedLength)

        // Attempt to decrypt the data we received before passing it along
        guard let decrypted = self.cipher.unpack(encrypted: nextData, expectedCiphertextLength: payloadLength) else
        {
            throw AsyncDarkstarClientConnectionError.decryptionFailure
        }

        return decrypted
    }
}

public class DarkstarWritable: Writable
{
    let network: AsyncConnection
    let cipher: AsyncDarkstarCipher

    public init(_ network: AsyncConnection, _ cipher: AsyncDarkstarCipher)
    {
        self.network = network
        self.cipher = cipher
    }

    /// Gets content and encrypts it before passing it along to the network
    public func write(_ data: Data) async throws
    {
        guard let encrypted = self.cipher.pack(plaintext: data) else
        {
            throw AsyncDarkstarClientConnectionError.encryptionFailure
        }

        try await self.network.write(encrypted)
    }

    // End of Connection Protocol

    func sendAddress() async throws
    {
        let address = AddressReader().createAddr()
        guard let encryptedAddress = self.cipher.pack(plaintext: address) else
        {
            throw AsyncDarkstarClientConnectionError.sendAddressFailed
        }

        try await network.write(encryptedAddress)
    }
}

public enum AsyncDarkstarClientConnectionError: Error
{
    case keychainUnavailable
    case badEncryptionMode
    case wrongKeyType
    case encryptionFailure
    case wrongSize(Int, Int) // actual, expected
    case decryptionFailure
    case numberDecodeFailure
    case sendAddressFailed
    case badServerAddress(String)
}
