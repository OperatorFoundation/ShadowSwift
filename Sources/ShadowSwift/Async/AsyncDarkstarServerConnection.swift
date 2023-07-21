//
//  AsyncDarkstarServerConnection.swift
//  
//
//  Created by Dr. Brandon Wiley on 7/7/23.
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

import Crypto
import Foundation
import Logging

import Chord
import Datable
import Net
import TransmissionAsync

open class AsyncDarkstarServerConnection: AsyncChannelConnection<DarkstarServerChannel>
{
    public init(_ network: AsyncConnection, _ config: ShadowConfig.ShadowServerConfig, _ logger: Logger) async throws
    {
        let channel = try await DarkstarServerChannel(network, config, logger)

        super.init(channel, logger)
    }
}

public class DarkstarServerChannel: Channel
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

    public init(_ network: AsyncConnection, _ config: ShadowConfig.ShadowServerConfig, _ logger: Logger) async throws
    {
        self.network = network
        self.logger = logger

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

        // FIXME - move private key to keychain
        let server = try await AsyncDarkstarServer(serverPersistentPrivateKey: config.serverPrivateKey, host: host, port: port, connection: self.network, bloomFilter: DarkStarServerConnection.bloomFilter)

        let eCipher = try AsyncDarkstarCipher(key: server.serverToClientSharedKey, host: host, port: port, isServerConnection: true, logger: self.logger)
        let dCipher = try AsyncDarkstarCipher(key: server.clientToServerSharedKey, host: host, port: port, isServerConnection: true, logger: self.logger)

        self.encryptingCipher = eCipher
        self.decryptingCipher = dCipher
    }

    public func close() async throws
    {
        try await self.network.close()
    }
}
