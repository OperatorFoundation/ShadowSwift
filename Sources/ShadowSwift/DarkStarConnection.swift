//
//  ShadowConnection.swift
//  Shadow
//
//  Created by Mafalda on 8/3/20.
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

import Chord
import Datable
import Transport
import SwiftHexTools
import Crypto
import Net
import Transmission

open class DarkStarConnection: Transport.Connection
{
    public var stateUpdateHandler: ((NWConnection.State) -> Void)?
    public var viabilityUpdateHandler: ((Bool) -> Void)?
    public var log: Logger

    let networkQueue = DispatchQueue(label: "ShadowNetworkQueue")
    let encryptingCipher: DarkStarCipher
    var decryptingCipher: DarkStarCipher
    var network: Transmission.Connection

    public convenience init?(host: NWEndpoint.Host, port: NWEndpoint.Port, parameters: NWParameters, config: ShadowConfig, isClient: Bool, logger: Logger)
    {
        
        #if os(macOS)
        // Only support Apple devices with secure enclave.
        guard SecureEnclave.isAvailable else {return nil}
        #endif

        var maybeHostString: String? = nil
        switch host
        {
            case .ipv4(let ipv4):
                let data = ipv4.rawValue
                maybeHostString = "\(data[0]).\(data[1]).\(data[2]).\(data[3])"
            default:
                maybeHostString = nil
        }
        guard let hostString = maybeHostString else {return nil}

        let endpoint = NWEndpoint.hostPort(host: host, port: port)
        guard let newConnection = Transmission.TransmissionConnection(host: hostString, port: Int(port.rawValue))
        else
        {
            logger.error("Failed to initialize a ShadowConnection because we could not create a Network Connection using host \(host) and port \(Int(port.rawValue)).")
            return nil
        }

        self.init(connection: newConnection, endpoint: endpoint, parameters: parameters, config: config, isClient: isClient, logger: logger)
    }

    public init?(connection: Transmission.Connection, endpoint: NWEndpoint, parameters: NWParameters, config: ShadowConfig, isClient: Bool, logger: Logger)
    {
        self.log = logger

        guard config.mode == .DARKSTAR else
        {
            log.error("Attempted a connection with \(config.mode.rawValue), Currently DarkStar is the only supported shadow mode.")
            return nil
            
        }
        
        if isClient
        {
            guard let serverPersistentPublicKeyData = Data(hex: config.password) else {return nil}
            guard let serverPersistentPublicKey = try? P256.KeyAgreement.PublicKey(compactRepresentation: serverPersistentPublicKeyData) else {return nil}

            guard let client = DarkStarClient(serverPersistentPublicKey: serverPersistentPublicKey, endpoint: endpoint, connection: connection) else {return nil}

            guard let eCipher = DarkStarCipher(key: client.clientToServerSharedKey, endpoint: endpoint, isServerConnection: false, logger: self.log) else {return nil}
            guard let dCipher = DarkStarCipher(key: client.serverToClientSharedKey, endpoint: endpoint, isServerConnection: false, logger: self.log) else {return nil}

            self.encryptingCipher = eCipher
            self.decryptingCipher = dCipher
            self.network = connection
        }
        else
        {
            guard let serverPersistentPrivateKeyData = Data(hex: config.password) else {return nil}
            guard let serverPersistentPrivateKey = try? P256.KeyAgreement.PrivateKey(rawRepresentation: serverPersistentPrivateKeyData) else {return nil}

            guard let server = DarkStarServer(serverPersistentPrivateKey: serverPersistentPrivateKey, endpoint: endpoint, connection: connection) else {return nil}

            guard let eCipher = DarkStarCipher(key: server.serverToClientSharedKey, endpoint: endpoint, isServerConnection: true, logger: logger) else {return nil}
            guard let dCipher = DarkStarCipher(key: server.clientToServerSharedKey, endpoint: endpoint, isServerConnection: true, logger: logger) else {return nil}

            self.encryptingCipher = eCipher
            self.decryptingCipher = dCipher
            self.network = connection
            self.log = logger
        }

        if let actualStateUpdateHandler = self.stateUpdateHandler
        {
            actualStateUpdateHandler(.ready)
        }

        if let actualViabilityUpdateHandler = self.viabilityUpdateHandler
        {
            actualViabilityUpdateHandler(true)
        }
    }

    // MARK: Connection Protocol

    public func start(queue: DispatchQueue)
    {
        guard let updateHandler = stateUpdateHandler
        else
        {
            log.info("Called start when there is no stateUpdateHandler.")
            return
        }

        updateHandler(.ready)
    }

    public func cancel()
    {
        // FIXME: Need to add Connection.close() to Transmission library
        // network.close()

        if let stateUpdate = self.stateUpdateHandler
        {
            stateUpdate(NWConnection.State.cancelled)
        }

        if let viabilityUpdate = self.viabilityUpdateHandler
        {
            viabilityUpdate(false)
        }
    }

    /// Gets content and encrypts it before passing it along to the network
    public func send(content: Data?, contentContext: NWConnection.ContentContext, isComplete: Bool, completion: NWConnection.SendCompletion)
    {
        guard let someData = content
        else
        {
            log.debug("Shadow connection received a send command with no content.")
            switch completion
            {
                case .contentProcessed(let handler):
                    handler(nil)
                    return
                default:
                    return
            }
        }

        guard let encrypted = encryptingCipher.pack(plaintext: someData)
        else
        {
            log.error("Failed to encrypt shadow send content.")
            return
        }

        let written = network.write(data: encrypted)

        switch completion
        {
            case .contentProcessed(let handler):
                if written { handler(nil) }
                else { handler(NWError.posix(.EIO)) }
                return
            default:
                return
        }
    }

    // Decrypts the received content before passing it along
    public func receive(completion: @escaping (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)
    {
        self.receive(minimumIncompleteLength: 1, maximumLength: Cipher.maxPayloadSize, completion: completion)
    }


    // TODO: Introduce buffer to honor the requested read size from the application
    // Decrypts the received content before passing it along
    public func receive(minimumIncompleteLength: Int,
                        maximumLength: Int,
                        completion: @escaping (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)
    {
        // Get our encrypted length first
        let encryptedLengthSize = Cipher.lengthSize + Cipher.tagSize
        let maybeData = network.read(size: encryptedLengthSize)

        // Nothing to decrypt
        guard let someData = maybeData
        else
        {
            self.log.debug("Shadow receive called, but there was no data.")
            completion(nil, .defaultMessage, false, NWError.posix(.ENODATA))
            return
        }

        guard let lengthData = self.decryptingCipher.unpack(encrypted: someData, expectedCiphertextLength: Cipher.lengthSize)
        else
        {
            completion(maybeData, .defaultMessage, false, NWError.posix(POSIXErrorCode.EINVAL))
            return
        }

        DatableConfig.endianess = .big

        guard let lengthUInt16 = lengthData.uint16
        else
        {
            self.log.error("Failed to get encrypted data's expected length. Length data could not be converted to UInt16")
            completion(maybeData, .defaultMessage, false, NWError.posix(POSIXErrorCode.EINVAL))
            return
        }

        // Read data of payloadLength + tagSize
        let payloadLength = Int(lengthUInt16)
        let expectedLength = payloadLength + Cipher.tagSize
        let nextMaybeData = network.read(size: expectedLength)

        self.shadowReceive(payloadLength: payloadLength, maybeData: nextMaybeData, maybeContext: .defaultMessage, connectionComplete: false, maybeError: nil, completion: completion)
    }

    func shadowReceive(payloadLength: Int,
                       maybeData: Data?,
                       maybeContext: NWConnection.ContentContext?,
                       connectionComplete: Bool,
                       maybeError: NWError?,
                       completion: @escaping (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)
    {
        // Something went wrong
        if let error = maybeError
        {
            self.log.error("Shadow receive called, but we got an error: \(error)")
            completion(maybeData, maybeContext, connectionComplete, error)
            return
        }

        // Nothing to decrypt
        guard let someData = maybeData
        else
        {
            self.log.debug("Shadow receive called, but there was no data.")
            completion(nil, maybeContext, connectionComplete, maybeError)
            return
        }

        let dCipher = self.decryptingCipher

        // Attempt tp decrypt the data we received before passing it along
        guard let decrypted = dCipher.unpack(encrypted: someData, expectedCiphertextLength: payloadLength)
        else
        {
            self.log.error("Shadow failed to decrypt received data.")
            completion(someData, maybeContext, connectionComplete, NWError.posix(POSIXErrorCode.EBADMSG))
            return
        }

        completion(decrypted, maybeContext, connectionComplete, maybeError)
    }

    // End of Connection Protocol

    func sendAddress()
    {
        let address = AddressReader().createAddr()
        guard let encryptedAddress = encryptingCipher.pack(plaintext: address)
        else
        {
            self.log.error("Failed to encrypt our address. Cancelling connection.")

            // FIXME: Add Connection.close() to the Transmission library
            // self.network.cancel()

            if let actualStateUpdateHandler = self.stateUpdateHandler
            {
                actualStateUpdateHandler(.cancelled)
            }

            if let actualViabilityUpdateHandler = self.viabilityUpdateHandler
            {
                actualViabilityUpdateHandler(false)
            }

            return
        }

        let written = network.write(data: encryptedAddress)
        if written
        {
            if let actualStateUpdateHandler = self.stateUpdateHandler
            {
                actualStateUpdateHandler(.ready)
            }

            if let actualViabilityUpdateHandler = self.viabilityUpdateHandler
            {
                actualViabilityUpdateHandler(true)
            }
        }
        else
        {
            // FIXME: Add Connection.close() to the Transmission library
            // self.network.cancel()

            if let actualStateUpdateHandler = self.stateUpdateHandler
            {
                actualStateUpdateHandler(.cancelled)
            }

            if let actualViabilityUpdateHandler = self.viabilityUpdateHandler
            {
                actualViabilityUpdateHandler(false)
            }
        }
    }
}
