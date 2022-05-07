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

import Crypto
import Foundation
import Logging

import Chord
import Datable
import Net
import SwiftHexTools
import Transmission
import Transport

open class DarkStarServerConnection: Transport.Connection
{
    public var stateUpdateHandler: ((NWConnection.State) -> Void)?
    public var viabilityUpdateHandler: ((Bool) -> Void)?
    public var log: Logger

    let networkQueue = DispatchQueue(label: "ShadowNetworkQueue")
    let encryptingCipher: DarkStarCipher
    var decryptingCipher: DarkStarCipher
    var network: Transmission.Connection
    var bloomFilter: BloomFilter<Data>

    public convenience init?(host: NWEndpoint.Host, port: NWEndpoint.Port, parameters: NWParameters, config: ShadowConfig, bloomFilter: BloomFilter<Data>, logger: Logger)
    {
        #if os(macOS)
        // Only support Apple devices with secure enclave.
        guard SecureEnclave.isAvailable else
        {
            return nil
        }
        #endif
        
        var maybeHostString: String? = nil
        switch host
        {
            case .ipv4(let ipv4):
                let data = ipv4.rawValue
                maybeHostString = "\(data[0]).\(data[1]).\(data[2]).\(data[3])"
            default:
                maybeHostString = nil
                logger.error("ShadowSwift: DarkStarServerConnection init failed. Host must be IPV4")
        }
        
        guard let hostString = maybeHostString else
        {
            logger.error("ShadowSwift: DarkStarServerConnection init failed. Unable to resolve the host string.")
            return nil
        }

        let endpoint = NWEndpoint.hostPort(host: host, port: port)
        guard let newConnection = Transmission.TransmissionConnection(host: hostString, port: Int(port.rawValue)) else
        {
            logger.error("ShadowSwift: DarkStarServerConnection init failed. Failed to create a network connection using host \(host) and port \(Int(port.rawValue)).")
            return nil
        }
        
        self.init(connection: newConnection, endpoint: endpoint, parameters: parameters, config: config, bloomFilter: bloomFilter, logger: logger)
    }

    public init?(connection: Transmission.Connection, endpoint: NWEndpoint, parameters: NWParameters, config: ShadowConfig, bloomFilter: BloomFilter<Data>, logger: Logger)
    {
        self.bloomFilter = bloomFilter
        self.log = logger

        guard config.mode == .DARKSTAR else
        {
            log.error("ShadowSwift: DarkStarServerConnection init failed. Tried using \(config.mode.rawValue) cipher mode, Currently DarkStar is the only supported shadow mode.")
            return nil
        }
        
        guard let serverPersistentPrivateKeyData = Data(hex: config.password) else
        {
            logger.error("ShadowSwift: DarkStarServerConnection init failed. Unable to parse the config password.")
            return nil
        }
        
        guard let serverPersistentPrivateKey = try? P256.KeyAgreement.PrivateKey(rawRepresentation: serverPersistentPrivateKeyData) else
        {
            logger.error("ShadowSwift: DarkStarServerConnection init failed. Failed to generate a key from data.")
            return nil
        }

        guard let server = DarkStarServer(serverPersistentPrivateKey: serverPersistentPrivateKey, endpoint: endpoint, connection: connection, bloomFilter: bloomFilter) else
        {
            logger.error("ShadowSwift: DarkStarServerConnection init failed. The DarkStar handshake was unsuccessful.")
            return nil
        }

        guard let eCipher = DarkStarCipher(key: server.serverToClientSharedKey, endpoint: endpoint, isServerConnection: true, logger: logger) else
        {
            logger.error("ShadowSwift: DarkStarServerConnection init failed. Unable to create the encryption cipher.")
            return nil
        }
        
        guard let dCipher = DarkStarCipher(key: server.clientToServerSharedKey, endpoint: endpoint, isServerConnection: true, logger: logger) else
        {
            logger.error("ShadowSwift: DarkStarServerConnection init failed. unable to create the decryption cipher.")
            return nil
        }

        self.encryptingCipher = eCipher
        self.decryptingCipher = dCipher
        self.network = connection
        self.log = logger

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
        guard let updateHandler = stateUpdateHandler else
        {
            log.info("ShadowSwift: DarkStarServerConnection called start when there is no stateUpdateHandler.")
            return
        }

        updateHandler(.ready)
    }

    public func cancel()
    {
        log.info("ShadowSwift: DarkStarServerConnection received a cancel request, closing the connection.")
        
         network.close()

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
        guard let someData = content else
        {
            log.debug("ShadowSwift: DarkStarServerConnection received a send command with nil content.")
            
            if isComplete // We're done, close the connection
            {
                network.close()
            }
            
            switch completion
            {
                case .contentProcessed(let handler):
                    handler(nil)
                    return
                default:
                    return
            }
        }
        
        guard someData.count > 0 else
        {
            log.error("ShadowSwift: DarkStarServerConnection received a send command with no content.")
            
            switch completion
            {
                case .contentProcessed(let handler):
                    handler(NWError.posix(.ENODATA))
                    return
                default:
                    return
            }
        }

        guard let encrypted = encryptingCipher.pack(plaintext: someData) else
        {
            log.error("ShadowSwift: Failed to encrypt DarkStarServerConnection send content.")
            switch completion
            {
                case .contentProcessed(let handler):
                    handler(NWError.posix(.EBADMSG))
                    return
                default:
                    return
            }
        }

        let written = network.write(data: encrypted)

        switch completion
        {
            case .contentProcessed(let handler):
                if written
                { handler(nil) }
                else
                { handler(NWError.posix(.EIO)) }
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
        guard let someData = maybeData else
        {
            log.error("ShadowSwift: network.read returned nil.")
            completion(nil, .defaultMessage, false, NWError.posix(.ENODATA))
            return
        }
        
        guard let lengthData = self.decryptingCipher.unpack(encrypted: someData, expectedCiphertextLength: Cipher.lengthSize) else
        {
            log.error("ShadowSwift: decryption failure 🕳.")
            let _ = BlackHole(timeoutDelaySeconds: 30, socket: self)
            completion(maybeData, .defaultMessage, false, NWError.posix(POSIXErrorCode.EINVAL))
            return
        }

        DatableConfig.endianess = .big

        guard let lengthUInt16 = lengthData.uint16 else
        {
            log.error("ShadowSwift: Failed to get encrypted data's expected length. Length data could not be converted to UInt16")
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
        if let error = maybeError
        {
            log.error("ShadowSwift: shadowReceive error - \(error).")
            completion(maybeData, maybeContext, connectionComplete, error)
            return
        }

        // Nothing to decrypt
        guard let someData = maybeData else
        {
            log.debug("ShadowSwift: shadowReceive called with nil data.")
            
            if connectionComplete
            {
                network.close()
                completion(nil, maybeContext, connectionComplete, nil)
                return
            }
            else // This should never happen
            {
                self.log.error("ShadowSwift: We did not received any data but the connection is not complete.")
                completion(nil, maybeContext, connectionComplete, NWError.posix(.ENODATA))
                return
            }
        }

        let dCipher = self.decryptingCipher

        // Attempt to decrypt the data we received before passing it along
        guard let decrypted = dCipher.unpack(encrypted: someData, expectedCiphertextLength: payloadLength) else
        {
            log.error("ShadowSwift: shadowReceive decryption failure 🕳.")
            let _ = BlackHole(timeoutDelaySeconds: 30, socket: self)
            
            completion(someData, maybeContext, connectionComplete, NWError.posix(POSIXErrorCode.EBADMSG))
            return
        }
        
        if connectionComplete
        {
            network.close()
        }
        
        completion(decrypted, maybeContext, false, nil)
    }

    // End of Connection Protocol

    func sendAddress()
    {
        let address = AddressReader().createAddr()
        guard let encryptedAddress = encryptingCipher.pack(plaintext: address) else
        {
            self.log.error("ShadowSwift: Failed to encrypt our address. Cancelling connection.")
            network.close()
            
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
            self.log.error("ShadowSwift: network.write Failed. Cancelling connection.")
            network.close()
            
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
