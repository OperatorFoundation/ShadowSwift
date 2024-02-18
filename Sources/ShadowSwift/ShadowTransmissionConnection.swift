//
//  File.swift
//  
//
//  Created by Joshua Clark on 9/12/22.
//

import Crypto
import Foundation
import Logging

import Chord
import Datable
import Net
import Transmission
import Transport
import Straw

public class ShadowTransmissionClientConnection: Transmission.Connection
{
    public var viabilityUpdateHandler: ((Bool) -> Void)?
    public var logger: Logger

    let networkQueue = DispatchQueue(label: "DarkStarClientConnectionQueue")
    let encryptingCipher: DarkStarCipher
    var decryptingCipher: DarkStarCipher
    var network: Transmission.Connection
    var networkClosed = false
    var strawBuffer = Straw()
    
    public convenience init?(host: String, port: Int, config: ShadowConfig.ShadowClientConfig, logger: Logger)
    {
        #if os(macOS)
        // Only support Apple devices with secure enclave.
        guard SecureEnclave.isAvailable else
        {
            return nil
        }
        #endif

        guard let newConnection = Transmission.TransmissionConnection(host: host, port: port) else
        {
            logger.error("\nDarkStarClientConnection - Failed to initialize because we could not create a Network Connection using host \(host) and port \(port).")
            return nil
        }
        
        self.init(connection: newConnection, host: host, port: port, config: config, logger: logger)
    }

    public init?(connection: Transmission.Connection, host: String, port: Int, config: ShadowConfig.ShadowClientConfig, logger: Logger)
    {
        self.logger = logger
        guard let ipvHost = IPv4Address(host) else
        {
            logger.error("\nDarkStarClientConnection - unable to resolve \(host) as a valid IPV4 address.")
            return nil
        }
        
        let endpointHost = NWEndpoint.Host.ipv4(ipvHost)
        let endpointPort = NWEndpoint.Port(integerLiteral: UInt16(port))
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: endpointPort)

        guard config.mode == .DARKSTAR else
        {
            logger.error("\nDarkStarClientConnection - Attempted a connection with \(config.mode.rawValue), Currently DarkStar is the only supported shadow mode.")
            return nil
        }
        
        let serverPersistentPublicKey: P256.KeyAgreement.PublicKey
        switch config.serverPublicKey
        {
            case .P256KeyAgreement(let publicKey):
                serverPersistentPublicKey = publicKey

            default:
                logger.error("Failed to initialize a ShadowTransmissionClientConnection: Incorrect public key type in config.")
                return nil
        }

        guard let client = DarkStarClient(serverPersistentPublicKey: serverPersistentPublicKey, endpoint: endpoint, connection: connection) else
        {
            logger.error("\nDarkStarClientConnection - handshake failed.")
            return nil
        }

        guard let eCipher = DarkStarCipher(key: client.clientToServerSharedKey, endpoint: endpoint, isServerConnection: false, logger: self.logger) else
        {
            logger.error("\nDarkStarClientConnection - failed to make an encryption cipher.")
            return nil
        }
        
        guard let dCipher = DarkStarCipher(key: client.serverToClientSharedKey, endpoint: endpoint, isServerConnection: false, logger: self.logger) else
        {
            logger.error("\nDarkStarClientConnection - failed to make a decryption cipher.")
            return nil
        }

        self.encryptingCipher = eCipher
        self.decryptingCipher = dCipher
        self.network = connection
    }

    
    public func read(size: Int) -> Data?
    {
        while strawBuffer.count < size
        {
            guard networkRead() else
            {
                return nil
            }
        }
        
        do
        {
            return try self.strawBuffer.read(size: size)
        }
        catch
        {
            return nil
        }
    }

    public func unsafeRead(size: Int) -> Data?
    {
        while strawBuffer.count < size
        {
            guard networkRead() else
            {
                return nil
            }
        }

        do
        {
            return try self.strawBuffer.read(size: size)
        }
        catch
        {
            return nil
        }
    }
    
    public func read(maxSize: Int) -> Data?
    {
        while self.strawBuffer.isEmpty
        {
            guard networkRead() else
            {
                return nil
            }
        }
        
        do
        {
            return try self.strawBuffer.read(maxSize: maxSize)
        }
        catch
        {
            return nil
        }
    }
    
    public func readWithLengthPrefix(prefixSizeInBits: Int) -> Data?
    {
        return TransmissionTypes.readWithLengthPrefix(prefixSizeInBits: prefixSizeInBits, connection: self)
    }
    
    public func write(string: String) -> Bool
    {
        if networkClosed {
            return false
        }
        
        return self.write(data: string.data)
    }
    
    public func write(data: Data) -> Bool
    {
        if networkClosed {
            return false
        }
        
        guard data.count > 0 else
        {
            return true
        }

        guard let encrypted = encryptingCipher.pack(plaintext: data) else
        {
            logger.error("\nDarkStarClientConnection - Failed to encrypt send content.")
            return false
        }

        return network.write(data: encrypted)
    }
    
    public func writeWithLengthPrefix(data: Data, prefixSizeInBits: Int) -> Bool
    {
        if networkClosed {
            return false
        }

        return TransmissionTypes.writeWithLengthPrefix(data: data, prefixSizeInBits: prefixSizeInBits, connection: self)
    }
    
    public func close()
    {
        if !networkClosed {
            networkClosed = true
            self.network.close()
        }
    }
    
    func networkRead() -> Bool
    {
        if networkClosed {
            return false
        }
        
        // Get our encrypted length first
        let encryptedLengthSize = Cipher.lengthSize + Cipher.tagSize
        let maybeData = self.network.read(size: encryptedLengthSize)
        
        guard let someData = maybeData else
        {
            self.logger.error("\nDarkStarClientConnection - receive called, but there was no data.")
            self.close()
            return false
        }
        
        guard someData.count == encryptedLengthSize else
        {
            self.logger.error("\nDarkStarClientConnection - receive(min:max:) called, but the encrypted length data was the wrong size.")
            self.logger.error("\nDarkStarClientConnection - required size: \(encryptedLengthSize), received size: \(someData.count)")
            self.close()
            return false
        }
        
        guard let lengthData = self.decryptingCipher.unpack(encrypted: someData, expectedCiphertextLength: Cipher.lengthSize) else
        {
            // use decryptingCipher counter to see if this is the first time we have received something from the server
            if decryptingCipher.decryptCounter == 1
            {
                // TODO: if it is the first time and decryption fails, hang up and try again
                self.close()
                return false
            }
            else
            {
                // It is not the first time and we fail to decrypt, hang up and walk away
                self.close()
                return false
            }
        }

        guard let lengthUInt16 = lengthData.maybeNetworkUint16 else
        {
            self.logger.error("\nDarkStarClientConnection - Failed to get encrypted data's expected length. Length data could not be converted to UInt16")
            self.close()
            return false
        }

        // Read data of payloadLength + tagSize
        let payloadLength = Int(lengthUInt16)
        let expectedLength = payloadLength + Cipher.tagSize
        let nextMaybeData = network.read(size: expectedLength)
                
        guard let nextData = nextMaybeData else
        {
            self.logger.error("\nDarkStarClientConnection - receive called, but there was no data.")
            self.close()
            return false
        }
        
        guard nextData.count == expectedLength else
        {
            self.logger.error("\nDarkStarClientConnection - receive(min:max:) called, but the encrypted length data was the wrong size.")
            self.logger.error("\nDarkStarClientConnection - required size: \(encryptedLengthSize), received size: \(someData.count)")
            self.close()
            return false
        }
        
        guard let plaintext = self.decryptingCipher.unpack(encrypted: nextData, expectedCiphertextLength: payloadLength) else
        {
            // use decryptingCipher counter to see if this is the first time we have received something from the server
            if decryptingCipher.decryptCounter == 1
            {
                // TODO: if it is the first time and decryption fails, hang up and try again
                self.close()
                return false
            }
            else
            {
                // It is not the first time and we fail to decrypt, hang up and walk away
                self.close()
                return false
            }
        }
        
        self.strawBuffer.write(plaintext)
        return true
    }
}
