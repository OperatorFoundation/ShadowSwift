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

// TODO: FIX THE LOG MESSAGES
public class ShadowTransmissionClientConnection: Transmission.Connection
{
    public var viabilityUpdateHandler: ((Bool) -> Void)?
    public var log: Logger

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
        self.log = logger
        guard let ipvHost = IPv4Address(host) else
        {
            log.error("\nDarkStarClientConnection - unable to resolve \(host) as a valid IPV4 address.")
            return nil
        }
        
        let endpointHost = NWEndpoint.Host.ipv4(ipvHost)
        let endpointPort = NWEndpoint.Port(integerLiteral: UInt16(port))
        let endpoint = NWEndpoint.hostPort(host: endpointHost, port: endpointPort)

        guard config.mode == .DARKSTAR else
        {
            log.error("\nDarkStarClientConnection - Attempted a connection with \(config.mode.rawValue), Currently DarkStar is the only supported shadow mode.")
            return nil
        }
        
        let serverPersistentPublicKey: P256.KeyAgreement.PublicKey
        switch config.serverPublicKey
        {
            case .P256KeyAgreement(let publicKey):
                serverPersistentPublicKey = publicKey

            default:
                print("Wrong public key type")
                return nil
        }

        guard let client = DarkStarClient(serverPersistentPublicKey: serverPersistentPublicKey, endpoint: endpoint, connection: connection) else
        {
            log.error("\nDarkStarClientConnection - handshake failed.")
            return nil
        }

        guard let eCipher = DarkStarCipher(key: client.clientToServerSharedKey, endpoint: endpoint, isServerConnection: false, logger: self.log) else
        {
            log.error("\nDarkStarClientConnection - failed to make an encryption cipher.")
            return nil
        }
        
        guard let dCipher = DarkStarCipher(key: client.serverToClientSharedKey, endpoint: endpoint, isServerConnection: false, logger: self.log) else
        {
            log.error("\nDarkStarClientConnection - failed to make a decryption cipher.")
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
        let prefixSizeInBytes = prefixSizeInBits * 8
        guard let lengthData = self.read(size: prefixSizeInBytes) else
        {
            return nil
        }
        
        let length: Int
        switch prefixSizeInBits
        {
            case 8:
                let uint8 = UInt8(data: lengthData)
                length = Int(uint8)
            
            case 16:
                let uint16 = UInt16(data: lengthData)
                length = Int(uint16)
            
            case 32:
                let uint32 = UInt32(data: lengthData)
                length = Int(uint32)
            
            case 64:
                let uint64 = UInt64(data: lengthData)
                length = Int(uint64)
            
            default:
                return nil
        }
        
        return self.read(size: length)
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
            log.error("\nDarkStarClientConnection - Failed to encrypt send content.")
            return false
        }

        return network.write(data: encrypted)
    }
    
    public func writeWithLengthPrefix(data: Data, prefixSizeInBits: Int) -> Bool
    {
        if networkClosed {
            return false
        }
        
        let dataSize = data.count
        switch prefixSizeInBits
        {
            case 8:
                guard dataSize < UInt8.max else
                {
                    return false
                }
                
                let uint8 = UInt8(dataSize)
                let newData = uint8.data + data
                return self.write(data: newData)
                
            case 16:
                guard dataSize < UInt16.max else
                {
                    return false
                }
                
                let uint16 = UInt16(dataSize)
                let newData = uint16.data + data
                return self.write(data: newData)
                
            case 32:
                guard dataSize < UInt32.max else
                {
                    return false
                }
                
                let uint32 = UInt32(dataSize)
                let newData = uint32.data + data
                return self.write(data: newData)
                
            case 64:
                guard dataSize < UInt64.max else
                {
                    return false
                }
                
                let uint64 = UInt64(dataSize)
                let newData = uint64.data + data
                return self.write(data: newData)
                
            default:
                return false
        }
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
            self.log.error("\nDarkStarClientConnection - receive called, but there was no data.")
            self.close()
            return false
        }
        
        guard someData.count == encryptedLengthSize else
        {
            self.log.error("\nDarkStarClientConnection - receive(min:max:) called, but the encrypted length data was the wrong size.")
            self.log.error("\nDarkStarClientConnection - required size: \(encryptedLengthSize), received size: \(someData.count)")
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
            self.log.error("\nDarkStarClientConnection - Failed to get encrypted data's expected length. Length data could not be converted to UInt16")
            self.close()
            return false
        }

        // Read data of payloadLength + tagSize
        let payloadLength = Int(lengthUInt16)
        let expectedLength = payloadLength + Cipher.tagSize
        let nextMaybeData = network.read(size: expectedLength)
                
        guard let nextData = nextMaybeData else
        {
            self.log.error("\nDarkStarClientConnection - receive called, but there was no data.")
            self.close()
            return false
        }
        
        guard nextData.count == expectedLength else
        {
            self.log.error("\nDarkStarClientConnection - receive(min:max:) called, but the encrypted length data was the wrong size.")
            self.log.error("\nDarkStarClientConnection - required size: \(encryptedLengthSize), received size: \(someData.count)")
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
