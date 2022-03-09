//
//  File.swift
//  
//
//  Created by Dr. Brandon Wiley on 9/24/21.
//

import Foundation
import Crypto
import Transmission
import Datable
import SwiftHexTools
import Net

let P256KeySize = 32 // compact format
let ConfirmationSize = 32
let NonceSize = 32

let DarkStarString = "DarkStar"
let ServerString = "server"
let ClientString = "client"

public struct DarkStar
{
    var encryptKey: SymmetricKey!
    var decryptKey: SymmetricKey!

    static public func randomBytes(size: Int) -> Data
    {
        var dataArray = [Data.Element]()
        
        for _ in 1...size
        {
            let someInt = Int.random(in: 0 ..< 256)
            dataArray.append(Data.Element(someInt))
        }
                
        return Data(array: dataArray)
    }

    #if os(macOS)
    static public func generateServerConfirmationCode(theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateEphemeralKey: SecureEnclave.P256.KeyAgreement.PrivateKey, myPrivateStaticKey: SecureEnclave.P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint) -> Data?
    {
        guard let ecdh = try? myPrivateStaticKey.sharedSecretFromKeyAgreement(with: theirPublicKey) else {return nil}
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return nil}
        let serverPersistentPublicKeyData = myPrivateStaticKey.publicKey.compactRepresentation!
        let clientEphemeralPublicKeyData = theirPublicKey.compactRepresentation!

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverPersistentPublicKeyData)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ServerString.data)
        let result = hash.finalize()

        return Data(result)
    }
    #else
    static public func generateServerConfirmationCode(theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateEphemeralKey: P256.KeyAgreement.PrivateKey, myPrivateStaticKey: P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint) -> filterData?
    {
        guard let ecdh = try? myPrivateStaticKey.sharedSecretFromKeyAgreement(with: theirPublicKey) else {return nil}
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return nil}
        let serverPersistentPublicKeyData = myPrivateStaticKey.publicKey.compactRepresentation!
        let clientEphemeralPublicKeyData = theirPublicKey.compactRepresentation!

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverPersistentPublicKeyData)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ServerString.data)
        let result = hash.finalize()

        return Data(result)
    }
    #endif
    
    
    static public func handleServerEphemeralKey(connection: Connection) -> (P256.KeyAgreement.PrivateKey, P256.KeyAgreement.PublicKey)?
    {
        let myEphemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let myEphemeralPublicKey = myEphemeralPrivateKey.publicKey
        let myEphemeralPublicKeyData = myEphemeralPublicKey.compactRepresentation!

        guard connection.write(data: myEphemeralPublicKeyData) else {return nil}

        return (myEphemeralPrivateKey, myEphemeralPublicKey)
    }

    #if os(macOS)
    static public func handleClientEphemeralKey(connection: Connection) -> (SecureEnclave.P256.KeyAgreement.PrivateKey, P256.KeyAgreement.PublicKey)?
    {
        guard let myEphemeralPrivateKey = try? SecureEnclave.P256.KeyAgreement.PrivateKey() else {return nil}
        let myEphemeralPublicKey = myEphemeralPrivateKey.publicKey
        let myEphemeralPublicKeyData = myEphemeralPublicKey.compactRepresentation!

        guard connection.write(data: myEphemeralPublicKeyData) else {return nil}

        return (myEphemeralPrivateKey, myEphemeralPublicKey)
    }
    
    static public func generateClientConfirmationCode(connection: Connection, theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateKey: SecureEnclave.P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Data?
    {
        guard let ecdh = try? myPrivateKey.sharedSecretFromKeyAgreement(with: theirPublicKey) else {return nil}
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return nil}
        let serverPersistentPublicKeyData = serverPersistentPublicKey.compactRepresentation!
        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation!

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverPersistentPublicKeyData)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ClientString.data)
        let result = hash.finalize()

        return Data(result)
    }
    
    #else
    static public func handleClientEphemeralKey(connection: Connection) -> (P256.KeyAgreement.PrivateKey, P256.KeyAgreement.PublicKey)?
    {
        guard let myEphemeralPrivateKey = try? P256.KeyAgreement.PrivateKey() else {return nil}
        let myEphemeralPublicKey = myEphemeralPrivateKey.publicKey
        let myEphemeralPublicKeyData = myEphemeralPublicKey.compactRepresentation!

        guard connection.write(data: myEphemeralPublicKeyData) else {return nil}

        return (myEphemeralPrivateKey, myEphemeralPublicKey)
    }
    
    static public func generateClientConfirmationCode(connection: Connection, theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateKey: P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> filterData?
    {
        guard let ecdh = try? myPrivateKey.sharedSecretFromKeyAgreement(with: theirPublicKey) else {return nil}
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return nil}
        let serverPersistentPublicKeyData = serverPersistentPublicKey.compactRepresentation!
        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation!

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverPersistentPublicKeyData)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ClientString.data)
        let result = hash.finalize()

        return Data(result)
    }
    #endif

    

    static public func handleTheirEphemeralPublicKey(connection: Connection) -> P256.KeyAgreement.PublicKey?
    {
        // Receive their ephemeral key
        guard let theirEphemeralPublicKeyData = connection.read(size: P256KeySize) else {return nil}
        guard let theirEphemeralPublicKey = try? P256.KeyAgreement.PublicKey(compactRepresentation: theirEphemeralPublicKeyData) else {return nil}
        return theirEphemeralPublicKey
    }

    static func sharedSecretToData(secret: SharedSecret) -> Data
    {
        let data = secret.withUnsafeBytes
        {
            (rawPointer: UnsafeRawBufferPointer) -> Data in

            var result = Data(repeating: 0, count: 32)
            for index in 0..<32
            {
                result[index] = rawPointer[index]
            }

            return result
        }

        return data
    }

    static func symmetricKeyToData(key: SymmetricKey) -> Data
    {
        let data = key.withUnsafeBytes
        {
            (rawPointer: UnsafeRawBufferPointer) -> Data in

            var result = Data(repeating: 0, count: 32)
            for index in 0..<32
            {
                result[index] = rawPointer[index]
            }

            return result
        }

        return data
    }

    static func makeServerIdentifier(_ endpoint: NWEndpoint) -> Data?
    {
        switch endpoint
        {
            case .hostPort(let host, let port):
                guard let portData = port.rawValue.maybeNetworkData else {return nil}
                switch host
                {
                    case .ipv4(let ipv4):
                        let ipv4Data = ipv4.rawValue
                        return ipv4Data + portData
                    case .ipv6(let ipv6):
                        let ipv6Data = ipv6.rawValue
                        return ipv6Data + portData
                    default:
                        return nil
                }
            default:
                return nil
        }
    }
}

enum ServerType: UInt8
{
    case ipv4 = 0
    case ipv6 = 1
}

enum HandshakeState
{
    case start(StartState)
    case finished(FinishedState)
}

struct StartState
{
    let serverPersistentPublicKey: P256.KeyAgreement.PublicKey
}

struct FinishedState
{
    let encryptKey: SymmetricKey
    let decryptKey: SymmetricKey
}
