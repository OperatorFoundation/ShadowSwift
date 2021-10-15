//
//  File.swift
//  
//
//  Created by Dr. Brandon Wiley on 9/24/21.
//

import Foundation
import Crypto
import Transmission
import Network
import Datable

let P256KeySize = 32
let ConfirmationSize = 32
let NonceSize = 32

let DarkStarString = "DarkStar"
let ServerString = "server"
let ClientString = "client"

public struct DarkStar
{
    let encryptKey: SymmetricKey
    let decryptKey: SymmetricKey

    static public func randomBytes(size: Int) -> Data
    {
        var data = Data(count: size)
        _ = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, size, $0.baseAddress!)
        }
        return data
    }

    static public func generateServerConfirmationCode(clientSharedKey: SymmetricKey, endpoint: NWEndpoint, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Data?
    {
        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return nil}
        guard let serverEphemeralPublicKeyData = serverEphemeralPublicKey.compactRepresentation else {return nil}
        guard let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation else {return nil}

        var hmac = HMAC<SHA256>(key: clientSharedKey)
        hmac.update(data: serverIdentifier)
        hmac.update(data: serverEphemeralPublicKeyData)
        hmac.update(data: clientEphemeralPublicKeyData)
        hmac.update(data: DarkStarString.data)
        hmac.update(data: ServerString.data)
        let result = hmac.finalize()

        return Data(result)
    }

    static public func handleMyEphemeralKey(connection: Connection) -> (P256.KeyAgreement.PrivateKey, P256.KeyAgreement.PublicKey)?
    {
        let myEphemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let myEphemeralPublicKey = myEphemeralPrivateKey.publicKey
        guard let myEphemeralPublicKeyData = myEphemeralPublicKey.compactRepresentation else {return nil}

        guard connection.write(data: myEphemeralPublicKeyData) else {return nil}

        return (myEphemeralPrivateKey, myEphemeralPublicKey)
    }

    static public func generateClientConfirmationCode(connection: Connection, theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateKey: P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Data?
    {
        guard let ecdh = try? myPrivateKey.sharedSecretFromKeyAgreement(with: theirPublicKey) else {return nil}
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return nil}
        guard let serverPersistentPublicKeyData = serverPersistentPublicKey.compactRepresentation else {return nil}
        guard let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation else {return nil}

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

            var result = Data(repeating: 0, count: 8)
            for index in 0..<8
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
                        guard let serverTypeData = ServerType.ipv4.rawValue.maybeNetworkData else {return nil}
                        let ipv4Data = ipv4.rawValue
                        return serverTypeData + ipv4Data + portData
                    case .ipv6(let ipv6):
                        guard let serverTypeData = ServerType.ipv6.rawValue.maybeNetworkData else {return nil}
                        let ipv6Data = ipv6.rawValue
                        return serverTypeData + ipv6Data + portData
                    default:
                        return nil
                }
            default:
                return nil
        }
    }

    static public func handleTheirNonce(connection: Connection) -> Data?
    {
        return connection.read(size: NonceSize)
    }

    static public func handleMyNonce(connection: Connection) -> Data?
    {
        let nonce = DarkStar.randomBytes(size: NonceSize)
        guard connection.write(data: nonce) else {return nil}
        return nonce
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
