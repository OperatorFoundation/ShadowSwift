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

public struct DarkStar
{
    let encryptKey: SymmetricKey
    let decryptKey: SymmetricKey

    public init?(serverPersistentPublicKey: P256.KeyAgreement.PublicKey, endpoint: NWEndpoint, connection: Connection)
    {
        // Send client ephemeral key
        let clientEphemeralPrivateKey = P256.KeyAgreement.PrivateKey()
        let clientEphemeralPublicKey = clientEphemeralPrivateKey.publicKey
        guard let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation else {return}

        guard connection.write(data: clientEphemeralPublicKeyData) else {return}

        // Receive server ephemeral key
        guard let serverEphemeralPublicKeyData = connection.read(size: P256KeySize) else {return nil}
        guard let serverEphemeralPublicKey = try? P256.KeyAgreement.PublicKey(compactRepresentation: serverEphemeralPublicKeyData) else {return}

        // Derive shared keys
        guard let newEncryptKey = DarkStar.createEncryptKey(serverPersistentPublicKey: serverPersistentPublicKey, serverEphemeralPublicKey: serverEphemeralPublicKey, clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEndpoint: endpoint) else {return nil}
        encryptKey = newEncryptKey

        guard let decryptKey = DarkStar.createDecryptKey(serverPersistentPublicKey: serverPersistentPublicKey, serverEphemeralPublicKey: serverEphemeralPublicKey, clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEndpoint: endpoint) else {return nil}
        self.decryptKey = decryptKey

        let clientConfirmationCode = DarkStar.generateConfirmationCode(endpoint: endpoint, serverEphemeralPublicKey: serverEphemeralPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey)

        // Receive server confirmation code
        guard let serverConfirmationCode = connection.read(size: ConfirmationSize) else {return nil}

        guard clientConfirmationCode == serverConfirmationCode else {return nil}
    }

    static func createEncryptKey(serverPersistentPublicKey: P256.KeyAgreement.PublicKey, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, serverEndpoint: NWEndpoint) -> SymmetricKey?
    {
        return DarkStar.createSharedKey(serverPersistentPublicKey: serverPersistentPublicKey, serverEphemeralPublicKey: serverEphemeralPublicKey, clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEndpoint: serverEndpoint, personalizationString: "client")
    }

    static func createDecryptKey(serverPersistentPublicKey: P256.KeyAgreement.PublicKey, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, serverEndpoint: NWEndpoint) -> SymmetricKey?
    {
        return DarkStar.createSharedKey(serverPersistentPublicKey: serverPersistentPublicKey, serverEphemeralPublicKey: serverEphemeralPublicKey, clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEndpoint: serverEndpoint, personalizationString: "server")
    }

    static func createSharedKey(serverPersistentPublicKey: P256.KeyAgreement.PublicKey, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, serverEndpoint: NWEndpoint, personalizationString: String) -> SymmetricKey?
    {
        guard let ephemeralECDH = try? clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverEphemeralPublicKey) else {return nil}

        // This is upsetting.
        let ephemeralECDHData = ephemeralECDH.withUnsafeBytes
        {
            (rawPointer: UnsafeRawBufferPointer) -> Data in

            var result = Data(repeating: 0, count: 8)
            for index in 0..<8
            {
                result[index] = rawPointer[index]
            }

            return result
        }

        guard let persistentECDH = try? clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverPersistentPublicKey) else {return nil}

        let persistentECDHData = persistentECDH.withUnsafeBytes
        {
            (rawPointer: UnsafeRawBufferPointer) -> Data in

            var result = Data(repeating: 0, count: 8)
            for index in 0..<8
            {
                result[index] = rawPointer[index]
            }

            return result
        }

        let clientEphemeralPublicKey = clientEphemeralPrivateKey.publicKey
        guard let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation else {return nil}
        guard let serverEphemeralPublicKeyData = serverEphemeralPublicKey.compactRepresentation else {return nil}

        guard let serverIdentifier = DarkStar.makeServerIdentifier(serverEndpoint) else {return nil}

        var hash = SHA256()
        hash.update(data: ephemeralECDHData)
        hash.update(data: persistentECDHData)
        hash.update(data: serverIdentifier)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: serverEphemeralPublicKeyData)
        hash.update(data: "ntor".data)
        hash.update(data: personalizationString.data)
        let hashed = hash.finalize()

        let hashedData = Data(hashed)
        return SymmetricKey(data: hashedData)
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

    static public func generateConfirmationCode(endpoint: NWEndpoint, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Data?
        {
            guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return nil}
            guard let serverEphemeralPublicKeyData = serverEphemeralPublicKey.compactRepresentation else {return nil}
            guard let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation else {return nil}

            var hash = SHA256()
            hash.update(data: serverIdentifier)
            hash.update(data: serverEphemeralPublicKeyData)
            hash.update(data: clientEphemeralPublicKeyData)
            hash.update(data: "ntor".data)
            hash.update(data: "server".data)
            let result = hash.finalize()

            return Data(result)
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
