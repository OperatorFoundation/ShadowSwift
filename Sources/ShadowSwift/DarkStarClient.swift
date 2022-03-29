//
//  DarkStarClient.swift
//  ShadowSwift
//
//  Created by Dr. Brandon Wiley on 10/14/21.
//

import Foundation
import Crypto
import Transmission
import Net
import Datable
import SwiftHexTools

public class DarkStarClient
{
    let clientToServerSharedKey: SymmetricKey
    let serverToClientSharedKey: SymmetricKey

    #if os(macOS)
    static public func handleServerConfirmationCode(connection: Connection, endpoint: NWEndpoint, serverStaticPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPrivateKey: SecureEnclave.P256.KeyAgreement.PrivateKey) -> Bool
    {
        let data = connection.read(size: P256KeySize)

        guard let ecdh = try? clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverStaticPublicKey) else {return false}
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return false}
        let clientEphemeralPublicKeyData = clientEphemeralPrivateKey.publicKey.compactRepresentation!
        let serverStaticPublicKeyData = serverStaticPublicKey.compactRepresentation!

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverStaticPublicKeyData)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ServerString.data)
        let result = hash.finalize()

        let code = Data(result)

        return data == code
    }
    
    static public func handleClientConfirmationCode(connection: Connection, theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateKey: SecureEnclave.P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Bool
    {
        guard let data = DarkStar.generateClientConfirmationCode(connection: connection, theirPublicKey: theirPublicKey, myPrivateKey: myPrivateKey, endpoint: endpoint, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey) else {return false}

        return connection.write(data: data)
    }

    static public func createClientToServerSharedKey(clientEphemeralPrivateKey: SecureEnclave.P256.KeyAgreement.PrivateKey, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, serverEndpoint: NWEndpoint) -> SymmetricKey?
    {
        createClientSharedKey(clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverPersistentPublicKey: serverPersistentPublicKey, serverEndpoint: serverEndpoint, personalizationString: ServerString)
    }

    static public func createServerToClientSharedKey(clientEphemeralPrivateKey: SecureEnclave.P256.KeyAgreement.PrivateKey, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, serverEndpoint: NWEndpoint) -> SymmetricKey?
    {
        createClientSharedKey(clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverPersistentPublicKey: serverPersistentPublicKey, serverEndpoint: serverEndpoint, personalizationString: ClientString)
    }

    static func createClientSharedKey(clientEphemeralPrivateKey: SecureEnclave.P256.KeyAgreement.PrivateKey, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, serverEndpoint: NWEndpoint, personalizationString: String) -> SymmetricKey?
    {
        guard let ephemeralECDH = try? clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverEphemeralPublicKey) else {return nil}

        let ephemeralECDHData = DarkStar.sharedSecretToData(secret: ephemeralECDH)

        guard let persistentECDH = try? clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverPersistentPublicKey) else {return nil}

        let persistentECDHData = DarkStar.sharedSecretToData(secret: persistentECDH)

        let clientEphemeralPublicKey = clientEphemeralPrivateKey.publicKey

        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation!

        let serverEphemeralPublicKeyData = serverEphemeralPublicKey.compactRepresentation!

        guard let serverIdentifier = DarkStar.makeServerIdentifier(serverEndpoint) else {return nil}

        var hash = SHA256()
        hash.update(data: ephemeralECDHData)
        hash.update(data: persistentECDHData)
        hash.update(data: serverIdentifier)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: serverEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: personalizationString.data) // Destination
        let hashed = hash.finalize()

        let hashedData = Data(hashed)
        return SymmetricKey(data: hashedData)
    }
    
    #else // SecureEnclave is only available on Apple devices
    static public func handleServerConfirmationCode(connection: Connection, endpoint: NWEndpoint, serverStaticPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPrivateKey: P256.KeyAgreement.PrivateKey) -> Bool
    {
        let data = connection.read(size: P256KeySize)

        guard let ecdh = try? clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverStaticPublicKey) else {return false}
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return false}
        let clientEphemeralPublicKeyData = clientEphemeralPrivateKey.publicKey.compactRepresentation!
        let serverStaticPublicKeyData = serverStaticPublicKey.compactRepresentation!

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverStaticPublicKeyData)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ServerString.data)
        let result = hash.finalize()

        let code = Data(result)

        return data == code
    }
    
    static public func handleClientConfirmationCode(connection: Connection, theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateKey: P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Bool
    {
        guard let data = DarkStar.generateClientConfirmationCode(connection: connection, theirPublicKey: theirPublicKey, myPrivateKey: myPrivateKey, endpoint: endpoint, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey) else {return false}

        return connection.write(data: data)
    }

    static public func createClientToServerSharedKey(clientEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, serverEndpoint: NWEndpoint) -> SymmetricKey?
    {
        createClientSharedKey(clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverPersistentPublicKey: serverPersistentPublicKey, serverEndpoint: serverEndpoint, personalizationString: ServerString)
    }

    static public func createServerToClientSharedKey(clientEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, serverEndpoint: NWEndpoint) -> SymmetricKey?
    {
        createClientSharedKey(clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverPersistentPublicKey: serverPersistentPublicKey, serverEndpoint: serverEndpoint, personalizationString: ClientString)
    }

    static func createClientSharedKey(clientEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, serverEndpoint: NWEndpoint, personalizationString: String) -> SymmetricKey?
    {
        guard let ephemeralECDH = try? clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverEphemeralPublicKey) else {return nil}

        let ephemeralECDHData = DarkStar.sharedSecretToData(secret: ephemeralECDH)

        guard let persistentECDH = try? clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverPersistentPublicKey) else {return nil}

        let persistentECDHData = DarkStar.sharedSecretToData(secret: persistentECDH)

        let clientEphemeralPublicKey = clientEphemeralPrivateKey.publicKey

        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation!

        let serverEphemeralPublicKeyData = serverEphemeralPublicKey.compactRepresentation!

        guard let serverIdentifier = DarkStar.makeServerIdentifier(serverEndpoint) else {return nil}

        var hash = SHA256()
        hash.update(data: ephemeralECDHData)
        hash.update(data: persistentECDHData)
        hash.update(data: serverIdentifier)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: serverEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: personalizationString.data) // Destination
        let hashed = hash.finalize()

        print(ephemeralECDHData.hex)
        print(persistentECDHData.hex)
        print(serverIdentifier.hex)
        print(clientEphemeralPublicKeyData.hex)
        print(serverEphemeralPublicKeyData.hex)
        print(DarkStarString.data.hex)
        print(personalizationString.data.hex)

        let hashedData = Data(hashed)
        return SymmetricKey(data: hashedData)
    }
    #endif

    public init?(serverPersistentPublicKey: P256.KeyAgreement.PublicKey, endpoint: NWEndpoint, connection: Connection)
    {
        // Send client ephemeral key
        guard let (clientEphemeralPrivateKey, clientEphemeralPublicKey) = DarkStar.handleClientEphemeralKey(connection: connection) else {return nil}

        // Send client confirmation code
        guard DarkStarClient.handleClientConfirmationCode(connection: connection, theirPublicKey: serverPersistentPublicKey, myPrivateKey: clientEphemeralPrivateKey, endpoint: endpoint, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey) else {return nil}

        // Receive server ephemeral key
        guard let serverEphemeralPublicKey = DarkStar.handleTheirEphemeralPublicKey(connection: connection) else {return nil}

        // Create shared key
        guard let clientToServerSharedKey = DarkStarClient.createClientToServerSharedKey(clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverPersistentPublicKey: serverPersistentPublicKey, serverEndpoint: endpoint) else {return nil}
        self.clientToServerSharedKey = clientToServerSharedKey

        guard let serverToClientSharedKey = DarkStarClient.createClientToServerSharedKey(clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverPersistentPublicKey: serverPersistentPublicKey, serverEndpoint: endpoint) else {return nil}
        self.serverToClientSharedKey = serverToClientSharedKey

        //      Todo: Get rid of this
        //        let keyb64 = sharedKey.withUnsafeBytes {
        //            return Data(Array($0)).hex
        //        }
        //
        //        print("Shared key: " + keyb64)

        // Receive and validate server confirmation code
        guard DarkStarClient.handleServerConfirmationCode(connection: connection, endpoint: endpoint, serverStaticPublicKey: serverPersistentPublicKey, clientEphemeralPrivateKey: clientEphemeralPrivateKey) else {return nil}
    }
}
