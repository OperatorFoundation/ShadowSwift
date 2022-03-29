//
//  DarkStarServer.swift
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

public class DarkStarServer
{
    let serverToClientSharedKey: SymmetricKey
    let clientToServerSharedKey: SymmetricKey

    static public func handleServerConfirmationCode(connection: Connection, endpoint: NWEndpoint, serverStaticPrivateKey: P256.KeyAgreement.PrivateKey, serverEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Bool
    {
        guard let ecdh = try? serverStaticPrivateKey.sharedSecretFromKeyAgreement(with: clientEphemeralPublicKey) else {return false}
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return false}
        let serverPersistentPublicKeyData = serverStaticPrivateKey.publicKey.compactRepresentation!
        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation!

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverPersistentPublicKeyData)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ServerString.data)
        let result = hash.finalize()

        let data = Data(result)

        return connection.write(data: data)
    }

    static public func handleClientConfirmationCode(connection: Connection, theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateKey: P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Bool
    {
        guard let data = connection.read(size: ConfirmationSize) else
        {
            print("DarkStarServer failed to read confirmation data.")
            return false
        }

        guard let code = generateClientConfirmationCode(connection: connection, theirPublicKey: theirPublicKey, myPrivateKey: myPrivateKey, endpoint: endpoint, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey)
        else
        {
            print("DarkStarServer failed to generate a client confirmation code.")
            return false
        }
        
        if data == code
        {
            return true
        }
        else
        {
            print("data: \(data.hex) != code: \(code.hex)")
            return false
        }
    }

    static public func generateClientConfirmationCode(connection: Connection, theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateKey:P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Data?
    {
        guard let ecdh = try? myPrivateKey.sharedSecretFromKeyAgreement(with: theirPublicKey) else
        {
            print("DarkStarServer failed to generate a shared secret.")
            return nil
        }
        
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)
        
        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else
        {
            print("DarkStarServer failed to make a server identifier.")
            return nil
        }
        
        print("Created a server identifier: \(serverIdentifier) from an endpoint: \(endpoint)")
                
        guard let serverPersistentPublicKeyData = serverPersistentPublicKey.compactRepresentation else
        {
            print("DarkStarServer failed to get public key data.")
            return nil
        }
                
        guard let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation else
        {
            print("DarkStarServer failed failed to create ephemeral public key data.")
            return nil
        }
        
        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverPersistentPublicKeyData)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ClientString.data)
        let result = hash.finalize()
        
        print("ecdhData: \(ecdhData.hex)")
        print("serverIdentifier: \(serverIdentifier.hex)")
        print("serverPersistentPublicKeyData \(serverPersistentPublicKeyData.hex)")
        print("clientEphemeralPublicKeyData: \(clientEphemeralPublicKeyData.hex)")
        print("DarkStarString as data: \(DarkStarString.data.hex)")
        print("ClientString as data as hex :) : \(ClientString.data.hex)")

        return Data(result)
    }

    static public func createServerToClientSharedKey(serverPersistentPrivateKey: P256.KeyAgreement.PrivateKey, serverEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey, serverEndpoint: NWEndpoint) -> SymmetricKey?
    {
        createServerSharedKey(serverPersistentPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey, serverEndpoint: serverEndpoint, personalizationString: ClientString)
    }

    static public func createClientToServerSharedKey(serverPersistentPrivateKey: P256.KeyAgreement.PrivateKey, serverEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey, serverEndpoint: NWEndpoint) -> SymmetricKey?
    {
        createServerSharedKey(serverPersistentPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey, serverEndpoint: serverEndpoint, personalizationString: ServerString)
    }

    static func createServerSharedKey(serverPersistentPrivateKey: P256.KeyAgreement.PrivateKey, serverEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey, serverEndpoint: NWEndpoint, personalizationString: String) -> SymmetricKey?
    {
        guard let ephemeralECDH = try? serverEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: clientEphemeralPublicKey) else {return nil}

       let ephemeralECDHData = DarkStar.sharedSecretToData(secret: ephemeralECDH)

        guard let persistentECDH = try? serverPersistentPrivateKey.sharedSecretFromKeyAgreement(with: clientEphemeralPublicKey) else {return nil}

        let persistentECDHData = DarkStar.sharedSecretToData(secret: persistentECDH)

        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.compactRepresentation!

        let serverEphemeralPublicKey = serverEphemeralPrivateKey.publicKey
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

    // TODO: Logging
    public init?(serverPersistentPrivateKey: P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, connection: Connection)
    {
        print("Initializing a DarkStarServer")
        let serverPersistentPublicKey = serverPersistentPrivateKey.publicKey

        // Receive client ephemeral key
        guard let clientEphemeralPublicKey = DarkStar.handleTheirEphemeralPublicKey(connection: connection) else
        {return nil}
        print("Received client ephemeral key")

        // Receive and validate client confirmation code
        guard DarkStarServer.handleClientConfirmationCode(connection: connection, theirPublicKey: clientEphemeralPublicKey, myPrivateKey: serverPersistentPrivateKey, endpoint: endpoint, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey) else
        {
            print("DarkStarServer received an invalid client confirmation code.")
            return nil
        }
        print("Received and validated client confirmation code")

        // Send server ephemeral key
        guard let (serverEphemeralPrivateKey, _) = DarkStar.handleServerEphemeralKey(connection: connection) else
        {return nil}
        print("Sent server ephemeral key")

        // Create shared key
        guard let serverToClientSharedKey = DarkStarServer.createServerToClientSharedKey(serverPersistentPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey, serverEndpoint: endpoint) else
        {return nil}
        
        self.serverToClientSharedKey = serverToClientSharedKey
        print("Created serverToClientSharedKey")

        guard let clientToServerSharedKey = DarkStarServer.createClientToServerSharedKey(serverPersistentPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey, serverEndpoint: endpoint) else
        {return nil}
        
        self.clientToServerSharedKey = clientToServerSharedKey
        print("Created clientToServerSharedKey")

        //      Todo: Get rid of this
        //        let keyb64 = sharedKey.withUnsafeBytes {
        //            return Data(Array($0)).hex
        //        }
        //
        //        print("Shared key: " + keyb64)

        // Send server confirmation code
        guard DarkStarServer.handleServerConfirmationCode(connection: connection, endpoint: endpoint, serverStaticPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey) else
        {return nil}
        
        print("Sent server confirmation code.")
    }
}
