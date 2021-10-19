//
//  DarkStarServer.swift
//  ShadowSwift
//
//  Created by Dr. Brandon Wiley on 10/14/21.
//

import Foundation
import Crypto
import Transmission
import Network
import Datable
import SwiftHexTools

public class DarkStarServer
{
    let serverNonce: AES.GCM.Nonce
    let clientNonce: AES.GCM.Nonce
    let sharedKey: SymmetricKey

    static public func handleServerConfirmationCode(connection: Connection, sharedKey: SymmetricKey, endpoint: NWEndpoint, serverEphemeralPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Bool
    {
        guard let data = DarkStar.generateServerConfirmationCode(clientSharedKey: sharedKey, endpoint: endpoint, serverEphemeralPublicKey: serverEphemeralPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey) else {return false}
        print("server confirmation code: \(data.hex)")
        return connection.write(data: data)
    }

    static public func handleClientConfirmationCode(connection: Connection, theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateKey: P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Bool
    {
        let data = connection.read(size: ConfirmationSize)

        guard let code = generateClientConfirmationCode(connection: connection, theirPublicKey: theirPublicKey, myPrivateKey: myPrivateKey, endpoint: endpoint, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey) else {return false}
        
        print(code.hex)
        print(data!.hex)
        

        return data == code
    }

    static public func generateClientConfirmationCode(connection: Connection, theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateKey: P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, serverPersistentPublicKey: P256.KeyAgreement.PublicKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey) -> Data?
    {
        print(serverPersistentPublicKey.derRepresentation.hex)
        print(clientEphemeralPublicKey.derRepresentation.hex)
        print(theirPublicKey)
        
        
        guard let ecdh = try? myPrivateKey.sharedSecretFromKeyAgreement(with: theirPublicKey) else {return nil}
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        print("ecdhData: \(ecdhData.hex)")
        
        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else {return nil}
        
        print("serverIdentifier: \(serverIdentifier.hex)")
        
        let serverPersistentPublicKeyData = serverPersistentPublicKey.derRepresentation
        
        print("SPPK: \(serverPersistentPublicKeyData.hex)")
        
        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.derRepresentation

        print("CEPK: \(clientEphemeralPublicKeyData.hex)")
        
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

    static public func createServerSharedKey(serverPersistentPrivateKey: P256.KeyAgreement.PrivateKey, serverEphemeralPrivateKey: P256.KeyAgreement.PrivateKey, clientEphemeralPublicKey: P256.KeyAgreement.PublicKey, serverEndpoint: NWEndpoint) -> SymmetricKey?
    {
        guard let ephemeralECDH = try? serverEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: clientEphemeralPublicKey) else {return nil}

       let ephemeralECDHData = DarkStar.sharedSecretToData(secret: ephemeralECDH)

        guard let persistentECDH = try? serverPersistentPrivateKey.sharedSecretFromKeyAgreement(with: clientEphemeralPublicKey) else {return nil}

        let persistentECDHData = DarkStar.sharedSecretToData(secret: persistentECDH)

        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.derRepresentation

        let serverEphemeralPublicKey = serverEphemeralPrivateKey.publicKey
        let serverEphemeralPublicKeyData = serverEphemeralPublicKey.derRepresentation

        guard let serverIdentifier = DarkStar.makeServerIdentifier(serverEndpoint) else {return nil}

        var hash = SHA256()
        hash.update(data: ephemeralECDHData)
        hash.update(data: persistentECDHData)
        hash.update(data: serverIdentifier)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: serverEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ServerString.data)
        let hashed = hash.finalize()

        let hashedData = Data(hashed)
        return SymmetricKey(data: hashedData)
    }

    public init?(serverPersistentPrivateKey: P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint, connection: Connection)
    {
        let serverPersistentPublicKey = serverPersistentPrivateKey.publicKey

        // Receive client ephemeral key
        guard let clientEphemeralPublicKey = DarkStar.handleTheirEphemeralPublicKey(connection: connection) else {return nil}

        // Receive and validate client confirmation code
        guard DarkStarServer.handleClientConfirmationCode(connection: connection, theirPublicKey: clientEphemeralPublicKey, myPrivateKey: serverPersistentPrivateKey, endpoint: endpoint, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey) else {return nil}

        // Receive client nonce
        guard let clientNonceData = DarkStar.handleTheirNonce(connection: connection) else {return nil}

        guard let clientNonce = try? AES.GCM.Nonce(data: clientNonceData) else {return nil}
        self.clientNonce = clientNonce

        // Send server ephemeral key
        guard let (serverEphemeralPrivateKey, serverEphemeralPublicKey) = DarkStar.handleMyEphemeralKey(connection: connection) else {return nil}

        // Create shared key
        guard let sharedKey = DarkStarServer.createServerSharedKey(serverPersistentPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey, serverEndpoint: endpoint) else {return nil}
        self.sharedKey = sharedKey

        // Send server confirmation code
        guard DarkStarServer.handleServerConfirmationCode(connection: connection, sharedKey: sharedKey, endpoint: endpoint, serverEphemeralPublicKey: serverEphemeralPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey) else {return nil}

        // Send server nonce
        guard let serverNonce = DarkStar.handleMyNonce(connection: connection) else {return nil}

        guard let serverNonce = try? AES.GCM.Nonce(data: serverNonce) else {return nil}
        self.serverNonce = serverNonce
    }
}
