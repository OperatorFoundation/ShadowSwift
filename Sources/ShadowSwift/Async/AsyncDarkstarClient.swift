//
//  AsyncDarkstarClient.swift
//  ShadowSwift
//
//
//  Created by Dr. Brandon Wiley on 10/14/21.
//

import Crypto
import Foundation

import Datable
import KeychainTypes
import Net
import TransmissionAsync

public class AsyncDarkstarClient
{
    let clientToServerSharedKey: SymmetricKey
    let serverToClientSharedKey: SymmetricKey

    static public func handleServerConfirmationCode(connection: AsyncConnection, host: String, port: Int, serverStaticPublicKey: PublicKey, clientEphemeralPrivateKey: PrivateKey) async throws
    {
        let data = try await connection.readSize(AsyncP256KeySize)

        let ecdh = try clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverStaticPublicKey)

        let ecdhData = AsyncDarkstar.sharedSecretToData(secret: ecdh)

        let serverIdentifier = try AsyncDarkstar.makeServerIdentifier(host, port)
        
        
        // FIXME: INCORRECT KEY FORMAT
        // FIXME: USE DARKSTAR KEY FORMAT
        guard let serverStaticPublicKeyKeychainData = serverStaticPublicKey.data else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }
        let serverStaticPublicKeyCryptoKit = try P256.KeyAgreement.PublicKey(x963Representation: serverStaticPublicKeyKeychainData)
        
        guard let clientEphemeralPublicKeyKeychainData = clientEphemeralPrivateKey.publicKey.data else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }
        let clientEphemeralPublicKeyCryptoKit = try P256.KeyAgreement.PublicKey(x963Representation: clientEphemeralPublicKeyKeychainData)
        
        
        let clientEphemeralPublicKeyDarkstarData = clientEphemeralPublicKeyCryptoKit.compactRepresentation!
        let serverStaticPublicKeyDarkstarData = serverStaticPublicKeyCryptoKit.compactRepresentation!
        

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverStaticPublicKeyDarkstarData)
        hash.update(data: clientEphemeralPublicKeyDarkstarData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ServerString.data)
        let result = hash.finalize()

        let code = Data(result)

        guard data == code else
        {
            throw AsyncDarkstarClientError.codesDoNotMatch(data, code)
        }
    }

    static public func handleClientConfirmationCode(connection: AsyncConnection, theirPublicKey: PublicKey, myPrivateKey: PrivateKey, host: String, port: Int, serverPersistentPublicKey: PublicKey, clientEphemeralPublicKey: PublicKey) async throws
    {
        let data = try AsyncDarkstar.generateClientConfirmationCode(connection: connection, theirPublicKey: theirPublicKey, myPrivateKey: myPrivateKey, host: host, port: port, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey)
        try await connection.write(data)
    }

    static public func createClientToServerSharedKey(clientEphemeralPrivateKey: PrivateKey, serverEphemeralPublicKey: PublicKey, serverPersistentPublicKey: PublicKey, host: String, port: Int) throws -> SymmetricKey
    {
        return try createClientSharedKey(clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverPersistentPublicKey: serverPersistentPublicKey, host: host, port: port, personalizationString: ServerString)
    }

    static public func createServerToClientSharedKey(clientEphemeralPrivateKey: PrivateKey, serverEphemeralPublicKey: PublicKey, serverPersistentPublicKey: PublicKey, host: String, port: Int) throws -> SymmetricKey
    {
        return try createClientSharedKey(clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverPersistentPublicKey: serverPersistentPublicKey, host: host, port: port, personalizationString: ClientString)
    }

    static func createClientSharedKey(clientEphemeralPrivateKey: PrivateKey, serverEphemeralPublicKey: PublicKey, serverPersistentPublicKey: PublicKey, host: String, port: Int, personalizationString: String) throws -> SymmetricKey
    {
        let ephemeralECDH = try clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverEphemeralPublicKey)
        let ephemeralECDHData = AsyncDarkstar.sharedSecretToData(secret: ephemeralECDH)
        let persistentECDH = try clientEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: serverPersistentPublicKey)
        let persistentECDHData = DarkStar.sharedSecretToData(secret: persistentECDH)
        let clientEphemeralPublicKey = clientEphemeralPrivateKey.publicKey
        let serverIdentifier = try AsyncDarkstar.makeServerIdentifier(host, port)
        
        guard let serverEphemeralPublicKeyKeychainData = serverEphemeralPublicKey.data else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }
        let serverEphemeralPublicKeyCryptoKit = try P256.KeyAgreement.PublicKey(x963Representation: serverEphemeralPublicKeyKeychainData)
        guard let serverEphemeralPublicKeyDarkstarData = serverEphemeralPublicKeyCryptoKit.compactRepresentation else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }

        guard let clientEphemeralPublicKeyKeychainData = clientEphemeralPublicKey.data else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }
        let clientEphemeralPublicKeyCryptoKit = try P256.KeyAgreement.PublicKey(x963Representation: clientEphemeralPublicKeyKeychainData)
        guard let clientEphemeralPublicKeyDarkstarData = clientEphemeralPublicKeyCryptoKit.compactRepresentation else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }

        var hash = SHA256()
        hash.update(data: ephemeralECDHData)
        hash.update(data: persistentECDHData)
        hash.update(data: serverIdentifier)
        hash.update(data: clientEphemeralPublicKeyDarkstarData)
        hash.update(data: serverEphemeralPublicKeyDarkstarData)
        hash.update(data: DarkStarString.data)
        hash.update(data: personalizationString.data) // Destination
        let hashed = hash.finalize()

        let hashedData = Data(hashed)
        return SymmetricKey(data: hashedData)
    }

    public init(serverPersistentPublicKey: PublicKey, host: String, port: Int, connection: AsyncConnection) async throws
    {
        // Send client ephemeral key
        let (clientEphemeralPrivateKey, clientEphemeralPublicKey) = try await AsyncDarkstar.handleClientEphemeralKey(connection: connection)

        // Send client confirmation code
        try await AsyncDarkstarClient.handleClientConfirmationCode(connection: connection, theirPublicKey: serverPersistentPublicKey, myPrivateKey: clientEphemeralPrivateKey, host: host, port: port, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey)

        // Receive server ephemeral key
        let serverEphemeralPublicKey = try await AsyncDarkstar.handleTheirEphemeralPublicKey(connection: connection, bloomFilter: nil)

        // Create shared key
        let clientToServerSharedKey = try AsyncDarkstarClient.createClientToServerSharedKey(clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverPersistentPublicKey: serverPersistentPublicKey, host: host, port: port)

        self.clientToServerSharedKey = clientToServerSharedKey

        let serverToClientSharedKey = try AsyncDarkstarClient.createServerToClientSharedKey(clientEphemeralPrivateKey: clientEphemeralPrivateKey, serverEphemeralPublicKey: serverEphemeralPublicKey, serverPersistentPublicKey: serverPersistentPublicKey, host: host, port: port)

        self.serverToClientSharedKey = serverToClientSharedKey

        // Receive and validate server confirmation code
        try await AsyncDarkstarClient.handleServerConfirmationCode(connection: connection, host: host, port: port, serverStaticPublicKey: serverPersistentPublicKey, clientEphemeralPrivateKey: clientEphemeralPrivateKey)
    }
}

public enum AsyncDarkstarClientError: Error
{
    case codesDoNotMatch(Data, Data)
}
