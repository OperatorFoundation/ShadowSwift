//
//  AsyncDarkStarServer.swift
//  
//
//  Created by Dr. Brandon Wiley on 7/7/23.
//

import Crypto
import Foundation
#if os(macOS)
import os.log
#else
import Logging
#endif

import Datable
import Keychain
import Net
import TransmissionAsync

public class AsyncDarkstarServer
{
    let serverToClientSharedKey: SymmetricKey
    let clientToServerSharedKey: SymmetricKey

    public init(serverPersistentPrivateKey: PrivateKey, host: String, port: Int, connection: AsyncConnection, bloomFilter: BloomFilter<Data>) async throws
    {
        let serverPersistentPublicKey = serverPersistentPrivateKey.publicKey

        // Receive client ephemeral key
        guard let clientEphemeralPublicKey = try? await AsyncDarkstar.handleTheirEphemeralPublicKey(connection: connection, bloomFilter: bloomFilter) else
        {
            print("ShadowSwift: Failed to receive the client ephemeral key 🕳.")
            let _ = AsyncBlackHole(timeoutDelaySeconds: 30, socket: connection)
            throw AsyncDarkstarServerError.blackHoled
        }

        // Receive and validate client confirmation code
        do
        {
            try await AsyncDarkstarServer.handleClientConfirmationCode(connection: connection, theirPublicKey: clientEphemeralPublicKey, myPrivateKey: serverPersistentPrivateKey, host: host, port: port, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey)
        }
        catch
        {
            print("ShadowSwift: received an invalid client confirmation code 🕳. \(error)")
            let _ = AsyncBlackHole(timeoutDelaySeconds: 30, socket: connection)
            throw AsyncDarkstarServerError.blackHoled
        }

        // Send server ephemeral key
        guard let (serverEphemeralPrivateKey, _) = try? await AsyncDarkstar.handleServerEphemeralKey(connection: connection) else
        {
            print("ShadowSwift: Failed to send the server ephemeral key 🕳.")
            let _ = AsyncBlackHole(timeoutDelaySeconds: 30, socket: connection)
            throw AsyncDarkstarServerError.blackHoled
        }

        // Create shared key
        guard let serverToClientSharedKey = try? AsyncDarkstarServer.createServerToClientSharedKey(serverPersistentPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey, host: host, port: port) else
        {
            print("ShadowSwift: Failed to create serverToClientSharedKey 🕳.")
            let _ = AsyncBlackHole(timeoutDelaySeconds: 30, socket: connection)
            throw AsyncDarkstarServerError.blackHoled
        }

        self.serverToClientSharedKey = serverToClientSharedKey

        guard let clientToServerSharedKey = try? AsyncDarkstarServer.createClientToServerSharedKey(serverPersistentPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey, host: host, port: port) else
        {
            print("ShadowSwift: Failed to create clientToServerSharedKey 🕳.")
            let _ = AsyncBlackHole(timeoutDelaySeconds: 30, socket: connection)
            throw AsyncDarkstarServerError.blackHoled
        }

        self.clientToServerSharedKey = clientToServerSharedKey

        // Send server confirmation code
        do
        {
            try await AsyncDarkstarServer.handleServerConfirmationCode(connection: connection, host: host, port: port, serverStaticPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey)
        }
        catch
        {
            print("ShadowSwift: Failed to send the server confirmation code 🕳. \(error)")
            let _ = AsyncBlackHole(timeoutDelaySeconds: 30, socket: connection)
            throw AsyncDarkstarServerError.blackHoled
        }
    }

    static public func handleServerConfirmationCode(connection: AsyncConnection, host: String, port: Int, serverStaticPrivateKey: PrivateKey, serverEphemeralPrivateKey: PrivateKey, clientEphemeralPublicKey: PublicKey) async throws
    {
        let ecdh = try serverStaticPrivateKey.sharedSecretFromKeyAgreement(with: clientEphemeralPublicKey)
        let ecdhData = AsyncDarkstar.sharedSecretToData(secret: ecdh)
        let serverIdentifier = try AsyncDarkstar.makeServerIdentifier(host, port)
        let serverPersistentPublicKeyData = serverStaticPrivateKey.publicKey.data!
        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.data!

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverPersistentPublicKeyData)
        hash.update(data: clientEphemeralPublicKeyData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ServerString.data)
        let result = hash.finalize()

        let data = Data(result)

        try await connection.write(data)
    }

    static public func handleClientConfirmationCode(connection: AsyncConnection, theirPublicKey: PublicKey, myPrivateKey: PrivateKey, host: String, port: Int, serverPersistentPublicKey: PublicKey, clientEphemeralPublicKey: PublicKey) async throws
    {
        let data = try await connection.readSize(ConfirmationSize)
        let code = try generateClientConfirmationCode(connection: connection, theirPublicKey: theirPublicKey, myPrivateKey: myPrivateKey, host: host, port: port, serverPersistentPublicKey: serverPersistentPublicKey, clientEphemeralPublicKey: clientEphemeralPublicKey)

        guard data == code else
        {
            throw AsyncDarkstarServerError.codesDoNotMatch(code, data)
        }
    }

    static public func generateClientConfirmationCode(connection: AsyncConnection, theirPublicKey: PublicKey, myPrivateKey:PrivateKey, host: String, port: Int, serverPersistentPublicKey: PublicKey, clientEphemeralPublicKey: PublicKey) throws -> Data
    {
        let ecdh = try myPrivateKey.sharedSecretFromKeyAgreement(with: theirPublicKey)
        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)
        let serverIdentifier = try AsyncDarkstar.makeServerIdentifier(host, port)

        guard let serverPersistentPublicKeyData = serverPersistentPublicKey.data else
        {
            throw AsyncDarkstarServerError.keyToDataFailed
        }

        guard let clientEphemeralPublicKeyData = clientEphemeralPublicKey.data else
        {
            throw AsyncDarkstarServerError.keyToDataFailed
        }

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

    static public func createServerToClientSharedKey(serverPersistentPrivateKey: PrivateKey, serverEphemeralPrivateKey: PrivateKey, clientEphemeralPublicKey: PublicKey, host: String, port: Int) throws -> SymmetricKey
    {
        return try createServerSharedKey(serverPersistentPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey, host: host, port: port, personalizationString: ClientString)
    }

    static public func createClientToServerSharedKey(serverPersistentPrivateKey: PrivateKey, serverEphemeralPrivateKey: PrivateKey, clientEphemeralPublicKey: PublicKey, host: String, port: Int) throws -> SymmetricKey
    {
        return try createServerSharedKey(serverPersistentPrivateKey: serverPersistentPrivateKey, serverEphemeralPrivateKey: serverEphemeralPrivateKey, clientEphemeralPublicKey: clientEphemeralPublicKey, host: host, port: port, personalizationString: ServerString)
    }

    static func createServerSharedKey(serverPersistentPrivateKey: PrivateKey, serverEphemeralPrivateKey: PrivateKey, clientEphemeralPublicKey: PublicKey, host: String, port: Int, personalizationString: String) throws -> SymmetricKey
    {
        let ephemeralECDH = try serverEphemeralPrivateKey.sharedSecretFromKeyAgreement(with: clientEphemeralPublicKey)
        let ephemeralECDHData = DarkStar.sharedSecretToData(secret: ephemeralECDH)
        let persistentECDH = try serverPersistentPrivateKey.sharedSecretFromKeyAgreement(with: clientEphemeralPublicKey)
        let persistentECDHData = DarkStar.sharedSecretToData(secret: persistentECDH)
        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.data!
        let serverEphemeralPublicKey = serverEphemeralPrivateKey.publicKey
        let serverEphemeralPublicKeyData = serverEphemeralPublicKey.data!
        let serverIdentifier = try AsyncDarkstar.makeServerIdentifier(host, port)

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
}

public enum AsyncDarkstarServerError: Error
{
    case codesDoNotMatch(Data, Data)
    case keyToDataFailed
    case blackHoled
}

