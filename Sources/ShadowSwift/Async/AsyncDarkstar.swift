//
//  AsyncDarkstar.swift
//  
//
//  Created by Dr. Brandon Wiley on 7/6/23.
//

import Foundation

//
//  File.swift
//
//
//  Created by Dr. Brandon Wiley on 9/24/21.
//
import Crypto

import Datable
import Foundation
import KeychainTypes
import Net
import TransmissionAsync

let AsyncP256KeySize = 32 // compact format

public struct AsyncDarkstar
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
    static public func generateServerConfirmationCode(theirPublicKey: PublicKey, myPrivateEphemeralKey: PrivateKey, myPrivateStaticKey: PrivateKey, endpoint: NWEndpoint) throws -> Data
    {
        guard let ecdh = try? myPrivateStaticKey.sharedSecretFromKeyAgreement(with: theirPublicKey) else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }

        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else
        {
            throw AsyncDarkstarError.failedToMakeServerIdentifier
        }

        guard let serverPersistentPublicKeyKeychainData = myPrivateStaticKey.publicKey.data else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }
        let serverPersistentPublicKeyCryptoKit = try P256.KeyAgreement.PublicKey(rawRepresentation: serverPersistentPublicKeyKeychainData)
        guard let serverPersistentPublicKeyDarkstarData = serverPersistentPublicKeyCryptoKit.compactRepresentation else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }

        guard let clientEphemeralPublicKeyKeychainData = theirPublicKey.data else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }
        let clientEphemeralPublicKeyCryptoKit = try P256.KeyAgreement.PublicKey(rawRepresentation: clientEphemeralPublicKeyKeychainData)
        guard let clientEphemeralPublicKeyDarkstarData = clientEphemeralPublicKeyCryptoKit.compactRepresentation else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverPersistentPublicKeyDarkstarData)
        hash.update(data: clientEphemeralPublicKeyDarkstarData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ServerString.data)
        let result = hash.finalize()

        return Data(result)
    }
#else
    static public func generateServerConfirmationCode(theirPublicKey: P256.KeyAgreement.PublicKey, myPrivateEphemeralKey: P256.KeyAgreement.PrivateKey, myPrivateStaticKey: P256.KeyAgreement.PrivateKey, endpoint: NWEndpoint) -> Data?
    {
        guard let ecdh = try? myPrivateStaticKey.sharedSecretFromKeyAgreement(with: theirPublicKey) else
        {
            print("Darkstar: Failed to generate the shared secret.")
            return nil
        }

        let ecdhData = DarkStar.sharedSecretToData(secret: ecdh)

        guard let serverIdentifier = DarkStar.makeServerIdentifier(endpoint) else
        {
            print("Darkstar: Failed to generate the server identifier.")
            return nil
        }

        guard let serverPersistentPublicKeyDarkstarData = myPrivateStaticKey.publicKey.compactRepresentation else
        {
            print("Darkstar: Failed to generate the serverPersistentPublicKey data.")
            return nil
        }

        guard let clientEphemeralPublicKeyDarkstarData = theirPublicKey.compactRepresentation else
        {
            print("Darkstar: Failed to generate the clientEphemeralPublicKey data.")
            return nil
        }

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverPersistentPublicKeyDarkstarData)
        hash.update(data: clientEphemeralPublicKeyDarkstarData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ServerString.data)
        let result = hash.finalize()

        return Data(result)
    }
#endif


    static public func handleServerEphemeralKey(connection: AsyncConnection) async throws -> (PrivateKey, PublicKey)
    {
        let myEphemeralPrivateKey = DarkStar.generateEvenKey()
        let myEphemeralPublicKey = myEphemeralPrivateKey.publicKey

        guard let myEphemeralPublicKeyData = myEphemeralPublicKey.compactRepresentation else
        {
            print("Darkstar.handleServerEphemeralKey: failed to generate a compact representation of our public key")
            throw AsyncDarkstarError.keyAgreementFailed
        }

        try await connection.write(myEphemeralPublicKeyData)

        let keychainPrivate = try KeychainTypes.PrivateKey(type: .P256KeyAgreement, data: myEphemeralPrivateKey.x963Representation)
        let keychainPublic = try KeychainTypes.PublicKey(type: .P256KeyAgreement, data: myEphemeralPublicKey.x963Representation)

        return (keychainPrivate, keychainPublic)
    }

    static public func handleClientEphemeralKey(connection: AsyncConnection) async throws -> (PrivateKey, PublicKey)
    {
        let myEphemeralPrivateKey = DarkStar.generateEvenKey()
        let myEphemeralPublicKey = myEphemeralPrivateKey.publicKey

        guard let myEphemeralPublicKeyData = myEphemeralPublicKey.compactRepresentation else
        {
            print("Darkstar.handleServerEphemeralKey: failed to generate a compact representation of our public key")
            throw AsyncDarkstarError.keyAgreementFailed
        }

        try await connection.write(myEphemeralPublicKeyData)

        let keychainPrivate = try KeychainTypes.PrivateKey(type: .P256KeyAgreement, data: myEphemeralPrivateKey.rawRepresentation)
        let keychainPublic = try KeychainTypes.PublicKey(type: .P256KeyAgreement, data: myEphemeralPublicKey.rawRepresentation)

        return (keychainPrivate, keychainPublic)
    }

    static public func generateClientConfirmationCode(connection: AsyncConnection, theirPublicKey: PublicKey, myPrivateKey: PrivateKey, host: String, port: Int, serverPersistentPublicKey: PublicKey, clientEphemeralPublicKey: PublicKey) throws -> Data
    {
        let ecdh = try myPrivateKey.sharedSecretFromKeyAgreement(with: theirPublicKey)
        let ecdhData = AsyncDarkstar.sharedSecretToData(secret: ecdh)

        let serverIdentifier = try AsyncDarkstar.makeServerIdentifier(host, port)

        guard let serverPersistentPublicKeyKeychainData = serverPersistentPublicKey.data else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }
        let serverPersistentPublicKeyCryptoKit = try P256.KeyAgreement.PublicKey(rawRepresentation: serverPersistentPublicKeyKeychainData)
        guard let serverPersistentPublicKeyDarkstarData = serverPersistentPublicKeyCryptoKit.compactRepresentation else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }

        guard let clientEphemeralPublicKeyKeychainData = clientEphemeralPublicKey.data else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }
        let clientEphemeralPublicKeyCryptoKit = try P256.KeyAgreement.PublicKey(rawRepresentation: clientEphemeralPublicKeyKeychainData)
        guard let clientEphemeralPublicKeyDarkstarData = clientEphemeralPublicKeyCryptoKit.compactRepresentation else
        {
            throw AsyncDarkstarError.keyAgreementFailed
        }

        var hash = SHA256()
        hash.update(data: ecdhData)
        hash.update(data: serverIdentifier)
        hash.update(data: serverPersistentPublicKeyDarkstarData)
        hash.update(data: clientEphemeralPublicKeyDarkstarData)
        hash.update(data: DarkStarString.data)
        hash.update(data: ClientString.data)
        let result = hash.finalize()

        return Data(result)
    }

    static public func handleTheirEphemeralPublicKey(connection: AsyncConnection, bloomFilter: BloomFilter<Data>?) async throws -> PublicKey
    {
        // Receive their ephemeral key
        print("AsyncDarkstar - Attempting to read client key data...")
        let theirEphemeralPublicKeyData = try await connection.readSize(P256KeySize)
        print("AsyncDarkstar - Read \(theirEphemeralPublicKeyData.count) bytes of client key data.")

        if let bloomFilter = bloomFilter // Server
        {
            // See if theirEphemeralPublicKeyData is in the BloomFilter, return nil if it is.
            if bloomFilter.contains(theirEphemeralPublicKeyData)
            {
                throw AsyncDarkstarError.bloomFilterTriggered
            }
            // If it's not in a BloomFilter, add it to the BloomFilter and Save the BloomFilter
            else
            {
                bloomFilter.insert(theirEphemeralPublicKeyData)

                if let bloomFilterURL = bloomFilter.getBloomFileURL()
                {
                    let filterSaved = bloomFilter.save(pathURL: bloomFilterURL)
                    if !filterSaved
                    {
                        print("Warning: Failed to save the updated BloomFilter")
                    }
                }
                else
                {
                    print("Warning: Unable to save BloomFilter. Unabale to resolve the directory URL.")
                }
            }
        }
        
        let cryptoKitKey = try P256.KeyAgreement.PublicKey(compactRepresentation: theirEphemeralPublicKeyData)
        
        return try PublicKey(type: .P256KeyAgreement, data: cryptoKitKey.x963Representation)
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

    static func makeServerIdentifier(_ host: String, _ port: Int) throws -> Data
    {
        guard let portData = UInt16(port).maybeNetworkData else
        {
            throw AsyncDarkstarError.numberToDataConversionFailed
        }

        let array = host.split(separator: ".").map { UInt8(string: String($0)) }
        let ipv4Data = Data(array: array)
        return ipv4Data + portData
    }
}

public enum AsyncDarkstarError: Error
{
    case numberToDataConversionFailed
    case keyAgreementFailed
    case failedToMakeServerIdentifier
    case bloomFilterTriggered
}
