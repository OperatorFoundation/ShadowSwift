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
import Keychain
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

        let serverPersistentPublicKeyData = myPrivateStaticKey.publicKey.data!
        let clientEphemeralPublicKeyData = theirPublicKey.data!

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


    static public func handleServerEphemeralKey(connection: AsyncConnection) async throws -> (PrivateKey, PublicKey)
    {
        let myEphemeralPrivateKey = try PrivateKey(type: .P256KeyAgreement)
        let myEphemeralPublicKey = myEphemeralPrivateKey.publicKey
        let myEphemeralPublicKeyData = myEphemeralPublicKey.data!

        try await connection.write(myEphemeralPublicKeyData)

        return (myEphemeralPrivateKey, myEphemeralPublicKey)
    }

    static public func handleClientEphemeralKey(connection: AsyncConnection) async throws -> (PrivateKey, PublicKey)
    {
        let myEphemeralPrivateKey = try PrivateKey(type: .P256KeyAgreement)
        let myEphemeralPublicKey = myEphemeralPrivateKey.publicKey
        let myEphemeralPublicKeyData = myEphemeralPublicKey.data!

        try await connection.write(myEphemeralPublicKeyData)

        return (myEphemeralPrivateKey, myEphemeralPublicKey)
    }

    static public func generateClientConfirmationCode(connection: AsyncConnection, theirPublicKey: PublicKey, myPrivateKey: PrivateKey, host: String, port: Int, serverPersistentPublicKey: PublicKey, clientEphemeralPublicKey: PublicKey) throws -> Data
    {
        let ecdh = try myPrivateKey.sharedSecretFromKeyAgreement(with: theirPublicKey)
        let ecdhData = AsyncDarkstar.sharedSecretToData(secret: ecdh)

        let serverIdentifier = try AsyncDarkstar.makeServerIdentifier(host, port)

        let serverPersistentPublicKeyData = serverPersistentPublicKey.data!
        let clientEphemeralPublicKeyData = clientEphemeralPublicKey.data!

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

    static public func handleTheirEphemeralPublicKey(connection: AsyncConnection, bloomFilter: BloomFilter<Data>?) async throws -> PublicKey
    {
        // Receive their ephemeral key
        let theirEphemeralPublicKeyData = try await connection.readSize(P256KeySize)

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

        return try PublicKey(type: .P256KeyAgreement, data: theirEphemeralPublicKeyData)
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
