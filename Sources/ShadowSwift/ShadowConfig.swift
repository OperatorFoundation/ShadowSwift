//
//  ShadowConfig.swift
//  Shadow
//
//  Created by Mafalda on 8/18/20.
//

import Crypto
import Foundation
public class ShadowConfig {
    public struct ShadowServerConfig: Codable
    {
        public let serverAddress: String
        public let serverPrivateKey: String
        public let mode: CipherMode
        public let transport: String
        
        private enum CodingKeys : String, CodingKey
        {
            case serverAddress, serverPrivateKey, mode = "cipherName", transport
        }
        
        public init(serverAddress: String, serverPrivateKey: String, mode: CipherMode, transport: String)
        {
            self.serverAddress = serverAddress
            self.serverPrivateKey = serverPrivateKey
            self.mode = mode
            self.transport = transport
        }
        
        init?(from data: Data)
        {
            let decoder = JSONDecoder()
            do
            {
                let decoded = try decoder.decode(ShadowServerConfig.self, from: data)
                self = decoded
            }
            catch
            {
                print("Error received while attempting to decode a ShadowConfig json file: \(error)")
                return nil
            }
        }
        
        public init?(path: String)
        {
            let url = URL(fileURLWithPath: path)
            
            do
            {
                let data = try Data(contentsOf: url)
                self.init(from: data)
            }
            catch
            {
                print("Error decoding Shadow config file: \(error)")
                
                return nil
            }
        }
    }
    
    public struct ShadowClientConfig: Codable
    {
        public let serverAddress: String
        public let serverPublicKey: String
        public let mode: CipherMode
        public let transport: String
        
        private enum CodingKeys : String, CodingKey
        {
            case serverAddress, serverPublicKey, mode = "cipherName", transport
        }
        
        public init(serverAddress: String, serverPublicKey: String, mode: CipherMode, transport: String)
        {
            self.serverAddress = serverAddress
            self.serverPublicKey = serverPublicKey
            self.mode = mode
            self.transport = transport
        }
        
        init?(from data: Data)
        {
            let decoder = JSONDecoder()
            do
            {
                let decoded = try decoder.decode(ShadowClientConfig.self, from: data)
                self = decoded
            }
            catch
            {
                print("Error received while attempting to decode a ShadowConfig json file: \(error)")
                return nil
            }
        }
        
        public init?(path: String)
        {
            let url = URL(fileURLWithPath: path)
            
            do
            {
                let data = try Data(contentsOf: url)
                self.init(from: data)
            }
            catch
            {
                print("Error decoding Shadow config file: \(error)")
                
                return nil
            }
        }
    }

    public static func generateNewConfigPair(serverAddress: String, cipher: CipherMode) -> (serverConfig: ShadowServerConfig, clientConfig: ShadowClientConfig)
    {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let privateKeyData = privateKey.rawRepresentation
        let privateKeyString = privateKeyData.base64EncodedString()

        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.compactRepresentation
        let publicKeyString = publicKeyData!.base64EncodedString()

        print("Server Key: \(privateKeyString)")
        print("Client Key: \(publicKeyString)")
        
        let serverConfig = ShadowServerConfig(serverAddress: serverAddress, serverPrivateKey: privateKeyString, mode: cipher, transport: "shadow")
        let clientConfig = ShadowClientConfig(serverAddress: serverAddress, serverPublicKey: publicKeyString, mode: cipher, transport: "shadow")
        
        return (serverConfig, clientConfig)
    }

    public static func createNewConfigFiles(inDirectory saveDirectory: URL, serverAddress: String, cipher: CipherMode) -> (saved: Bool, error: Error?)
    {
        guard saveDirectory.isDirectory else
        {
            return(false, ShadowConfigError.urlIsNotDirectory)
        }
        
        let configPair = ShadowConfig.generateNewConfigPair(serverAddress: serverAddress, cipher: cipher)
        let encoder = JSONEncoder()
        
        do
        {
            let serverJson = try encoder.encode(configPair.serverConfig)
            let serverConfigFilename = "ShadowServerConfig.json"
            let serverConfigFilePath = saveDirectory.appendingPathComponent(serverConfigFilename).path
            guard FileManager.default.createFile(atPath: serverConfigFilePath, contents: serverJson) else
            {
                return (false, ShadowConfigError.failedToSaveFile(filePath: serverConfigFilePath))
            }
            
            let clientJson = try encoder.encode(configPair.clientConfig)
            let clientConfigFilename = "ShadowClientConfig.json"
            let clientConfigFilePath = saveDirectory.appendingPathComponent(clientConfigFilename).path
            
            guard FileManager.default.createFile(atPath: clientConfigFilePath, contents: clientJson) else
            {
                return (false, ShadowConfigError.failedToSaveFile(filePath: clientConfigFilePath))
            }
            
            return (true, nil)
        }
        catch
        {
            return(false, error)
        }
    }

}
