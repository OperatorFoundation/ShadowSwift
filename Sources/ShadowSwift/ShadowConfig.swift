//
//  ShadowConfig.swift
//  Shadow
//
//  Created by Mafalda on 8/18/20.
//

import Crypto
import Foundation

import KeychainTypes

public class ShadowConfig
{
    public struct ShadowServerConfig: Codable
    {
        public static let serverConfigFilename = "ShadowServerConfig.json"
        public let serverAddress: String
        public let serverPrivateKey: PrivateKey
        public let mode: CipherMode
        public var transportName = "shadow"
        
        private enum CodingKeys : String, CodingKey
        {
            case serverAddress, serverPrivateKey, mode = "cipherName", transportName = "transport"
        }
        
        public init(serverAddress: String, serverPrivateKey: PrivateKey, mode: CipherMode)
        {
            self.serverAddress = serverAddress
            self.serverPrivateKey = serverPrivateKey
            self.mode = mode
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
        public static let clientConfigFilename = "ShadowClientConfig.json"
        public let serverAddress: String
        public let serverPublicKey: PublicKey
        public let mode: CipherMode
        public var transportName = "shadow"
        
        private enum CodingKeys : String, CodingKey
        {
            case serverAddress, serverPublicKey, mode = "cipherName", transportName = "transport"
        }
        
        public init(serverAddress: String, serverPublicKey: PublicKey, mode: CipherMode)
        {
            self.serverAddress = serverAddress
            self.serverPublicKey = serverPublicKey
            self.mode = mode
        }
        
        public init?(from data: Data)
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

    public static func generateNewConfigPair(serverAddress: String, cipher: CipherMode) throws -> (serverConfig: ShadowServerConfig, clientConfig: ShadowClientConfig)
    {
        let privateKey = try PrivateKey(type: .P256KeyAgreement)
        let publicKey = privateKey.publicKey

        let serverConfig = ShadowServerConfig(serverAddress: serverAddress, serverPrivateKey: privateKey, mode: cipher)
        let clientConfig = ShadowClientConfig(serverAddress: serverAddress, serverPublicKey: publicKey, mode: cipher)
        
        return (serverConfig, clientConfig)
    }

    // FIXME: Make this function signature more Swifty (return types)
    public static func createNewConfigFiles(inDirectory saveDirectory: URL, serverAddress: String, cipher: CipherMode) -> (saved: Bool, error: Error?)
    {
        guard saveDirectory.isDirectory else
        {
            return(false, ShadowConfigError.urlIsNotDirectory)
        }

        do
        {
            let configPair = try ShadowConfig.generateNewConfigPair(serverAddress: serverAddress, cipher: cipher)

            let encoder = JSONEncoder()
            let serverJson = try encoder.encode(configPair.serverConfig)
            let serverConfigFilePath = saveDirectory.appendingPathComponent(ShadowServerConfig.serverConfigFilename).path
            guard FileManager.default.createFile(atPath: serverConfigFilePath, contents: serverJson) else
            {
                return (false, ShadowConfigError.failedToSaveFile(filePath: serverConfigFilePath))
            }

            let clientJson = try encoder.encode(configPair.clientConfig)
            
            let clientConfigFilePath = saveDirectory.appendingPathComponent(ShadowClientConfig.clientConfigFilename).path

            guard FileManager.default.createFile(atPath: clientConfigFilePath, contents: clientJson) else
            {
                return (false, ShadowConfigError.failedToSaveFile(filePath: clientConfigFilePath))
            }

            return (true, nil)
        }
        catch
        {
            print(error)
            return (false, error)
        }
    }

}
