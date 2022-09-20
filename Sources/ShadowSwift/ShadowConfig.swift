//
//  ShadowConfig.swift
//  Shadow
//
//  Created by Mafalda on 8/18/20.
//

import Crypto
import Foundation

public struct ShadowConfig: Codable
{
    public let password: String
    public let serverIP: String
    public let port: UInt16
    public let mode: CipherMode
    
    private enum CodingKeys : String, CodingKey
    {
        case password, serverIP, port, mode = "cipherName"
    }
    
    public init(key: String, serverIP: String, port: UInt16, mode: CipherMode)
    {
        self.password = key
        self.serverIP = serverIP
        self.port = port
        self.mode = mode
    }
    
    init?(from data: Data)
    {
        let decoder = JSONDecoder()
        do
        {
            let decoded = try decoder.decode(ShadowConfig.self, from: data)
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
    
    static func generateNewConfigPair(serverIP: String, serverPort: UInt16) -> (serverConfig: ShadowConfig, clientConfig: ShadowConfig)
    {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let privateKeyData = privateKey.rawRepresentation
        let privateKeyHex = privateKeyData.hex

        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.compactRepresentation
        let publicKeyHex = publicKeyData!.hex

        print("Server Key: \(privateKeyHex)")
        print("Client Key: \(publicKeyHex)")
        
        let serverConfig = ShadowConfig(key: privateKeyHex, serverIP: serverIP, port: serverPort, mode: .DARKSTAR)
        let clientConfig = ShadowConfig(key: publicKeyHex, serverIP: serverIP, port: serverPort, mode: .DARKSTAR)
        
        return (serverConfig, clientConfig)
    }
    
    public static func createNewConfigFiles(inDirectory saveDirectory: URL, serverIP: String, serverPort: UInt16) -> (saved: Bool, error: Error?)
    {
        guard saveDirectory.isDirectory else
        {
            return(false, ShadowConfigError.urlIsNotDirectory)
        }
        
        let configPair = ShadowConfig.generateNewConfigPair(serverIP: serverIP, serverPort: serverPort)
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
