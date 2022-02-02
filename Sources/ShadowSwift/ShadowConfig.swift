//
//  ShadowConfig.swift
//  Shadow
//
//  Created by Mafalda on 8/18/20.
//

import Foundation

import Crypto

public struct ShadowConfig: Codable
{
    public let key: String
    public let serverIP: String
    public let port: UInt16
    public let mode: CipherMode
    
    private enum CodingKeys : String, CodingKey
    {
        case key, serverIP, port, mode = "cipherName"
    }
    
    public init(key: String, serverIP: String, port: UInt16, mode: CipherMode)
    {
        self.key = key
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
            return nil
        }        
    }
    
}
