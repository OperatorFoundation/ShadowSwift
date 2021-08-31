//
//  ShadowConfig.swift
//  Shadow
//
//  Created by Mafalda on 8/18/20.
//

import Foundation

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS))
import CryptoKit
#else
import Crypto
#endif

public struct ShadowConfig: Codable
{
    public let password: String
    public let mode: CipherMode
    
    private enum CodingKeys : String, CodingKey
    {
        case password, mode = "cipherName"
    }
    
    public init(password: String, mode: CipherMode)
    {
        self.password = password
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
