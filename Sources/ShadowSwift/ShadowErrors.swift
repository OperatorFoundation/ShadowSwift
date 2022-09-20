//
//  ShadowErrors.swift
//  Shadow
//
//  Created by Mafalda on 8/26/20.
//

import Foundation

enum ShadowError: Error
{
    case failedToUnpackLength
    case failedToDecodeLength
    case failedToEncrypt
    case failedToDecrypt
}

enum ShadowConfigError: Error
{
    case urlIsNotDirectory
    case failedToSaveFile(filePath: String)
    
    public var description: String
    {
        switch self
        {
            case .urlIsNotDirectory:
                return "The provided URL is not a directory."
            case .failedToSaveFile(let filePath):
                return "Failed to save the config file to \(filePath)"
        }
    }
}
