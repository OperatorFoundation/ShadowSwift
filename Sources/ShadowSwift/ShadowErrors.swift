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
