//
//  Crypto+CustomStringConvertible.swift
//  
//
//  Created by Dr. Brandon Wiley on 4/19/22.
//

import Crypto
import Foundation
import SwiftHexTools

extension AES.GCM.Nonce: CustomStringConvertible
{
    public var description: String
    {
        let data = Data(self)
        return data.hex
    }
}

extension SymmetricKey: CustomStringConvertible
{
    public var description: String
    {
        self.withUnsafeBytes
        {
            bytes in

            let data = Data(bytes)
            return data.hex
        }
    }
}

extension P256.KeyAgreement.PrivateKey: CustomStringConvertible
{
    public var description: String
    {
        return self.rawRepresentation.hex
    }
}

extension P256.KeyAgreement.PublicKey: CustomStringConvertible
{
    public var description: String
    {
        return self.compactRepresentation!.hex
    }
}

extension P256.Signing.PrivateKey: CustomStringConvertible
{
    public var description: String
    {
        return self.rawRepresentation.hex
    }
}

extension P256.Signing.PublicKey: CustomStringConvertible
{
    public var description: String
    {
        return self.compactRepresentation!.hex
    }
}
