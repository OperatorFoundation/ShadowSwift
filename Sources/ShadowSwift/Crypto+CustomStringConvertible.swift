//
//  Crypto+CustomStringConvertible.swift
//  
//
//  Created by Dr. Brandon Wiley on 4/19/22.
//

import Crypto
import Foundation

extension AES.GCM.Nonce: CustomStringConvertible
{
    public var description: String
    {
        let data = Data(self)
        return data.base64EncodedString()
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
            return data.base64EncodedString()
        }
    }
}

extension P256.KeyAgreement.PrivateKey: CustomStringConvertible
{
    public var description: String
    {
        return self.rawRepresentation.base64EncodedString()
    }
}

extension P256.KeyAgreement.PublicKey: CustomStringConvertible
{
    public var description: String
    {
        return self.compactRepresentation!.base64EncodedString()
    }
}

extension P256.Signing.PrivateKey: CustomStringConvertible
{
    public var description: String
    {
        return self.rawRepresentation.base64EncodedString()
    }
}

extension P256.Signing.PublicKey: CustomStringConvertible
{
    public var description: String
    {
        return self.compactRepresentation!.base64EncodedString()
    }
}
