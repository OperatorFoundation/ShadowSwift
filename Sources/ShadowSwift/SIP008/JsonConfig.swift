//
//  JsonConfig.swift
//  
//
//  Created by Dr. Brandon Wiley on 1/6/22.
//
// Provides support for Shadowsocks SIP008 - Online Configuration Delivery
// https://shadowsocks.org/en/wiki/SIP008-Online-Configuration-Delivery.html
//
// Example config:
//{
//    "version": 1,
//    "servers": [
//        {
//            // Server UUID to distinguish between servers when updating.
//            "id": "27b8a625-4f4b-4428-9f0f-8a2317db7c79",
//            "remarks": "Name of the server",
//            "server": "example.com",
//            "server_port": 8388,
//            "password": "example",
//            "method": "chacha20-ietf-poly1305",
//            "plugin": "xxx",
//            "plugin_opts": "xxxxx"
//        },
//        // Another server
//        {
//            "id": "7842c068-c667-41f2-8f7d-04feece3cb67",
//            "remarks": "Name of the server",
//            "server": "example.com",
//            "server_port": 8388,
//            "password": "example",
//            "method": "chacha20-ietf-poly1305",
//            "plugin": "xxx",
//            "plugin_opts": "xxxxx"
//        }
//    ],
//    // The above fields are mandatory.
//    // Optional fields for data usage:
//    "bytes_used": 274877906944,
//    "bytes_remaining": 824633720832
//    // You may add other custom fields in the root object.
//}

import Foundation

import Datable
import KeychainTypes

public struct JsonConfig: Codable
{
    let version: Int
    let servers: [ServerConfig]
}

public struct ServerConfig: Codable
{
    let id: String
    let server: String
    let server_port: UInt16
    let password: String
    let method: String
}

extension JsonConfig
{
    public init?(url: URL)
    {
        // "Delivery of an SIP008 JSON document must use HTTPS as the transport protocol. Clients must not ignore certificate issues or TLS handshake errors to protect against TLS MITM attacks. The web server should be configured to only use modern TLS versions to avoid week encryption and protect against TLS downgrade attacks. Plain HTTP can only be used for debugging purposes. Clients may display a warning message or reject it when a plain HTTP link is used."
        guard url.scheme == "https" else {return nil}

        guard let data = try? Data(contentsOf: url) else {return nil}

        let decoder = JSONDecoder()
        do
        {
            let result = try decoder.decode(JsonConfig.self, from: data)
            self = result
        }
        catch
        {
            print("Failed to decode a JSON config: \(error)")
            return nil
        }
    }

    public init?(path: String)
    {
        let url = URL(fileURLWithPath: path)

        guard let data = try? Data(contentsOf: url) else {return nil}

        let decoder = JSONDecoder()
        guard let result = try? decoder.decode(JsonConfig.self, from: data) else {return nil}
        self = result
    }
}

extension ServerConfig
{
    public var shadowConfig: ShadowConfig.ShadowServerConfig?
    {
        guard let mode = CipherMode(rawValue: self.method) else
        {
            return nil
        }

        guard let serverPrivateKeyData = Data(base64: self.password) else
        {
            return nil
        }

        do
        {
            let serverPrivateKey = try PrivateKey(type: .P256KeyAgreement, data: serverPrivateKeyData)
            return try ShadowConfig.ShadowServerConfig(serverAddress: "\(server):\(server_port)", serverPrivateKey: serverPrivateKey, mode: mode)
        }
        catch
        {
            // print(error)
            return nil
        }
    }
}
