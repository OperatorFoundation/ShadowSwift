//
//  ShadowConnectionFactory.swift
//  Shapeshifter-Swift-Transports
//
//  Created by Mafalda on 8/3/20.
//  MIT License
//
//  Copyright (c) 2020 Operator Foundation
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import Foundation
import Logging

import Net
import Transport

open class ShadowConnectionFactory: ConnectionFactory
{
    var log: Logger
    
    public var name = "Shadow"
    public var config: ShadowConfig
    public var connection: Connection?
    public var host: NWEndpoint.Host?
    public var port: NWEndpoint.Port?

    public init(config: ShadowConfig, logger: Logger)
    {
        self.host = NWEndpoint.Host(config.serverIP)
        self.port = NWEndpoint.Port(rawValue: config.port)
        self.config = config
        self.log = logger
    }

    public convenience init?(url: URL, serverid: UUID, logger: Logger)
    {
        guard let jsonConfig = JsonConfig(url: url) else {return nil}
        self.init(jsonConfig: jsonConfig, serverid: serverid, logger: logger)
    }

    public convenience init?(path: String, serverid: UUID, logger: Logger)
    {
        guard let jsonConfig = JsonConfig(path: path) else {return nil}
        self.init(jsonConfig: jsonConfig, serverid: serverid, logger: logger)
    }

    init?(jsonConfig: JsonConfig, serverid: UUID, logger: Logger)
    {
        self.log = logger

        let maybeServerConfig = jsonConfig.servers.first
        {
            (config: ServerConfig) -> Bool in

            return config.id == serverid.uuidString
        }
        guard let serverConfig = maybeServerConfig else {return nil}
        guard let shadowConfig = serverConfig.shadowConfig else {return nil}
        self.config = shadowConfig

        self.host = NWEndpoint.Host(serverConfig.server)
        self.port = NWEndpoint.Port(integerLiteral: UInt16(serverConfig.server_port))
    }
    
    public func connect(using parameters: NWParameters) -> Connection?
    {
        guard let currentHost = self.host, let currentPort = self.port else
        {
            log.error("Failed to connect as ShadowConnectionFactory does not have a valid endpoint.")
            return nil
        }

        guard config.mode == .DARKSTAR else
        {
            log.error("Unable to make a shadow connection using \(config.mode.rawValue). Currently only DarkStar is supported.")
            return nil
        }

        return DarkStarConnection(host: currentHost, port: currentPort, parameters: parameters, config: config, isClient: true, logger: log)
    }
}
