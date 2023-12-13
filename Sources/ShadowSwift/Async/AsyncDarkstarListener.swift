//
//  AsyncDarkstarListener.swift
//  
//
//  Created by Dr. Brandon Wiley on 7/7/23.
//

import Foundation
import Logging

import TransmissionAsync

public class AsyncDarkstarListener: AsyncListener
{
    let host: String?
    let port: Int
    let config: ShadowConfig.ShadowServerConfig
    let logger: Logger
    let networkListener: AsyncListener

    public init(config: ShadowConfig.ShadowServerConfig, logger: Logger, verbose: Bool = false) throws
    {
        self.host = config.serverIP
        self.port = Int(config.serverPort)
        self.config = config
        self.logger = logger
        self.networkListener = try AsyncTcpSocketListener(host: self.host, port: self.port, self.logger, verbose: verbose)
    }

    public func accept() async throws -> AsyncConnection
    {
        let network = try await networkListener.accept()
        return try await AsyncDarkstarServerConnection(network, self.config, self.logger)
    }

    public func close() async throws
    {
        try await self.networkListener.close()
    }
}

public enum AsyncDarkstarListenerError: Error
{
    case badServerAddress(String)
}
