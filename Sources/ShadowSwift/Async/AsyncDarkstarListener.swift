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

    public convenience init(config: ShadowConfig.ShadowServerConfig, logger: Logger) throws
    {
        let asyncTcpSocketListener = try AsyncTcpSocketListener(host: config.serverIP, port: Int(config.serverPort), logger)
        self.init(config: config, listener: asyncTcpSocketListener, logger: logger)
    }
    
    public init(config: ShadowConfig.ShadowServerConfig, listener: AsyncListener, logger: Logger)
    {
        self.host = config.serverIP
        self.port = Int(config.serverPort)
        self.config = config
        self.logger = logger
        self.networkListener = listener
    }

    public func accept() async throws -> AsyncConnection
    {
        let network = try await networkListener.accept()
        logger.debug("AsyncDarkstarListener accepted a new connection.")
        
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
