//
//  AsyncDarkstarListener.swift
//  
//
//  Created by Dr. Brandon Wiley on 7/7/23.
//

import Foundation
#if os(macOS)
import os.log
#else
import Logging
#endif

import TransmissionAsync

public class AsyncDarkstarListener: AsyncListener
{
    let host: String?
    let port: Int
    let config: ShadowConfig.ShadowServerConfig
    let logger: Logger
    let networkListener: AsyncListener

    public init(config: ShadowConfig.ShadowServerConfig, logger: Logger) throws
    {
        let parts = config.serverAddress.split(separator: ".")
        guard parts.count == 2 else
        {
            throw AsyncDarkstarListenerError.badServerAddress(config.serverAddress)
        }

        let host = String(parts[0])

        guard let port = Int(String(parts[1])) else
        {
            throw AsyncDarkstarListenerError.badServerAddress(config.serverAddress)
        }

        self.host = host
        self.port = port
        self.config = config
        self.logger = logger
        self.networkListener = try AsyncTcpSocketListener(host: self.host, port: self.port, self.logger)
    }

    public func accept() async throws -> AsyncConnection
    {
        let network = try await networkListener.accept()
        return try await AsyncDarkstarServerConnection(network, self.config, self.logger)
    }
}

public enum AsyncDarkstarListenerError: Error
{
    case badServerAddress(String)
}
