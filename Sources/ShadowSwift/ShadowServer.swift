//
//  File.swift
//  
//
//  Created by Dr. Brandon Wiley on 10/14/21.
//

import Foundation
import Logging

import Net
import Transmission
import TransmissionTransport
import Transport

public class ShadowServer: Transmission.Listener
{
    let config: ShadowConfig.ShadowServerConfig
    var log: Logger

    let listener: Transmission.Listener
    let endpoint: NWEndpoint
    let bloomFilterURL: URL

    public init?(host: String, port: Int, config: ShadowConfig.ShadowServerConfig, logger: Logger, bloomFilterURL: URL)
    {
        if host == "0.0.0.0"
        {
            logger.error("Shadow Server does not allow '0.0.0.0' as a bindhost you must use the actual server IP.")
            return nil
        }
        
        self.config = config
        self.log = logger
        
        guard let ipv4Address = IPv4Address(host) else
        {
            logger.error("Failed to start the Shadow server: \(host) is not a valid IPV4 address.")
            return nil
        }
                                                  
        self.endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host.ipv4(ipv4Address), port: NWEndpoint.Port(integerLiteral: UInt16(port)))

        guard let listener = TransmissionListener(port: port, logger: nil) else
        {
            logger.error("Failed to start the Shadow server: we were unable to get a Transmission listener.")
            return nil
        }
        
        self.listener = listener
        self.bloomFilterURL = bloomFilterURL
    }
    
    public convenience init?(host: String, port: Int, config: ShadowConfig.ShadowServerConfig, logger: Logger)
    {
        guard let supportDirectoryURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else
        {
            logger.error("Failed to start the Shadow server: we could not get application support directory path.")
            return nil
        }
        
        let bloomURL = supportDirectoryURL.appendingPathComponent(bloomFilterFilename)
        
        self.init(host: host, port: port, config: config, logger: logger, bloomFilterURL: bloomURL)
    }

    public func accept() throws -> Transmission.Connection
    {
        let connection = try self.listener.accept()

        guard let shadow = DarkStarServerConnection(connection: connection, endpoint: self.endpoint, parameters: .tcp, config: self.config, logger: self.log, bloomFilterURL: self.bloomFilterURL) else
        {
            log.error("ShadowServer.Error: incoming connection cannot be used to create a DarkStarServerConnection.")
            throw ShadowServerError.darkStarConnectionError
        }
        
        guard let transmissionConnection = TransportToTransmissionConnection(shadow) else
        {
            log.error("ShadowServer.Error: incoming DarkStarServerConnection could not be used to create a TransmissionConnection.")
            throw ShadowServerError.transportToTransmissionError
        }
        
        return transmissionConnection
    }
    
    public func close()
    {
        listener.close()
    }
    
    enum ShadowServerError: LocalizedError
    {
        case darkStarConnectionError
        case transportToTransmissionError
        
        var errorDescription: String?
        {
            switch self
            {
                case .darkStarConnectionError:
                    return "We failed to create a DarkStar connection."
                case .transportToTransmissionError:
                    return "We failed to convert the DarkStar transport connection to a Transmission connection."
            }
        }
    }
}
