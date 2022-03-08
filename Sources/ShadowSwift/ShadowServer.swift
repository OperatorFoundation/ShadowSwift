//
//  File.swift
//  
//
//  Created by Dr. Brandon Wiley on 10/14/21.
//

import Foundation
import Net
import Logging

import Transmission
import Transport
import TransmissionTransport

public class ShadowServer: Transmission.Listener
{
    let config: ShadowConfig
    var log: Logger

    let listener: Transmission.Listener
    let endpoint: NWEndpoint

    public init?(host: String, port: Int, config: ShadowConfig, logger: Logger)
    {
        self.config = config
        self.log = logger

        self.endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host.ipv4(IPv4Address(host)!), port: NWEndpoint.Port(integerLiteral: UInt16(port)))

        guard let listener = TransmissionListener(port: port, logger: nil) else {return nil}
        self.listener = listener
    }

    public func accept() throws -> Transmission.Connection
    {
        let connection = try self.listener.accept()

        guard let shadow = DarkStarConnection(connection: connection, endpoint: self.endpoint, parameters: .tcp, config: self.config, isClient: false, logger: self.log) else
        {
            throw ShadowServerError.darkStarConnectionError
        }
        
        guard let transmissionConnection = TransportToTransmissionConnection(shadow) else
        {
            throw ShadowServerError.transportToTransmissionError
        }
        
        return transmissionConnection
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
                    return "We to create a DarkStar connection."
                case .transportToTransmissionError:
                    return "We failed to convert the DarkStar transport connection to a Transmission connection."
            }
        }
    }
}
