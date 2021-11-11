//
//  File.swift
//  
//
//  Created by Dr. Brandon Wiley on 10/14/21.
//

import Foundation
import Network
import Logging
import Transmission
import Transport

public class ShadowServer
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

    public func accept() -> Transport.Connection?
    {
        let connection = self.listener.accept()

        if self.config.mode == .DARKSTAR_SERVER
        {
            let shadow = DarkStarConnection(connection: connection, endpoint: self.endpoint, parameters: .tcp, config: self.config, logger: self.log)
            return shadow
        }
        else
        {
            let shadow = ShadowConnection(connection: connection, parameters: .tcp, config: self.config, logger: self.log)
            return shadow
        }
    }
}
