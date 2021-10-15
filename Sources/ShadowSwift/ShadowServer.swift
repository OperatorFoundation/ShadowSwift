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

public class ShadowServer
{
    let config: ShadowConfig
    var log: Logger

    let listener: Listener

    public init?(host: String, port: Int, config: ShadowConfig, logger: Logger)
    {
        self.config = config
        self.log = logger

        guard let listener = Listener(port: port) else {return nil}
        self.listener = listener
    }

    public func accept() -> ShadowConnection?
    {
        let connection = self.listener.accept()
        let shadow = ShadowConnection(connection: connection, parameters: .tcp, config: self.config, logger: self.log)
        return shadow
    }
}
