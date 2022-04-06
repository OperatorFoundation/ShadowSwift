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
    var bloomFilter: BloomFilter<Data>
    
    // TODO: Ask how to pursue the closing
    public func close()
    {
        listener.close()
    }
    
    let config: ShadowConfig
    var log: Logger

    let listener: Transmission.Listener
    let endpoint: NWEndpoint

    public init?(host: String, port: Int, config: ShadowConfig, logger: Logger)
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
            logger.error("Unable to initialize a Shadow Server \(host) is not a valid IPV4 address.")
            return nil
        }
                                                  
        self.endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host.ipv4(ipv4Address), port: NWEndpoint.Port(integerLiteral: UInt16(port)))

        guard let listener = TransmissionListener(port: port, logger: nil) else {return nil}
        self.listener = listener
        
        guard let supportDirectoryURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else
        {
            logger.error("Could not get application support directory path.")
            return nil
        }
        
        let bloomFilterPath = supportDirectoryURL.path + "/" + "BloomFilter"
        
        guard let newBloomFilter = BloomFilter<Data>(withFileAtPath: bloomFilterPath) else
        {
            logger.error("Failed to initialize ShadowServer: Unabale to create a BloomFilter with the file at \(bloomFilterPath)")
            return nil
        }
        
        self.bloomFilter = newBloomFilter
    }

    public func accept() throws -> Transmission.Connection
    {
        let connection = try self.listener.accept()

        guard let shadow = DarkStarServerConnection(connection: connection, endpoint: self.endpoint, parameters: .tcp, config: self.config, bloomFilter: self.bloomFilter, logger: self.log) else
        {
            let transport = TransmissionToTransportConnection({return connection})
            
            let _ = BlackHole(timeoutDelaySeconds: 30, socket: transport)
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
                    return "We failed to create a DarkStar connection."
                case .transportToTransmissionError:
                    return "We failed to convert the DarkStar transport connection to a Transmission connection."
            }
        }
    }
}
