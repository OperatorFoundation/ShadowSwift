//
//  ShadowConnection.swift
//  Shadow
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

import Crypto
import Foundation
import Logging

import Chord
import Datable
import Net
import SwiftHexTools
import Transmission
import Transport

open class DarkStarRetryingClientConnection: Transport.Connection
{
    public struct RetryConfig
    {
        let host: NWEndpoint.Host
        let port: NWEndpoint.Port
        let parameters: NWParameters
        let config: ShadowConfig
        let logger: Logger
    }
    
    var retryConfig: RetryConfig
    
    public var stateUpdateHandler: ((NWConnection.State) -> Void)?
    {
        get
        {
            guard let handler = network.stateUpdateHandler else
            {
                return nil
            }
            
            return handler
        }
        
        set
        {
            network.stateUpdateHandler = newValue
        }
    }
    
    public var viabilityUpdateHandler: ((Bool) -> Void)?
    {
        get
        {
            guard let handler = network.viabilityUpdateHandler else
            {
                return nil
            }
            
            return handler
        }
        
        set
        {
            network.viabilityUpdateHandler = newValue
        }
    }
    
    var network: DarkStarClientConnection
    var networkClosed = false

    public init?(host: NWEndpoint.Host, port: NWEndpoint.Port, parameters: NWParameters, config: ShadowConfig, logger: Logger)
    {
        guard let newDarkStarConnection = DarkStarClientConnection(host: host, port: port, parameters: parameters, config: config, logger: logger) else
        {
            return nil
        }
        
        self.retryConfig = RetryConfig(host: host, port: port, parameters: parameters, config: config, logger: logger)
        self.network = newDarkStarConnection
    }

    // MARK: Connection Protocol

    public func start(queue: DispatchQueue)
    {
        network.start(queue: queue)
    }

    public func cancel()
    {
        if !networkClosed
        {
            networkClosed = true
            network.cancel()
        }
    }

    /// Gets content and encrypts it before passing it along to the network
    public func send(content: Data?, contentContext: NWConnection.ContentContext, isComplete: Bool, completion: NWConnection.SendCompletion)
    {
        network.send(content: content, contentContext: contentContext, isComplete: isComplete, completion: completion)
    }

    // Decrypts the received content before passing it along
    public func receive(completion: @escaping (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)
    {
        self.receive(minimumIncompleteLength: 1, maximumLength: Cipher.maxPayloadSize, completion: completion)
    }


    public func receive(minimumIncompleteLength: Int,
                        maximumLength: Int,
                        completion: @escaping (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void)
    {
        network.receive(minimumIncompleteLength: minimumIncompleteLength, maximumLength: maximumLength)
        {
            (maybeData, maybeContext, isComplete, maybeError) in
            
            if let error = maybeError
            {
                switch error
                {
                    case .posix(let posixErrorCode):
                        switch posixErrorCode
                        {
                            case .EBADF:
                                guard let newConnection = DarkStarClientConnection(host: self.retryConfig.host, port: self.retryConfig.port, parameters: self.retryConfig.parameters, config: self.retryConfig.config, logger: self.retryConfig.logger) else
                                {
                                    completion(maybeData, maybeContext, isComplete, error)
                                    return
                                }
                                
                                self.network = newConnection
                                
                            default:
                                completion(maybeData, maybeContext, isComplete, error)
                        }
                    default:
                        completion(maybeData, maybeContext, isComplete, error)
                }
            }
            else
            {
                completion(maybeData, maybeContext, isComplete, maybeError)
            }
        }
    }
}
