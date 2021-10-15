//
//  ShadowTests.swift
//  ShadowTests
//
//  Created by Mafalda on 8/3/20.
//

import XCTest
import Logging

import Datable
import SwiftHexTools

#if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS))
import CryptoKit
import Network
#else
import Crypto
import NetworkLinux
#endif

import XCTest
@testable import ShadowSwift

class ShadowSwiftTests: XCTestCase
{
    let logger: Logger = Logger(label: "Shadow Logger")
    let testIPString = "159.203.158.90"
    let testPort: UInt16 = 2345
    let plainText = Data(array: [0, 1, 2, 3, 4])

    override static func setUp()
    {
        LoggingSystem.bootstrap(StreamLogHandler.standardError)
    }
    
    func testShadowConnection()
    {
        let connected = expectation(description: "Connection callback called")
        //let sent = expectation(description: "TCP data sent")
        
        let host = NWEndpoint.Host(testIPString)
        guard let port = NWEndpoint.Port(rawValue: testPort)
            else
        {
            XCTFail()
            return
        }
        
        let logger = Logger(label: "Shadow Logger")

        let shadowConfig = ShadowConfig(password: "1234", mode: .CHACHA20_IETF_POLY1305)
        
        let shadowFactory = ShadowConnectionFactory(host: host, port: port, config: shadowConfig, logger: logger)
        
        guard var shadowConnection = shadowFactory.connect(using: .tcp)
            else
        {
            XCTFail()
            return
        }
        
        shadowConnection.stateUpdateHandler =
        {
            state in
            
            switch state
            {
            case NWConnection.State.ready:
                logger.info("\nConnected state ready\n")
                connected.fulfill()
            default:
                logger.debug("\nReceived a state other than ready: \(state)\n")
                return
            }
        }
        
        shadowConnection.start(queue: .global())
        
        //let godot = expectation(description: "forever")
        wait(for: [connected], timeout: 3000)
    }
    
    func testShadowSend()
    {
        let shadowQueue = DispatchQueue(label: "ShadowQueue")
        let connected = expectation(description: "Connection callback called")
        let sent = expectation(description: "TCP data sent")
        
        let host = NWEndpoint.Host(testIPString)
        guard let port = NWEndpoint.Port(rawValue: testPort)
            else
        {
            XCTFail()
            return
        }
        
        let logger = Logger(label: "Shadow Logger")

        let shadowConfig = ShadowConfig(password: "1234", mode: .CHACHA20_IETF_POLY1305)
        
        let shadowFactory = ShadowConnectionFactory(host: host, port: port, config: shadowConfig, logger: logger)
        
        guard var shadowConnection = shadowFactory.connect(using: .tcp)
            else
        {
            XCTFail()
            return
        }
        
        shadowConnection.stateUpdateHandler =
        {
            state in
            
            switch state
            {
            case NWConnection.State.ready:
                connected.fulfill()
                
                shadowConnection.send(content: Data("1234"), contentContext: .defaultMessage, isComplete: true, completion: NWConnection.SendCompletion.contentProcessed(
                {
                    (maybeError) in
                    
                    if let sendError = maybeError
                    {
                        logger.error("Send Error: \(sendError)")
                        XCTFail()
                        return
                    }
                    
                    sent.fulfill()
                }))
            default:
                logger.debug("\nReceived a state other than ready: \(state)\n")
                return
            }
        }
        
        shadowConnection.start(queue: shadowQueue)
        
        //let godot = expectation(description: "forever")
        wait(for: [connected, sent], timeout: 3000)
    }
    
    func testShadowReceive()
    {
        let connected = expectation(description: "Connection callback called")
        let sent = expectation(description: "TCP data sent")
        let received = expectation(description: "TCP data received")
        let serverListening = expectation(description: "Server is listening")
        let serverNewConnectionReceived = expectation(description: "Server received a new connection")
        let serverReceivedData = expectation(description: "Server received a message")
        let serverResponded = expectation(description: "Server responded to a message")
        let serverReceived2 = expectation(description: "Server received a 2nd message")
        let serverResponded2 = expectation(description: "Server responded to a 2nd message")
        
        DispatchQueue.main.async {
            self.runTestServer(listening: serverListening,
                               connectionReceived: serverNewConnectionReceived,
                               dataReceived: serverReceivedData,
                               responseSent: serverResponded,
                               dataReceived2: serverReceived2,
                               responseSent2: serverResponded2)
        }
        
        wait(for: [serverListening], timeout: 20)

        let host = NWEndpoint.Host(testIPString)
        guard let port = NWEndpoint.Port(rawValue: testPort)
            else
        {
            XCTFail()
            return
        }
        
        let logger = Logger(label: "Shadow Logger")
        let shadowConfig = ShadowConfig(password: "1234", mode: .CHACHA20_IETF_POLY1305)
        let shadowFactory = ShadowConnectionFactory(host: host, port: port, config: shadowConfig, logger: logger)
        
        guard var shadowConnection = shadowFactory.connect(using: .tcp)
            else
        {
            XCTFail()
            return
        }
        
        shadowConnection.stateUpdateHandler =
        {
            state in
            
            switch state
            {
            case NWConnection.State.ready:
                logger.info("\nConnected state ready\n")
                connected.fulfill()
                
                shadowConnection.send(content: Data("GET / HTTP/1.0\r\n\r\n"), contentContext: .defaultMessage, isComplete: true, completion: NWConnection.SendCompletion.contentProcessed(
                {
                    (maybeError) in
                    
                    if let sendError = maybeError
                    {
                        logger.error("Send Error: \(sendError)")
                        XCTFail()
                        return
                    }
                    
                    sent.fulfill()
                    
                    shadowConnection.receive(minimumIncompleteLength: 4, maximumLength: 4)
                    {
                        (maybeData, maybeContext, isComplete, maybeReceiveError) in
                        
                        if let receiveError = maybeReceiveError
                        {
                            logger.error("Got a receive error \(receiveError)")
                            //XCTFail()
                            //return
                        }
                        
                        if maybeData != nil
                        {
                            logger.info("Received data!!")
                            received.fulfill()
                        }
                    }
                }))
            default:
                logger.debug("\nReceived a state other than ready: \(state)\n")
                return
            }
        }
        
        shadowConnection.start(queue: .global())
        
        //let godot = expectation(description: "forever")
        wait(for: [connected, sent, received, serverNewConnectionReceived, serverReceivedData, serverResponded], timeout: 15)
    }
    
    func testShadowReceiveSendTwice()
    {
        let connected = expectation(description: "Connection callback called")
        let sent = expectation(description: "TCP data sent")
        let received = expectation(description: "TCP data received")
        let sent2 = expectation(description: "2nd Send")
        let received2 = expectation(description: "2nd Received")
        
        let serverListening = expectation(description: "Server is listening")
        let serverNewConnectionReceived = expectation(description: "Server received a new connection")
        let serverReceivedData = expectation(description: "Server received a message")
        let serverReceived2 = expectation(description: "Server received 2nd message")
        let serverResponded = expectation(description: "Server responded to a message")
        let serverResponded2 = expectation(description: "Server responded a 2nd time")
        
        DispatchQueue.main.async {
            self.runTestServer(listening: serverListening,
                               connectionReceived: serverNewConnectionReceived,
                               dataReceived: serverReceivedData,
                               responseSent: serverResponded,
                               dataReceived2: serverReceived2,
                               responseSent2: serverResponded2)
        }
        
        wait(for: [serverListening], timeout: 20)

        let host = NWEndpoint.Host(testIPString)
        guard let port = NWEndpoint.Port(rawValue: testPort)
            else
        {
            XCTFail()
            return
        }
        
        let shadowConfig = ShadowConfig(password: "1234", mode: .CHACHA20_IETF_POLY1305)
        let shadowFactory = ShadowConnectionFactory(host: host, port: port, config: shadowConfig, logger: logger)
        
        guard var shadowConnection = shadowFactory.connect(using: .tcp)
            else
        {
            XCTFail()
            return
        }
        
        shadowConnection.stateUpdateHandler =
        {
            state in
            
            switch state
            {
            case NWConnection.State.ready:
                    self.logger.info("\nConnected state ready\n")
                connected.fulfill()
                
                shadowConnection.send(content: Data("1234"), contentContext: .defaultMessage, isComplete: true, completion: NWConnection.SendCompletion.contentProcessed(
                {
                    (maybeError) in
                    
                    if let sendError = maybeError
                    {
                        self.logger.error("Send Error: \(sendError)")
                        XCTFail()
                        return
                    }
                    
                    sent.fulfill()
                    
                    shadowConnection.receive(minimumIncompleteLength: 4, maximumLength: 4)
                    {
                        (maybeData, maybeContext, isComplete, maybeReceiveError) in
                        
                        if let receiveError = maybeReceiveError
                        {
                            self.logger.error("Got a receive error \(receiveError)")
                            //XCTFail()
                            //return
                        }
                        
                        if maybeData != nil
                        {
                            self.logger.info("Received data!!")
                            received.fulfill()
                            
                            shadowConnection.send(content: "Send2", contentContext: .defaultMessage, isComplete: false, completion: NWConnection.SendCompletion.contentProcessed(
                            {
                                (maybeSendError) in
                                
                                if let sendError = maybeSendError
                                {
                                    self.logger.error("Error on 2nd send: \(sendError)")
                                    XCTFail()
                                    return
                                }
                                
                                sent2.fulfill()
                                
                                shadowConnection.receive(minimumIncompleteLength: 11, maximumLength: 11)
                                {
                                    (maybeData, _, _, maybeError) in
                                    
                                    if let error = maybeError
                                    {
                                        self.logger.error("Error on 2nd receive: \(error)")
                                        XCTFail()
                                    }
                                    
                                    if let data = maybeData
                                    {
                                        if data.string == "ServerSend2"
                                        {
                                            received2.fulfill()
                                        }
                                    }
                                }
                            }))
                        }
                    }
                }))
            default:
                    self.logger.debug("\nReceived a state other than ready: \(state)\n")
                return
            }
        }
        
        shadowConnection.start(queue: .global())
        
        //let godot = expectation(description: "forever")
        wait(for: [connected, sent, received, serverNewConnectionReceived, serverReceivedData, serverResponded, sent2, received2, serverReceived2, serverResponded2], timeout: 15)
    }
    
    func runTestServer(listening: XCTestExpectation,
                       connectionReceived: XCTestExpectation,
                       dataReceived: XCTestExpectation,
                       responseSent: XCTestExpectation,
                       dataReceived2: XCTestExpectation,
                       responseSent2: XCTestExpectation)
    {
        do
        {
            let listener = try NWListener(using: .tcp, on: NWEndpoint.Port(integerLiteral: 3333))
            listener.newTransportConnectionHandler =
            {
                (connection) in
                
                var newConnection = connection
                newConnection.stateUpdateHandler =
                {
                    (connectionState) in
                    
                    switch connectionState
                    {
                    case .ready:
                        connection.receive(minimumIncompleteLength: 4, maximumLength: 4)
                        {
                            (maybeData, _, _, maybeReceiveError) in
                            
                            if maybeReceiveError != nil
                            {
                                return
                            }
                            
                            guard let receivedData = maybeData
                            else
                            {
                                return
                            }
                            
                            dataReceived.fulfill()
                            
                            if receivedData.string == "1234"
                            {
                                connection.send(content: "Okay".data, contentContext: .defaultMessage, isComplete: true, completion: NWConnection.SendCompletion.contentProcessed(
                                {
                                    (maybeSendError) in
                                    
                                    if maybeSendError != nil
                                    {
                                        return
                                    }
                                    else
                                    {
                                        responseSent.fulfill()
                                        
                                        connection.receive(minimumIncompleteLength: 5, maximumLength: 5)
                                        {
                                            (maybeData, _, _, maybeError) in
                                            
                                            if maybeError != nil
                                            {
                                                XCTFail()
                                                return
                                            }
                                            
                                            if let data = maybeData
                                            {
                                                if data.string == "Send2"
                                                {
                                                    dataReceived2.fulfill()
                                                    
                                                    connection.send(content: "ServerSend2", contentContext: .defaultMessage, isComplete: false, completion: NWConnection.SendCompletion.contentProcessed(
                                                    { (maybeError) in
                                                        if maybeError != nil
                                                        {
                                                            return
                                                        }
                                                        
                                                        responseSent2.fulfill()
                                                    }))
                                                }
                                            }
                                        }
                                    }
                                    
                                }))
                            }
                        }
                        
                    default:
return                        }
                }
                
                newConnection.start(queue: .global())
                connectionReceived.fulfill()
            }
            
            listener.start(queue: .global())
            listening.fulfill()
        }
        catch _
        {
            return
        }
    }
    
    func testJSONConfig()
    {
        let shadowConfig = ShadowConfig(password: "password", mode: .CHACHA20_IETF_POLY1305)
        let encoder = JSONEncoder()
        let json = try? encoder.encode(shadowConfig)
        
        let filePath = "/Users/mafalda/Documents/Operator/Canary/Sources/Resources/Configs/shadowsockscopy.json"
        FileManager.default.createFile(atPath: filePath, contents: json)
        
        
        guard let _ = ShadowConfig(path:filePath )
        else
        {
            XCTFail()
            return
        }
    }
}

