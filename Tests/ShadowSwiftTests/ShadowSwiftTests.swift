//
//  ShadowTests.swift
//  ShadowTests
//
//  Created by Mafalda on 8/3/20.
//

import XCTest
import Logging

import Crypto
import Datable
import SwiftHexTools
import Chord
import Net

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
        
        let _ = NWEndpoint.Host(testIPString)
        guard let _ = NWEndpoint.Port(rawValue: testPort)
            else
        {
            XCTFail()
            return
        }
        
        let logger = Logger(label: "Shadow Logger")
        let shadowConfig = ShadowConfig(key: "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6", serverIP: testIPString, port: testPort, mode: .DARKSTAR)
        
        let shadowFactory = ShadowConnectionFactory(config: shadowConfig, logger: logger)
        
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
        
        let _ = NWEndpoint.Host(testIPString)
        guard let _ = NWEndpoint.Port(rawValue: testPort)
            else
        {
            XCTFail()
            return
        }
        
        let logger = Logger(label: "Shadow Logger")

        let shadowConfig = ShadowConfig(key: "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6", serverIP: testIPString, port: testPort, mode: .DARKSTAR)
        
        let shadowFactory = ShadowConnectionFactory(config: shadowConfig, logger: logger)
        
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

        let _ = NWEndpoint.Host(testIPString)
        guard let _ = NWEndpoint.Port(rawValue: testPort)
            else
        {
            XCTFail()
            return
        }
        
        let logger = Logger(label: "Shadow Logger")
        let shadowConfig = ShadowConfig(key: "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6", serverIP: testIPString, port: testPort, mode: .DARKSTAR)
        let shadowFactory = ShadowConnectionFactory(config: shadowConfig, logger: logger)
        
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

        let _ = NWEndpoint.Host(testIPString)
        guard let _ = NWEndpoint.Port(rawValue: testPort)
            else
        {
            XCTFail()
            return
        }
        
        let shadowConfig = ShadowConfig(key: "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6", serverIP: testIPString, port: testPort, mode: .DARKSTAR)
        let shadowFactory = ShadowConnectionFactory(config: shadowConfig, logger: logger)
        
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
        let shadowConfig = ShadowConfig(key: "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6", serverIP: testIPString, port: testPort, mode: .DARKSTAR)
        let encoder = JSONEncoder()
        let json = try? encoder.encode(shadowConfig)
        
        let filePath = ""
        FileManager.default.createFile(atPath: filePath, contents: json)
        
        
        guard let _ = ShadowConfig(path:filePath )
        else
        {
            XCTFail()
            return
        }
    }

    func testDarkStarServer()
    {
//        let privateKey = P256.KeyAgreement.PrivateKey()
//        let privateKeyData = privateKey.derRepresentation
//        let privateKeyHex = privateKeyData.hex
        let privateKeyHex = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104204a6a7e6c9d15527905d58ef98aa59e2a81a3804f4d40ed1a219db6668d0c42fca144034200044ed5d754928698e5f73de6ff22feb516e146b7fd1a0e6ca466ccb77e2cc324bf3deb2b4df4d7583b521ecd466f37e84b8f7930482ca2a0d18baffd353fb207fd"
        guard let privateKeyBytes = Data(hex: privateKeyHex) else {return}
        guard let privateKey = try? P256.KeyAgreement.PrivateKey(derRepresentation: privateKeyBytes) else {return}
        let publicKey = privateKey.publicKey

        let publicKeyData = publicKey.compactRepresentation!
        let publicKeyHex = publicKeyData.hex
        print(publicKeyHex)

        guard let server = ShadowServer(host: "127.0.0.1", port: 1234, config: ShadowConfig(key: privateKeyHex, serverIP: "127.0.0.1", port: 1234, mode: .DARKSTAR), logger: self.logger) else {return}

        let queue = DispatchQueue(label: "Client")
        queue.async
        {
            guard let connection = server.accept() else {return}
            connection.send(content: "test\n".data, contentContext: NWConnection.ContentContext.defaultMessage, isComplete: true, completion: .contentProcessed({ maybeError in
                print("Sent!")
            }))
        }

        let factory = ShadowConnectionFactory(config: ShadowConfig(key: publicKeyHex, serverIP: "127.0.0.1", port: 1234, mode: .DARKSTAR), logger: self.logger)
        guard var client = factory.connect(using: .tcp) else {return}

        client.stateUpdateHandler={
            state in

            switch state
            {
                case .ready:
                    print("Ready!")
                default:
                    return
            }
        }
        let queue2 = DispatchQueue(label: "Client")
        client.start(queue: queue2)
    }

    func testDarkStarOnlyServer()
    {
        //        let privateKey = P256.KeyAgreement.PrivateKey()
        //        let privateKeyData = privateKey.derRepresentation
        //        let privateKeyHex = privateKeyData.hex
        let sent = XCTestExpectation(description: "Sent!")
        
        let privateKeyHex = "dd5e9e88d13e66017eb2087b128c1009539d446208f86173e30409a898ada148"
        guard let privateKeyBytes = Data(hex: privateKeyHex) else {
            XCTFail()
            return
        }
        guard let privateKey = try? P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyBytes) else {
            XCTFail()
            return
        }
        let publicKey = privateKey.publicKey

        let publicKeyData = publicKey.compactRepresentation!
        let publicKeyHex = publicKeyData.hex
        print(publicKeyHex)

        guard let server = ShadowServer(host: "127.0.0.1", port: 1234, config: ShadowConfig(key: privateKeyHex, serverIP: "127.0.0.1", port: 1234, mode: .DARKSTAR), logger: self.logger) else {
            XCTFail()
            return
        }

        guard let connection = server.accept() else {
            XCTFail()
            return
        }
        connection.send(content: "test\n".data, contentContext: NWConnection.ContentContext.defaultMessage, isComplete: true, completion: .contentProcessed({ maybeError in
            print("Sent!")
            sent.fulfill()
            }))
        wait(for: [sent], timeout: 30)  // 30 seconds
    }
    
    func testDarkStarClientOnly()
    {
        let ready = XCTestExpectation(description: "Ready!")
        
        let publicKeyData = Data(hex: "d089c225ef8cda8d477a586f062b31a756270124d94944e458edf1a9e1e41ed6")
        let publicKeyHex = publicKeyData!.hex
        print(publicKeyHex)
        
        let factory = ShadowConnectionFactory(config: ShadowConfig(key: publicKeyHex, serverIP: "127.0.0.1", port: 1234, mode: .DARKSTAR), logger: self.logger)
        guard var client = factory.connect(using: .tcp) else {return}

        client.stateUpdateHandler={
            state in

            switch state
            {
                case .ready:
                    print("Ready!")
                    ready.fulfill()
                default:
                    return
            }
        }
        let queue2 = DispatchQueue(label: "Client")
        client.start(queue: queue2)
        wait(for: [ready], timeout: 30)  // 30 seconds
    }

    func testGenerateKeys()
    {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let privateKeyData = privateKey.x963Representation
        let privateKeyHex = privateKeyData.hex

        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.compactRepresentation
        let publicKeyHex = publicKeyData!.hex

        print("Private key: \(privateKeyHex)")
        print("Public key: \(publicKeyHex)")
    }

    func testSIP008()
    {
        let ready = XCTestExpectation(description: "Ready!")
        
        guard let url = URL(string: "https://raw.githubusercontent.com/OperatorFoundation/ShadowSwift/main/Tests/ShadowSwiftTests/testsip008.json") else
        {
            XCTFail()
            return
        }
        guard let serverid = UUID(uuidString: "27b8a625-4f4b-4428-9f0f-8a2317db7c79") else
        {
            XCTFail()
            return
        }

        guard let factory = ShadowConnectionFactory(url: url, serverid: serverid, logger: self.logger) else
        {
            XCTFail()
            return
        }

        guard var client = factory.connect(using: .tcp) else {return}

        client.stateUpdateHandler={
            state in

            switch state
            {
                case .ready:
                    print("Ready!")
                    ready.fulfill()
                default:
                    return
            }
        }
        let queue2 = DispatchQueue(label: "Client")
        client.start(queue: queue2)
        wait(for: [ready], timeout: 30)  // 30 seconds
    }

    public func testULong()
    {
        let uint64 = UInt64.max
        let int64 = Int64(bitPattern: uint64)
        print(uint64)
        print(int64)
    }
}

