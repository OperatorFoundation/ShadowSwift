//
//  ShadowTests.swift
//  ShadowTests
//
//  Created by Mafalda on 8/3/20.
//

import Crypto
import XCTest

#if os(macOS) || os(iOS)
import os.log
#else
import Logging
#endif

import Datable
import Chord
import KeychainTypes
import Net
import Transmission

import XCTest
@testable import ShadowSwift

class ShadowSwiftTests: XCTestCase
{
#if os(macOS) || os(iOS)
    let logger: Logger = Logger()
#else
    let logger: Logger = Logger(label: "Shadow Logger")
#endif
    
    let testIPString = ""
    let testPort: UInt16 = 2345
    let plainText = Data(array: [0, 1, 2, 3, 4])

#if os(Linux)
    override static func setUp()
    {
        LoggingSystem.bootstrap(StreamLogHandler.standardError)
    }
#endif
    
    func testDarkStarClientOnly() throws
    {
        let ready = XCTestExpectation(description: "Ready!")
        let sent = XCTestExpectation(description: "Sent!")
        let received = XCTestExpectation(description: "Received")
        
        // TODO: Enter your server public key.
        let publicKeyString = "6LukZ8KqZLQ7eOdaTVFkBVqMA8NS1AUxwqG17L/kHnQ="
        guard let publicKeyData = Data(base64: publicKeyString) else
        {
            XCTFail()
            return
        }

        let publicKey = try PublicKey(type: .P256KeyAgreement, data: publicKeyData)
        
        // TODO: Enter your server IP and Port.
        let shadowConfig = ShadowConfig.ShadowClientConfig(serverAddress: "127.0.0.1:1234", serverPublicKey: publicKey, mode: .DARKSTAR)
        let shadowFactory = ShadowConnectionFactory(config: shadowConfig, logger: self.logger)
        let httpRequestData = Data("GET / HTTP/1.0\r\nConnection: close\r\n\r\n")
        print(">>>>>> Created a Shadow connection factory.")
        
        guard var shadowClientConnection = shadowFactory.connect(using: .tcp) else
        {
            XCTFail()
            return
        }
        print(">>>>>> Created a Shadow Client connection .")

        shadowClientConnection.stateUpdateHandler =
        {
            state in

            switch state
            {
                case .ready:
                    print(">>>>>> Shadow Client connection is ready.")
                    ready.fulfill()
                    shadowClientConnection.send(content: httpRequestData, contentContext: .defaultMessage, isComplete: true, completion: NWConnection.SendCompletion.contentProcessed(
                    {
                        maybeError in
                        
                        if let error = maybeError
                        {
                            print(">>>>>> shadowClientConnection received an error on send: \(error)")
                            XCTFail()
                            return
                        }
                        else
                        {
                            sent.fulfill()
                            print(">>>>>> shadowClientConnection successfully sent data to the server.")
                            
                            shadowClientConnection.receive(minimumIncompleteLength: 2, maximumLength: 10)
                            {
                                maybeData, maybeContext, isComplete, maybeReceiveError in
                                
                                if let error = maybeReceiveError
                                {
                                    print(">>>>>> shadowClientConnection received an error on receive: \(error)")
                                    XCTFail()
                                    return
                                }
                                else
                                {
                                    guard let receivedData = maybeData else
                                    {
                                        print(">>>>>> Shadow client received a nil data response.")
                                        XCTFail()
                                        return
                                    }
                                    
                                    let receivedString = receivedData.string
                                    print(">>>>>> shadowClientConnection received some data from the server:\n\(receivedString)")
                                    
                                    XCTAssertTrue(receivedString.contains("Yeah!"))
                                    received.fulfill()
                                }
                            }
                        }
                    }))
                default:
                    XCTFail()
                    return
            }
        }
        let queue2 = DispatchQueue(label: "Client")
        shadowClientConnection.start(queue: queue2)
        
        wait(for: [ready, sent, received], timeout: 60)  // 30 seconds
    }
    
    
    func testConfigFromFile()
    {
        guard ShadowConfig.ShadowServerConfig(path: FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Desktop/Configs/shadowsocksPrivateKey.json").path) != nil else
        {
            XCTFail()
            return
        }
    }
    
    func testShadowConnection() throws
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

        let publicKeyString = "6LukZ8KqZLQ7eOdaTVFkBVqMA8NS1AUxwqG17L/kHnQ="
        guard let publicKeyData = Data(base64: publicKeyString) else
        {
            XCTFail()
            return
        }

        let publicKey = try PublicKey(type: .P256KeyAgreement, data: publicKeyData)
        
        let shadowConfig = ShadowConfig.ShadowClientConfig(serverAddress: "127.0.0.1:1234", serverPublicKey: publicKey, mode: .DARKSTAR)
        
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
            default:
                    let logString = "\nReceived a state other than ready: \(state)\n"
                    self.logger.debug("\(logString)")
                return
            }
        }
        
        shadowConnection.start(queue: .global())
        
        //let godot = expectation(description: "forever")
        wait(for: [connected], timeout: 3000)
    }
    
    func testShadowSend() throws
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

        let publicKeyString = "6LukZ8KqZLQ7eOdaTVFkBVqMA8NS1AUxwqG17L/kHnQ="
        guard let publicKeyData = Data(base64: publicKeyString) else
        {
            XCTFail()
            return
        }

        let publicKey = try PublicKey(type: .P256KeyAgreement, data: publicKeyData)

        let shadowConfig = ShadowConfig.ShadowClientConfig(serverAddress: "127.0.0.1:1234", serverPublicKey: publicKey, mode: .DARKSTAR)
        
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
                        self.logger.error("Send Error: \(sendError)")
                        XCTFail()
                        return
                    }
                    
                    sent.fulfill()
                }))
            default:
                    let logString = "\nReceived a state other than ready: \(state)\n"
                    self.logger.debug("\(logString)")
                return
            }
        }
        
        shadowConnection.start(queue: shadowQueue)
        
        //let godot = expectation(description: "forever")
        wait(for: [connected, sent], timeout: 3000)
    }
    
    func testShadowReceive() throws
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

        let publicKeyString = "6LukZ8KqZLQ7eOdaTVFkBVqMA8NS1AUxwqG17L/kHnQ="
        guard let publicKeyData = Data(base64: publicKeyString) else
        {
            XCTFail()
            return
        }

        let publicKey = try PublicKey(type: .P256KeyAgreement, data: publicKeyData)
        
        let shadowConfig = ShadowConfig.ShadowClientConfig(serverAddress: "127.0.0.1:1234", serverPublicKey: publicKey, mode: .DARKSTAR)
        let shadowFactory = ShadowConnectionFactory(config: shadowConfig, logger: logger)
        
        guard var shadowConnection = shadowFactory.connect(using: .tcp) else
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
                
                    shadowConnection.send(content: Data(string: "GET / HTTP/1.0\r\n\r\n"), contentContext: .defaultMessage, isComplete: true, completion: NWConnection.SendCompletion.contentProcessed(
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
                        }
                    }
                }))
            default:
                    let logString = "\nReceived a state other than ready: \(state)\n"
                    self.logger.debug("\(logString)")
                return
            }
        }
        
        shadowConnection.start(queue: .global())
        
        //let godot = expectation(description: "forever")
        wait(for: [connected, sent, received, serverNewConnectionReceived, serverReceivedData, serverResponded], timeout: 15)
    }
    
    func testShadowReceiveSendTwice() throws
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

        let publicKeyString = "6LukZ8KqZLQ7eOdaTVFkBVqMA8NS1AUxwqG17L/kHnQ="
        guard let publicKeyData = Data(base64: publicKeyString) else
        {
            XCTFail()
            return
        }

        let publicKey = try PublicKey(type: .P256KeyAgreement, data: publicKeyData)
        
        let shadowConfig = ShadowConfig.ShadowClientConfig(serverAddress: "127.0.0.1:1234", serverPublicKey: publicKey, mode: .DARKSTAR)
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
                    let logString = "\nReceived a state other than ready: \(state)\n"
                    self.logger.debug("\(logString)")
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
                            return
                            
                    }
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
    
    func testCreateNewConfigPair()
    {
        let saveDirectory = FileManager.default.homeDirectoryForCurrentUser
        let result = ShadowConfig.createNewConfigFiles(inDirectory: saveDirectory, serverAddress: "127.0.0.1:1234", cipher: .DARKSTAR)
        
        if result.saved
        {
            print("New config files have been saved to \(saveDirectory)")
        }
        else
        {
            if let error = result.error
            {
                print("Failed to create or save new a new ShadowConfig pair. Error: \(error)")
            }
            else
            {
                print("Failed to create or save new a new ShadowConfig pair. No error information was provided.")
            }
            
            XCTFail()
        }
    }
    
    func testJSONConfig() throws
    {
        let privateKeyString = "RaHouPFVOazVSqInoMm8BSO9o/7J493y4cUVofmwXAU="
        guard let privateKeyData = Data(base64: privateKeyString) else
        {
            XCTFail()
            return
        }

        let privateKey = try PrivateKey(type: .P256KeyAgreement, data: privateKeyData)

        let shadowConfig = ShadowConfig.ShadowServerConfig(serverAddress: "127.0.0.1:1234", serverPrivateKey: privateKey, mode: .DARKSTAR)
        let encoder = JSONEncoder()
        let json = try? encoder.encode(shadowConfig)
        
        let filePath = ""
        FileManager.default.createFile(atPath: filePath, contents: json)
        
        
        guard let _ = ShadowConfig.ShadowServerConfig(path:filePath )
        else
        {
            XCTFail()
            return
        }
    }

    func testbytesToPrivateKey() throws {
        let privateKeyString = "RaHouPFVOazVSqInoMm8BSO9o/7J493y4cUVofmwXAU="
        guard let privateKeyData = Data(base64Encoded: privateKeyString) else {return}
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
        let publicKey = privateKey.publicKey
        guard let publicKeyData = publicKey.compactRepresentation else {return}
        print(publicKeyData.base64EncodedString())
    }
    
    func testDarkStarClientAndServer()
    {
        let privateKeyString = "RaHouPFVOazVSqInoMm8BSO9o/7J493y4cUVofmwXAU="
        guard let privateKeyBytes = Data(base64: privateKeyString) else {return}
        guard let privateKey = try? PrivateKey(type: .P256KeyAgreement, data: privateKeyBytes) else {return}
        let publicKey = privateKey.publicKey

        guard let server = ShadowServer(host: "127.0.0.1", port: 1234, config: ShadowConfig.ShadowServerConfig(serverAddress: "127.0.0.1:1234", serverPrivateKey: privateKey, mode: .DARKSTAR), logger: self.logger) else {return}

        let queue = DispatchQueue(label: "Client")
        queue.async
        {
            do
            {
                let connection = try server.accept()
                
                _ = connection.write(string: "test\n")
                print("Sent!")
            }
            catch
            {
                print(error.localizedDescription)
                XCTFail()
                return
            }
            
        }

        let factory = ShadowConnectionFactory(config: ShadowConfig.ShadowClientConfig(serverAddress: "127.0.0.1:1234", serverPublicKey: publicKey, mode: .DARKSTAR), logger: self.logger)
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
        let sent = XCTestExpectation(description: "Sent!")
        
        let privateKeyString = "RaHouPFVOazVSqInoMm8BSO9o/7J493y4cUVofmwXAU="
        guard let privateKeyBytes = Data(base64: privateKeyString) else
        {
            XCTFail()
            return
        }
        
        guard let privateKey = try? PrivateKey(type: .P256KeyAgreement, data: privateKeyBytes) else
        {
            XCTFail()
            return
        }
        
        guard let server = ShadowServer(host: "127.0.0.1", port: 1234, config: ShadowConfig.ShadowServerConfig(serverAddress: "127.0.0.1:1234", serverPrivateKey: privateKey, mode: .DARKSTAR), logger: self.logger) else {return}

        do
        {
            let connection = try server.accept()
            _ = connection.write(string: "test\n")
            print("Sent!")
            wait(for: [sent], timeout: 30)  // 30 seconds
        }
        catch
        {
            print(error)
            XCTFail()
            return
        }
    }

    func testGenerateKeys()
    {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let privateKeyData = privateKey.rawRepresentation
        let privateKeyString = privateKeyData.base64EncodedString()

        let publicKey = privateKey.publicKey
        let publicKeyData = publicKey.compactRepresentation
        let publicKeyString = publicKeyData!.base64EncodedString()

        print("Private key: \(privateKeyString)")
        print("Public key: \(publicKeyString)")
    }
    
    func testPublicKeyFromPrivateKey()
    {
        let privateKeyString = "RaHouPFVOazVSqInoMm8BSO9o/7J493y4cUVofmwXAU="
        guard let privateKeyData = Data(base64Encoded: privateKeyString) else {
            XCTFail()
            return
        }
        do {
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let publicKey = privateKey.publicKey
            let publicKeyData = publicKey.compactRepresentation
            let publicKeyString = publicKeyData!.base64EncodedString()

            print("Private key: \(privateKeyString)")
            print("Public key: \(publicKeyString)")
        } catch {
            XCTFail()
        }
    }
    
    
    func testPublicKeyFromPrivateKeyHex()
    {
        let privateKeyString = "e7afafe8098d06d9cac98cfdd5179bd031e81761717a04d0415765f0d8d5f4d0"
        guard let privateKeyData = Data(hex: privateKeyString) else {
            XCTFail()
            return
        }
        do {
            let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let publicKey = privateKey.publicKey
            let publicKeyData = publicKey.compactRepresentation
            let publicKeyString = publicKeyData!.hex

            print("Private key: \(privateKeyString)")
            print("Public key: \(publicKeyString)")
        } catch {
            XCTFail()
        }
    }
//    func testSIP008()
//    {
//        let ready = XCTestExpectation(description: "Ready!")
//
//        guard let url = URL(string: "https://raw.githubusercontent.com/OperatorFoundation/ShadowSwift/main/Tests/ShadowSwiftTests/testsip008.json") else
//        {
//            XCTFail()
//            return
//        }
//        guard let serverid = UUID(uuidString: "27b8a625-4f4b-4428-9f0f-8a2317db7c79") else
//        {
//            XCTFail()
//            return
//        }
//
//        guard let factory = ShadowConnectionFactory(url: url, serverid: serverid, logger: self.logger) else
//        {
//            XCTFail()
//            return
//        }
//
//        guard var client = factory.connect(using: .tcp) else {return}
//
//        client.stateUpdateHandler={
//            state in
//
//            switch state
//            {
//                case .ready:
//                    print("Ready!")
//                    ready.fulfill()
//                default:
//                    return
//            }
//        }
//        let queue2 = DispatchQueue(label: "Client")
//        client.start(queue: queue2)
//        wait(for: [ready], timeout: 30)  // 30 seconds
//    }

    public func testULong()
    {
        let uint64 = UInt64.max
        let int64 = Int64(bitPattern: uint64)
        print(uint64)
        print(int64)
    }
    
    func testBloomFilterSave()
    {
        guard let supportDirectoryURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else
        {
            logger.error("Could not get application support directory path.")
            XCTFail()
            return
        }
        
        let testString = "something"
        let testData = Data(string: testString)
        let bloomFilterPath = supportDirectoryURL.appendingPathComponent("BloomFilter.json")
        
        // instantiate a bloom filter.
        let bloomFilter = BloomFilter<Data>()
        
        // insert some data into the bloom filter.
        bloomFilter.insert(testData)
        
        // save the bloom filter JSON file.
        print("Saving BloomFilter to \(bloomFilterPath)")
        let filterSaved = bloomFilter.save(pathURL: bloomFilterPath)
        XCTAssertTrue(filterSaved)
        
        if FileManager.default.fileExists(atPath: bloomFilterPath.path)
        {
            guard let savedBloomFilter = BloomFilter<Data>(withFileAtPath: bloomFilterPath.path) else
            {
                XCTFail()
                return
            }
            
            XCTAssertTrue(savedBloomFilter.contains(testData))
            
        }
        else
        {
            XCTFail()
            return
        }
    }
    
    // TODO: func testBlackHole()
}

