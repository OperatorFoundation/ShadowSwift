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
        let testIPString = "159.203.158.90"
        let testPort: UInt16 = 2345
        let plainText = Data(array: [0, 1, 2, 3, 4])
        
        func testShadowConnection()
        {
            let connected = expectation(description: "Connection callback called")
            //let sent = expectation(description: "TCP data sent")
            
            let host = NWEndpoint.Host(testIPString)
            guard let port = NWEndpoint.Port(rawValue: testPort)
                else
            {
                print("\nUnable to initialize port.\n")
                XCTFail()
                return
            }
            
            let logger = Logger(label: "Shadow Logger")
            LoggingSystem.bootstrap(StreamLogHandler.standardError)
            
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
                    print("\nConnected state ready\n")
                    connected.fulfill()
                default:
                    print("\nReceived a state other than ready: \(state)\n")
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
                print("\nUnable to initialize port.\n")
                XCTFail()
                return
            }
            
            let logger = Logger(label: "Shadow Logger")
            LoggingSystem.bootstrap(StreamLogHandler.standardError)
            
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
                    print("\nConnected state ready\n")
                    connected.fulfill()
                    
                    shadowConnection.send(content: Data("1234"), contentContext: .defaultMessage, isComplete: true, completion: NWConnection.SendCompletion.contentProcessed(
                    {
                        (maybeError) in
                        
                        if let sendError = maybeError
                        {
                            print("Send Error: \(sendError)")
                            XCTFail()
                            return
                        }
                        
                        sent.fulfill()
                    }))
                default:
                    print("\nReceived a state other than ready: \(state)\n")
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
                print("\nUnable to initialize port.\n")
                XCTFail()
                return
            }
            
            let logger = Logger(label: "Shadow Logger")
            LoggingSystem.bootstrap(StreamLogHandler.standardError)
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
                    print("\nConnected state ready\n")
                    connected.fulfill()
                    
                    shadowConnection.send(content: Data("GET / HTTP/1.0\r\n\r\n"), contentContext: .defaultMessage, isComplete: true, completion: NWConnection.SendCompletion.contentProcessed(
                    {
                        (maybeError) in
                        
                        if let sendError = maybeError
                        {
                            print("Send Error: \(sendError)")
                            XCTFail()
                            return
                        }
                        
                        sent.fulfill()
                        
                        shadowConnection.receive(minimumIncompleteLength: 4, maximumLength: 4)
                        {
                            (maybeData, maybeContext, isComplete, maybeReceiveError) in
                            
                            if let receiveError = maybeReceiveError
                            {
                                print("Got a receive error \(receiveError)")
                                //XCTFail()
                                //return
                            }
                            
                            if let data = maybeData
                            {
                                print("Received data!!")
                                print(data.string)
                                received.fulfill()
                            }
                        }
                    }))
                default:
                    print("\nReceived a state other than ready: \(state)\n")
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
                print("\nUnable to initialize port.\n")
                XCTFail()
                return
            }
            
            let logger = Logger(label: "Shadow Logger")
            LoggingSystem.bootstrap(StreamLogHandler.standardError)
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
                    print("\nConnected state ready\n")
                    connected.fulfill()
                    
                    shadowConnection.send(content: Data("1234"), contentContext: .defaultMessage, isComplete: true, completion: NWConnection.SendCompletion.contentProcessed(
                    {
                        (maybeError) in
                        
                        if let sendError = maybeError
                        {
                            print("Send Error: \(sendError)")
                            XCTFail()
                            return
                        }
                        
                        sent.fulfill()
                        
                        shadowConnection.receive(minimumIncompleteLength: 4, maximumLength: 4)
                        {
                            (maybeData, maybeContext, isComplete, maybeReceiveError) in
                            
                            if let receiveError = maybeReceiveError
                            {
                                print("Got a receive error \(receiveError)")
                                //XCTFail()
                                //return
                            }
                            
                            if let data = maybeData
                            {
                                print("Received data!!")
                                print(data.string)
                                received.fulfill()
                                
                                shadowConnection.send(content: "Send2", contentContext: .defaultMessage, isComplete: false, completion: NWConnection.SendCompletion.contentProcessed(
                                {
                                    (maybeSendError) in
                                    
                                    if let sendError = maybeSendError
                                    {
                                        print("Error on 2nd send: \(sendError)")
                                        XCTFail()
                                        return
                                    }
                                    
                                    sent2.fulfill()
                                    
                                    shadowConnection.receive(minimumIncompleteLength: 11, maximumLength: 11)
                                    {
                                        (maybeData, _, _, maybeError) in
                                        
                                        if let error = maybeError
                                        {
                                            print("Error on 2nd receive: \(error)")
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
                    print("\nReceived a state other than ready: \(state)\n")
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
                            print("Server is ready.")
                            
                            connection.receive(minimumIncompleteLength: 4, maximumLength: 4)
                            {
                                (maybeData, _, _, maybeReceiveError) in
                                
                                if let receiveError = maybeReceiveError
                                {
                                    print("Server received an error on receive: \(receiveError)")
                                    return
                                }
                                
                                guard let receivedData = maybeData
                                else
                                {
                                    print("Server received nil data.")
                                    return
                                }
                                
                                dataReceived.fulfill()
                                
                                if receivedData.string == "1234"
                                {
                                    connection.send(content: "Okay".data, contentContext: .defaultMessage, isComplete: true, completion: NWConnection.SendCompletion.contentProcessed(
                                    {
                                        (maybeSendError) in
                                        
                                        if let sendError = maybeSendError
                                        {
                                            print("Error sending 'Okay' message: \(sendError)")
                                            return
                                        }
                                        else
                                        {
                                            print("Okay message sent!")
                                            responseSent.fulfill()
                                            
                                            connection.receive(minimumIncompleteLength: 5, maximumLength: 5)
                                            {
                                                (maybeData, _, _, maybeError) in
                                                
                                                if let error = maybeError
                                                {
                                                    print("Server error on 2nd receive: \(error)")
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
                                                            if let error = maybeError
                                                            {
                                                                print("Server error on 2nd send: \(error)")
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
                            print("Server state is not ready: \(connectionState)")
                        }
                    }
                    
                    newConnection.start(queue: .global())
                    connectionReceived.fulfill()
                }
                
                listener.start(queue: .global())
                listening.fulfill()
            }
            catch let listenerError
            {
                print("Error running a server: \(listenerError)")
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
        
    //    func testHKDF()
    //    {
    //        let correct = Data(base64Encoded: "k7qvG929qzyHVF7D2Bxke78qIxk1A8jk/JKSA7K0V40=")
    //        let secret = Data(base64Encoded: "aFkrPPcQtd5QLc5xBuUhazfDQijc3HVXb974bqnSH4c=")
    //        let salt = Data(base64Encoded: "rUU438RMMHLlSH0jLMp9FSrFHHuWj4eQw/dq1XQpnJ0=")
    //        let info = Data(string: "ss-subkey")
    //
    //        guard let result = Cipher(config: <#ShadowConfig#>, salt: <#Data#>, logger: <#Logger#>).hkdfSHA1(secret: secret!, salt: salt!, cipherMode: CipherMode.AES_128_GCM)
    //        else
    //        {
    //            XCTFail()
    //            return
    //        }
    //
    //        XCTAssertEqual(correct, result)
    //    }
    //
    //    // AES.GCM 128
    //    func testAES128()
    //    {
    //        let nonce = Data(base64Encoded: "GPiavgwl3vKAa6aK")
    //        let secret = Data(base64Encoded: "x1wXVJg6pM4ML48HB6YyEA==")
    //        let salt = Data(base64Encoded: "AIZClCKlN3LnoNtETQmh31kScJPT3jCt")
    //        let info = Data(string: "ss-subkey")
    //        let key = Cipher().hkdfSHA1(secret: secret!, salt: salt!, info: info)
    //        //let key = Data(base64Encoded: "vru391Vs32PEhzOuiS325A==")
    //
    //        // Encrypt a thing
    //        do
    //        {
    //            //Seal
    //            let encrypted = try AES.GCM.seal(plainText,
    //                                             using: SymmetricKey(data: key!),
    //                                             nonce: AES.GCM.Nonce(data: nonce!))
    //
    //
    //
    //            let correct = Data(base64Encoded: "I2lhGBsa1w45XV9I486z4A3j7oro")
    //            XCTAssertEqual(encrypted.combined![12...], correct)
    //        }
    //        catch let error
    //        {
    //            print("Error encrypting data: \(error)")
    //            XCTFail()
    //        }
    //    }
    //
    //    // AES.GCM 192
    //    func testAES192()
    //    {
    //        let nonce = Data(base64Encoded: "9y3YUf37OrbhoESq")
    //        let secret = Data(base64Encoded: "zxhocnRVToKo5axoM9ZiCRV8ZwU9zRD9")
    //        let salt = Data(base64Encoded: "biPWP0Uk2UI9tJmwjWACwzU5ltViYJvw")
    //        let info = Data(string: "ss-subkey")
    //        let key = Cipher().hkdfSHA1(secret: secret!, salt: salt!, info: info)
    //        //let key = Data(base64Encoded: "mEl7TEjOwbOBvCpwT9fA6xQuJJ5t8EOC")
    //
    //        // Encrypt a thing
    //        do
    //        {
    //            //Seal
    //            let encrypted = try AES.GCM.seal(plainText,
    //                                             using: SymmetricKey(data: key!),
    //                                             nonce: AES.GCM.Nonce(data: nonce!))
    //            let correct = Data(base64Encoded: "NJ2FGAA4h35pvqgHqbpqEEwYPmif")
    //
    //            XCTAssertEqual(encrypted.combined![12...], correct)
    //        }
    //        catch let error
    //        {
    //            print("Error encrypting data: \(error)")
    //            XCTFail()
    //        }
    //    }
    //
    //    // AES.GCM 256
    //    func testAES256()
    //    {
    //        let nonce = Data(base64Encoded: "MSX/t7/6kgl56xFP")
    //        let secret = Data(base64Encoded: "aFkrPPcQtd5QLc5xBuUhazfDQijc3HVXb974bqnSH4c=")
    //        let salt = Data(base64Encoded: "rUU438RMMHLlSH0jLMp9FSrFHHuWj4eQw/dq1XQpnJ0=")
    //        let info = Data(string: "ss-subkey")
    //        let key = Cipher().hkdfSHA1(secret: secret!, salt: salt!, info: info)
    //        //let key = Data(base64Encoded: "k7qvG929qzyHVF7D2Bxke78qIxk1A8jk/JKSA7K0V40=")
    //
    //        // Encrypt a thing
    //        do
    //        {
    //            //Seal
    //            let encrypted = try AES.GCM.seal(plainText,
    //                                             using: SymmetricKey(data: key!),
    //                                             nonce: AES.GCM.Nonce(data: nonce!))
    //            let correct = Data(base64Encoded: "6k8tJuPU87yBFrtniSage8SX9xiU")
    //
    //            XCTAssertEqual(encrypted.combined![12...], correct)
    //        }
    //        catch let error
    //        {
    //            print("Error encrypting data: \(error)")
    //            XCTFail()
    //        }
    //    }
    //
    //    // AES.GCM ChaChaPoly
    //    func testChaChaPoly()
    //    {
    //        let nonce = Data(base64Encoded: "kA3DoGigyGYfF2bj")
    //        let secret = Data(base64Encoded: "q2f5hKCwszOLvvsc4g1cMj1gwho1O3dE2ttwTks8haE=")
    //        let salt = Data(base64Encoded: "rUU438RMMHLlSH0jLMp9FSrFHHuWj4eQw/dq1XQpnJ0=")
    //        let info = Data(string: "ss-subkey")
    //        let key = Cipher().hkdfSHA1(secret: secret!, salt: salt!, info: info)
    //        //let key = Data(base64Encoded: "mnbqMaGH95dS2jZXaeT9UTszQ0myRcBu1CCjxA+MafY=")
    //
    //        do
    //        {
    //            let encrypted = try ChaChaPoly.seal(plainText,
    //                                                using: SymmetricKey(data: key!),
    //                                                nonce: ChaChaPoly.Nonce(data: nonce!))
    //            let correct = Data(base64Encoded: "LJQq3ms5dYIPoN/csclHFuCU1EH0")
    //            XCTAssertEqual(encrypted.combined[12...], correct)
    //        }
    //        catch let error
    //        {
    //            print("Error encrypting data: \(error)")
    //            XCTFail()
    //        }
    //    }

    }

