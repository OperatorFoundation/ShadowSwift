# ShadowSwift

Shadowsocks is a fast, free, and open-source encrypted proxy project, used to circumvent Internet censorship by utilizing a simple, but effective encryption and a shared password. ShadowSwift is a wrapper for Shadowsocks that makes it available as a Pluggable Transport. 

## Prerequisites

What things you need to install the software and how to install them

```
Xcode
```

## Installing

1. Clone the repository.

2. Navigate to the project folder

3. Update the dependencies using Swift Package Manager
```
swift package update
```

## Using the Library

### Client:
1. Create a Shadow connection factory with a ShadowConfig and a swift Logger containing the password and cipher mode.  For DarkStar mode, the password will be the server's persistent private key in hex.
```
let logger: Logger = Logger(label: "Shadow Logger")
LoggingSystem.bootstrap(StreamLogHandler.standardError)

let shadowConfig = ShadowConfig(key: publicKeyHex, serverIP: "127.0.0.1", port: 1234, mode: .DARKSTAR)
let factory = ShadowConnectionFactory(config: shadowConfig, logger: logger)
```

2. Connect using the client factory
```
guard var connection = factory.connect(using: .tcp) else 
{
    return
}

 connection.stateUpdateHandler = 
 {
    state in

    switch state
    {
        case .ready:
            print("Ready!")
        default:
            return
    }
}
```

3. Call .send and .receive on the client connection to send and receive data

#### Server:
1. When creating a shadow server you will need to have a bloom filter json file saved to /Users/<user>/Library/Application Support/BloomFilter. The BloomFilter struct has a static method to create an empty file in the correct directory. Once the initial file is created, you should not replace it as it keeps track of important information to help against replay attacks.
```
```
2. Create a Shadow config containing the password and cipher mode. For DarkStar mode, the password will be the server's persistent private key in hex.
```
let shadowServerConfig = ShadowConfig(password: "privateKeyHex", mode: .DARKSTAR)
```
3. Create a Shadow Server with the host, port, ShadowConfig and Swift Logger. 
```
guard let server = ShadowServer(host: "host", port: 2222, config: shadowServerConfig, logger: logger) else                
{
    return
}
```

2. Accept the connection
```
let connection = try server.accept()
```

3. Call .send and .receive on the server connection to send and receive data
```
let messageSent = connection.write(string: "test\n")
let maybeData = network.read(size: expectedLength)
```
