# ShadowSwift

Shadowsocks is a simple, but effective and popular network traffic obfuscation tool that uses basic encryption with a shared password. shadow is a wrapper for Shadowsocks that makes it available as a Pluggable Transport. 

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
1. Create a Shadow connection factory with the host, port and ShadowConfig containing the password and cipher mode.  For DarkStar mode, the password will be the server's persistent private key in hex.
```
        let factory = ShadowConnectionFactory(host: NWEndpoint.Host.ipv4(IPv4Address("host")!), port: NWEndpoint.Port(integerLiteral: port), config: ShadowConfig(password: "password", mode: .DARKSTAR_CLIENT), logger: self.logger)
```

2. Connect using the client factory
```
        guard var client = factory.connect(using: .tcp) else {return}
```

3. Call .send and .receive on the client connection to send and receive data

#### Server:
1. Create a Shadow Server with the host, port, and ShadowConfig containing the password and cipher mode. For DarkStar mode, the password will be the server's persistent private key in hex.
```
        guard let server = ShadowServer(host: "host", port: port, config: ShadowConfig(password: "password", mode: .DARKSTAR_SERVER), logger: self.logger) else {
            return
        }
```

2. Accept the connection
```
        guard let connection = server.accept() else {
            return
        }
```

3. Call .send and .receive on the server connection to send and receive data
