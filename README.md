# The Operator Foundation

[Operator](https://operatorfoundation.org) makes usable tools to help people around the world with censorship, security, and privacy.

## Shapeshifter

The Shapeshifter project provides network protocol shapeshifting technology
(also sometimes referred to as obfuscation). The purpose of this technology is
to change the characteristics of network traffic so that it is not identified
and subsequently blocked by network filtering devices.

There are two components to Shapeshifter: transports and the dispatcher. Each
transport provide different approach to shapeshifting. ShadowSwift is provided as a 
Swift library which can be integrated directly into applications.

If you are a tool developer working in the Swift programming language, then you
are in the right place. If you are a tool developer working in other languages we have 
several other tools available to you:

- A Go transports library that can be used directly in your application:
[shapeshifter-transports](https://github.com/OperatorFoundation/shapeshifter-transports)

- A Kotlin transports library that can be used directly in your Android application (currently supports Shadow):
[ShapeshifterAndroidKotlin](https://github.com/OperatorFoundation/ShapeshifterAndroidKotlin)

- A Java transports library that can be used directly in your Android application (currently supports Shadow):
[ShapeshifterAndroidJava](https://github.com/OperatorFoundation/ShapeshifterAndroidJava)

If you want a end user that is trying to circumvent filtering on your network or
you are a developer that wants to add pluggable transports to an existing tool
that is not written in the Go programming language, then you probably want the
dispatcher. Please note that familiarity with executing programs on the command
line is necessary to use this tool.
<https://github.com/OperatorFoundation/shapeshifter-dispatcher>

If you are looking for a complete, easy-to-use VPN that incorporates
shapeshifting technology and has a graphical user interface, consider
[Moonbounce](https://github.com/OperatorFoundation/Moonbounce), an application for macOS which incorporates shapeshifting without
the need to write code or use the command line.

### Shapeshifter Transports

This is the repository for the shapeshifter transports library for the Go
programming language. If you are looking for a tool which you can install and
use from the command line, take a look at the dispatcher instead:
<https://github.com/OperatorFoundation/shapeshifter-transports>

ShadowSwift implements the Pluggable Transports 3.0 specification available here:
<https://github.com/Pluggable-Transports/Pluggable-Transports-spec/tree/main/releases/PTSpecV3.0> Specifically,
they implement the [Swift Transports API v3.0](https://github.com/Pluggable-Transports/Pluggable-Transports-spec/blob/main/releases/PTSpecV3.0/Pluggable%20Transport%20Specification%20v3.0%20-%20Swift%20Transport%20API%20v3.0.md).

The purpose of the transport library is to provide a set of different
transports. Each transport implements a different method of shapeshifting
network traffic. The goal is for application traffic to be sent over the network
in a shapeshifted form that bypasses network filtering, allowing
the application to work on networks where it would otherwise be blocked or
heavily throttled.

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
1. Create a Shadow config containing the password and cipher mode. For DarkStar mode, the password will be the server's persistent private key in hex.
```
let shadowServerConfig = ShadowConfig(password: "privateKeyHex", mode: .DARKSTAR)
```
2. Create a Shadow Server with the host, port, ShadowConfig and Swift Logger. 
```
guard let server = ShadowServer(host: "host", port: 2222, config: shadowServerConfig, logger: logger) else                
{
    return
}
```

3. Accept the connection
```
let connection = try server.accept()
```

4. Call .send and .receive on the server connection to send and receive data
```
let messageSent = connection.write(string: "test\n")
let maybeData = network.read(size: expectedLength)
```
