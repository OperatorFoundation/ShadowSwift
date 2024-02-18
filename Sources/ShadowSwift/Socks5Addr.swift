//
//  Socks5Addr.swift
//  Shadow
//
//  Created by Mafalda on 8/27/20.
//

import Foundation
import Logging

/*
 Addresses used in Shadowsocks follow the SOCKS5 address format:
 [1-byte type][variable-length host][2-byte port]
 The port number is a 2-byte big-endian unsigned integer.
 */
/// Addr represents a SOCKS address as defined in RFC 1928 section 5.
/// [1-byte type][variable-length host][2-byte port]
struct Socks5Addr
{
    let type: AddrType
    let data: Data
    var string: String
    
}

/**
 SOCKS address types as defined in RFC 1928 section 5.
 The following address types are defined:
 0x01: host is a 4-byte IPv4 address.
 0x03: host is a variable length string, starting with a 1-byte length, followed by up to 255-byte domain name.
 0x04: host is a 16-byte IPv6 address.
 */
enum AddrType: Int
{
    case ipV4 = 1
    case domainName = 3
    case ipV6 = 4
}
