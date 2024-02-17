//
//  Socks.swift
//  Shadow
//
//  Created by Mafalda on 8/26/20.
//

import Foundation
import Logging

import Datable

struct Socks
{
    // MaxAddrLen is the maximum size of SOCKS address in bytes.
    let maxAddrLen = 1 + 1 + 255 + 2
    let address: Socks5Addr
    let log: Logger
    
    var udpEnabled = false
//    
//    func readAddr(buffer: Data) -> (addr: Socks5Addr, remaining: Data)?
//    {
//        guard let addrType = AddrType(rawValue: Int(buffer[0]))
//        else
//        {
//            log.error("Failed to read Socks5Addr, AddrType is unknown: \(Int(buffer[0]))")
//            return nil
//        }
//        
//        switch addrType
//        {
//        case .domainName:
//            <#code#>
//        default:
//            return nil
//        }
//    }
}


