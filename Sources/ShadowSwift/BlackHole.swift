//
//  BlackHole.swift
//  
//
//  Created by Joshua Clark on 1/24/22.
//

import Foundation
import Net
import Transport

open class BlackHole
{
    var running = true
    
    public init(timeoutDelaySeconds: Int, socket: Transport.Connection)
    {
        self.startPacketDelayTimer(socket: socket)
        startHoleTimer(timeOutSeconds: timeoutDelaySeconds, socket: socket)
    }
    
    func startPacketDelayTimer(socket: Transport.Connection)
    {
        let packetTimeMax = 5
        let packetTimeMin = 1
        let maxPacketSize = 1440 - 16 // max TCP size without encryption overhead
        let minPacketSize = 512 - 16
        let packetDelay = Int.random(in: packetTimeMin...packetTimeMax)
    
        DispatchQueue.main.asyncAfter(deadline: .now() + DispatchTimeInterval.seconds(packetDelay))
        {
            if self.running
            {
                let packetSize = Int.random(in: minPacketSize...maxPacketSize)
                let packetData = Data(randomCount: packetSize)
                socket.send(content: packetData, contentContext: NWConnection.ContentContext.defaultMessage, isComplete: false, completion: .idempotent)
                self.startPacketDelayTimer(socket: socket)
            }
        }
    }
    
    func startHoleTimer(timeOutSeconds: Int, socket: Transport.Connection)
    {
        print("ShadowSwift.Someone got put in timeout...")
        
        DispatchQueue.main.asyncAfter(deadline: .now() + DispatchTimeInterval.seconds(timeOutSeconds))
        {
            self.running = false
            socket.cancel()
        }
    }
}

extension Data
{
    init(randomCount: Int)
    {
        var data = Data(repeating: 0, count: randomCount)
        for index in 0..<randomCount
        {
            data[index] = UInt8.random(in: 0...255)
        }
        self = data
    }
}
