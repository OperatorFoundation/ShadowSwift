//
//  BlackHole.swift
//
//
//  Created by Joshua Clark on 1/24/22.
//

import Foundation
import Net
import TransmissionAsync

open class AsyncBlackHole
{
    var running = true

    public init(timeoutDelaySeconds: Int, socket: AsyncConnection)
    {
        self.startPacketDelayTimer(socket: socket)
        startHoleTimer(timeOutSeconds: timeoutDelaySeconds, socket: socket)
    }

    func startPacketDelayTimer(socket: AsyncConnection)
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

                Task
                {
                    try await socket.write(packetData)
                }
                
                self.startPacketDelayTimer(socket: socket)
            }
        }
    }

    func startHoleTimer(timeOutSeconds: Int, socket: AsyncConnection)
    {
        print("ShadowSwift.Someone got put in timeout...")

        DispatchQueue.main.asyncAfter(deadline: .now() + DispatchTimeInterval.seconds(timeOutSeconds))
        {
            self.running = false

            Task
            {
                try await socket.close()
            }
        }
    }
}
