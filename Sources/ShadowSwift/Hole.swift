//
//  File.swift
//  
//
//  Created by Joshua Clark on 1/24/22.
//

import Foundation
import Transport

open class Hole {
    func startHole(timeoutDelay: Int, socket: Transport.Connection) {
        let date = Date()
        let calendar = Calendar.current
        let timeInSeconds = calendar.component(.second, from: date)
        let endTime = timeInSeconds + timeoutDelay
        
        startPacketDelayTimer(mainTimer: endTime, socket: socket)
    }
    
    func startPacketDelayTimer(mainTimer: Int, socket: Transport.Connection) {
        let date = Date()
        let calendar = Calendar.current
        let timeInSeconds = calendar.component(.second, from: date)
        let packetTimeMax = 5
        let packetTimeMin = 1
        let packetSize = 1440 - 16 // max TCP size without encryption overhead
    }
//    var holeActive = false
//    var packetQueued = false
//
//    func startHole(timeoutDelay: Int, socket: Transport.Connection) {
//        holeActive = true
//        DispatchQueue.main.asyncAfter(deadline: .now() + DispatchTimeInterval.seconds(timeoutDelay)) { [self] in
//            holeActive = false
//        }
//        while holeActive {
//            packetQueued = true
//            while packetQueued {
//                packetQueued = false
//                startPacketDelayTimer(mainTimer: <#T##Int#>, socket: <#T##Connection#>)
//            }
//        }
//
//
//    }
//
//    func startPacketDelayTimer(mainTimer: Int, socket: Transport.Connection) {
//        DispatchQueue.main.asyncAfter(deadline: .now() + DispatchTimeInterval.seconds(mainTimer)) {
//            self.packetQueued = true
//        }
//    }
//
//    func checkBloom(salt: Data, socket: Transport.Connection) {
//        if self.contains(salt) {
//            self.startHole(timeoutDelay: 100, socket: socket)
//        } else {
//            self.insert(salt)
//        }
//    }
}

// Cipher.generateRandomBytes(count: Int.random(in: 0..<6))
