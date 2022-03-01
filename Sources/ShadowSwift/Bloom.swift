//
//  Bloom.swift
//  
//
//  Created by Joshua Clark on 1/23/22.
//

import Foundation
import Transport

public struct BloomFilter<Data: Hashable>: Codable
{
    private var data: [Bool]
    private let seeds: [Int]
    
    public init(size: Int, hashCount: Int)
    {
        data = Array(repeating: false, count: size)
        seeds = (0..<hashCount).map({ _ in Int.random(in: 0..<Int.max) })
    }
    
    init()
    {
        self.init(size: 512, hashCount: 3)
    }
    
    mutating func insert(_ salt: Data)
    {
        hashes(for: salt)
        .forEach({ hash in
            data[hash % data.count] = true
        })
    }
    
    func contains(_ salt: Data) -> Bool
    {
        return hashes(for: salt)
        .allSatisfy({ hash in
            data[hash % data.count]
        })
    }
    
    private func hashes(for salt: Data) -> [Int]
    {
        return seeds.map(
            { seed -> Int in
            var hasher = Hasher()
            hasher.combine(salt)
            hasher.combine(seed)
            let hashValue = abs(hasher.finalize())
            return hashValue
        })
    }
    
    // Use Codable to save as JSON
    func save(filename: String)
    {
        
    }
    
    // Use Codable to load from JSON
    func load(filename: String)
    {
        
    }
}

// Cipher.generateRandomBytes(count: Int.random(in: 0..<6))


