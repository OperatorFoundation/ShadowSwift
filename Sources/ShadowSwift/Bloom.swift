//
//  Bloom.swift
//  
//
//  Created by Joshua Clark on 1/23/22.
//

import Foundation
import Transport

// BloomFilter is a generic type with a type argument, Data.
// Data must conform to Hashable rules/protocol for code to work.
// Entire struct must conform to Codeable.
public struct BloomFilter<filterData: Hashable>: Codable
{
    private var data: [Bool]
    private let seeds: [Int]
    
    // init gives our variables a value
    public init(size: Int, hashCount: Int)
    {
        // data creates an empty array (for the salts to go)
        data = Array(repeating: false, count: size)
        // seeds here are generating random numbers to be mapped
        seeds = (0..<hashCount).map({ _ in Int.random(in: 0..<Int.max) })
    }
    // using the init that was declared just above, but giving hard coded values 512 & 3.
    init()
    {
        self.init(size: 512, hashCount: 3)
    }
    
    // Use Codable to load from JSON
    // Load will take the data from the filename and put it in the data array.
    public init?(withFileAtPath filePath: String)
    {
        let jsonDecoder = JSONDecoder()
        let url = URL(fileURLWithPath: filePath)
        
        
        do
        {
            let data = try Data(contentsOf: url)
            let decoded = try jsonDecoder.decode(BloomFilter.self, from: data)
            self = decoded
        }
        catch (let jsonDecodeError)
        {
          print("Failed to decode Bloom from JSON: \(jsonDecodeError)")
            return nil
        }
    }
    
    // here we are putting the salt into the Data array
    // data[hash % data.count] is a placefinder so it knows what spot in the array to put it in
    mutating func insert(_ salt: filterData)
    {
        hashes(for: salt)
        .forEach({ hash in
            data[hash % data.count] = true
        })
    }
    
    // Takes the salt we give it, and checks the array if there is a match. If it matches it returns true, false if not.
    func contains(_ salt: filterData) -> Bool
    {
        return hashes(for: salt)
        .allSatisfy({ hash in
            data[hash % data.count]
        })
    }
    
    // hashes returns an array of integers.
    // TODO: read the comment section of Swift.Hashing for more info
    private func hashes(for salt: filterData) -> [Int]
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
    // give it the filename of the JSON and it will search for that file and put the data in it.
    func save(filePath: String)
    {
        let jsonEncoder = JSONEncoder()
//        let bloomFilterDirectory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Desktop", isDirectory: true).appendingPathComponent("Configs", isDirectory: true)
        
        do
        {
            let data = try jsonEncoder.encode(self)
            
            // creates the file directory:
//            try FileManager.default.createDirectory(at: bloomFilterDirectory, withIntermediateDirectories: true)
//
//            // establishing a path for where the file will go:
//            let bloomFilterJsonFilePath = bloomFilterDirectory.appendingPathComponent("bloomFilter.json", isDirectory: false)
            
            // checks to see if there's a file at the path given
            guard FileManager.default.fileExists(atPath: filePath)
            else
            {
                print("File at path does not exist.")
                return
            }
            
            // takes the filePath string and changes it to a URL
            guard let pathUrl = URL.init(string: filePath)
            else
            {
                print("Could not create a URL from the filePath")
                return
            }
            
            // unsure if this appends or overwrites, test!
            try data.write(to: pathUrl)
            
        }
        catch (let jsonEncodeError)
        {
            print("Failed to encode Bloom as JSON: \(jsonEncodeError)")
            return
        }
    }
    
    func load(filePath: String)
    {
        
    }
}

// Cipher.generateRandomBytes(count: Int.random(in: 0..<6))


