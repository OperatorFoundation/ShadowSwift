//
//  BloomFilter.swift
//  
//
//  Created by Joshua Clark on 1/23/22.
//

import Foundation
import Transport

let bloomFilterFilename = "BloomFilter.json"

// BloomFilter is a generic type with a type argument, Data.
// Data must conform to Hashable rules/protocol for code to work.
// Entire struct must conform to Codeable.
public class BloomFilter<filterData: Hashable>: Codable
{
    private var data: [Bool]
    private let seeds: [Int]
    
    private var saveURL: URL?
    
    // init gives our variables a value
    public init(size: Int, hashCount: Int)
    {
        // data creates an empty array (for the salts to go)
        data = Array(repeating: false, count: size)
        // seeds here are generating random numbers to be mapped
        seeds = (0..<hashCount).map({ _ in Int.random(in: 0..<Int.max) })
    }
    
    private init(data: [Bool], seeds: [Int])
    {
        self.data = data
        self.seeds = seeds
    }
    
    /// Initializes a bloom filter with (size: 512,  hashCount: 3) and saves it
    convenience init(saveURL: URL? = nil)
    {
        self.init(size: 512, hashCount: 3)
        
        if let saveURL = saveURL
        {
            guard self.save(pathURL: saveURL) else
            {
                // print("Failed to initialize and save a new BloomFilter at \(saveURL.path)")
                return
            }
        }
        else
        {
            guard let bloomFilterURL = getBloomFileURL() else
            {
                // print("Could not save a new bloom filter, we could not find the application support directory.")
                return
            }
            
            guard self.save(pathURL: bloomFilterURL) else
            {
                // print("Failed to initialize and save a new BloomFilter at \(bloomFilterURL.path)")
                return
            }
        }
    }
    
    // This initializer will load a bloom filter if it already exists as a JSON file at the file path
    // Or it will create a new one and save it at that path
    public convenience init?(withFileAtPath filePath: String)
    {
        if FileManager.default.fileExists(atPath: filePath)
        {
            // If the file exists, load it
            let jsonDecoder = JSONDecoder()
            let url = URL(fileURLWithPath: filePath)
            
            do
            {
                let data = try Data(contentsOf: url)
                let decoded = try jsonDecoder.decode(BloomFilter.self, from: data)
                self.init(data: decoded.data, seeds: decoded.seeds)
                self.saveURL = URL(fileURLWithPath: filePath)
                
            }
            catch
            {
                // print("Failed to decode Bloom from JSON: \(error)")
                return nil
            }
            
        }
        else
        {
            // Otherwise make a new one
            self.init(saveURL: URL(fileURLWithPath: filePath))
        }
    }
    
    // here we are putting the salt into the Data array
    // data[hash % data.count] is a placefinder so it knows what spot in the array to put it in
    func insert(_ salt: filterData)
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
    // read the comment section of Swift.Hashing for more info
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
    func save(pathURL: URL) -> Bool
    {
        // create an encoder
        let jsonEncoder = JSONEncoder()
        
        do
        {
            // try to encode self as JSON data
            let data = try jsonEncoder.encode(self)
            var fileURL: URL
            var directoryURL: URL
            
            // filePath provided is a directory. Does not include filename
            if pathURL.isDirectory
            {
                // add a filename to the path provided for fileURL
                fileURL = pathURL.appendingPathComponent("BloomFilter.json")
                // filePath is a directory
                directoryURL = pathURL
            }
            // filePath provided includes the filename
            else
            {
                // user provided the complete filePath
                // save the URL version of this to fileURL
                fileURL = pathURL
                // create directoryURL by removing the filename from the path provided
                directoryURL = pathURL.deletingLastPathComponent()
            }
            
            // create the directory if it doesn't exist
            try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
            
            // check to see if there's a file at the path given
            // delete it if there is
            if FileManager.default.fileExists(atPath: fileURL.path)
            {
                try FileManager.default.removeItem(atPath: fileURL.path)
            }
            
            // save the JSON data to fileURL
            try data.write(to: fileURL)
            
        }
        catch
        {
            // print("Failed to encode Bloom as JSON: \(error)")
            return false
        }
        
        return true
    }
    
    func getBloomFileURL() -> URL?
    {
        if let saveURL = saveURL
        {
             return saveURL
        }
        else
        {
            guard let supportDirectoryURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else
            {
                // print("Could not get application support directory path.")
                
                return nil
            }
            
            let bloomFilterURL = supportDirectoryURL.appendingPathComponent(bloomFilterFilename)
            
            return bloomFilterURL
        }
    }
}

extension URL
{
    public var isDirectory: Bool
    {
        (try? resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory == true
    }
}

// Cipher.generateRandomBytes(count: Int.random(in: 0..<6))


