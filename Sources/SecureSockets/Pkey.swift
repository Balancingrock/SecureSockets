// =====================================================================================================================
//
//  File:       Pkey.swift
//  Project:    SecureSockets
//
//  Version:    1.1.0
//
//  Author:     Marinus van der Lugt
//  Company:    http://balancingrock.nl
//  Website:    http://swiftfire.nl/projects/securesockets/securesockets.html
//  Git:        https://github.com/Balancingrock/SecureSockets
//
//  Copyright:  (c) 2017-2020 Marinus van der Lugt, All rights reserved.
//
//  License:    Use or redistribute this code any way you like with the following two provision:
//
//  1) You ACCEPT this source code AS IS without any guarantees that it will work as intended. Any liability from its
//  use is YOURS.
//
//  2) You WILL NOT seek damages from the author or balancingrock.nl.
//
//  I also ask you to please leave this header with the source code.
//
//  Like you, I need to make a living:
//
//   - You can send payment (you choose the amount) via paypal to: sales@balancingrock.nl
//   - Or wire bitcoins to: 1GacSREBxPy1yskLMc9de2nofNv2SNdwqH
//
//  If you like to pay in another way, please contact me at rien@balancingrock.nl
//
//  Prices/Quotes for support, modifications or enhancements can be obtained from: rien@balancingrock.nl
//
// =====================================================================================================================
// PLEASE let me know about bugs, improvements and feature requests. (rien@balancingrock.nl)
// =====================================================================================================================
//
// History
//
// 1.1.0 - Switched to Swift.Result instead of BRUtils.Result
// 1.0.1 - Documentation update
// 1.0.0 - Removed older history
//
// =====================================================================================================================

import Foundation
import SwifterSockets
import COpenSsl


/// Returns a string containing the contents of the PEM structure.
///
/// - Parameter PEM_write_bio: A closure that writes the PEM content to the given BIO memory area.
///
/// - Returns: The content that was written to the BIO memory area interpreted as a String. Nil is there was an error, or nothing was written to the BIO area.

public func getStringFrom(PEM_write_bio closure: (OpaquePointer) -> Int32) -> String? {
    
    
    // Allocate BIO_mem area (don't use a file because that could expose vital data)
    
    guard let bio = BIO_new(BIO_s_mem()) else { return nil }
    defer { BIO_free(bio) }
    
    
    // Execute the PEM_write_bio... function
    
    let result = closure(bio)
    if result == 0 { return nil }
    
    
    // Move the data from the BIO_mem area into a Data type
    
    var data = Data()
    let buffer = UnsafeMutableRawPointer.allocate(byteCount: 1024, alignment: 8)
    defer { buffer.deallocate() }
    var nofBytes = BIO_read(bio, buffer, 1024)
    while nofBytes > 0 {
        data.append(buffer.assumingMemoryBound(to: UInt8.self), count: Int(nofBytes))
        nofBytes = BIO_read(bio, buffer, 1024)
    }
    
    
    // Convert the Data to a String type and return that
    
    return String.init(data: data, encoding: String.Encoding.utf8) ?? "String conversion error"
}


/// A wrapper class for the openSSL EVP_PKEY structure.

open class Pkey {
    
    
    /// The pointer to the openSSL EVP_PKEY structure
    
    public private(set) var optr: OpaquePointer!
    
    
    /// If this string is set, then a private key will be encrypted with this passphrase.
    ///
    /// This can add a level of security when private keys must be transferred or are kept in a place that is accesable by others than just the security administrator.
    
    public var privateKeyPassphrase: String?

    
    /// Allocate space for a new EVP_PKEY structure.
    
    public init?() {
        self.optr = EVP_PKEY_new()
        if optr == nil { return nil }
    }
    
    
    /// If this function fails, errno may hold a file system error, or errPrintErrors() may contain error information.
    ///
    /// - Parameters:
    ///   - withPublicKeyFile: The path to file containing a public key
    
    public init?(withPublicKeyFile path: String) {
        
        
        // Open the file with the public key
        
        guard let file = fopen(path, "r") else { return nil }
        defer { fclose(file) }
        
        
        // Read the key from the file and put it in a new ENV_PKEY structure
        
        guard let pkey = PEM_read_PUBKEY(file, nil, nil, nil) else {
            // nil = Failure
            // Note: the documentation does not mention it, but in case of errors there may be info in the error stack
            return nil
        }
        
        self.optr = pkey
    }
    
    
    /// If this function fails, errno may hold a file system error, or errPrintErrors() may contain error information.
    ///
    /// - Parameters:
    ///   - withPrivateKeyFile: The path to file containing a private key
    
    public init?(withPrivateKeyFile path: String) {
        
        
        // Open the file with the public key
        
        guard let file = fopen(path, "r") else { return nil }
        defer { fclose(file) }
        
        
        // Read the key from the file and put it in a new ENV_PKEY structure

        guard let pkey = PEM_read_PrivateKey(file, nil, nil, nil) else {
            // nil in case of failure, a pointer to pkey on success.
            // Note: The OpenSSL doc does not say that there will be error information in the stack but it hints at it by referring to the ERR_get_error.
            return nil
        }
        
        self.optr = pkey
    }

    
    /// Frees the openSSL structure.
    
    deinit {
        EVP_PKEY_free(optr)
    }
    
    
    /// - Returns: The private key if there is any. If the passphrase is set, then the private key will be encrypted with this passphrase before it is returned. If nil is returned errPrintErrors() may contain information about an error.
    
    public var privateKey: String? {
        
        return getStringFrom(
            
            PEM_write_bio: {
            
                (bio) -> Int32 in
            
                if var passphrase = privateKeyPassphrase, !passphrase.isEmpty {
                    let count = passphrase.utf8.count
                    return withUnsafeMutablePointer(to: &passphrase) { (p) -> Int32 in
                        let ptr = UnsafeMutableRawPointer(p).bindMemory(to: Int8.self, capacity: count)
                        return PEM_write_bio_PKCS8PrivateKey(bio, optr, EVP_des_ede3_cbc(), ptr, Int32(count), nil, nil)
                    }
                } else {
                    return PEM_write_bio_PKCS8PrivateKey(bio, optr, nil, nil, 0, nil, nil)
                }
            }
        )
    }
    
    
    /// Returns the public key is there is one. If it returns nil while a key is expected, the errPrintErrors() operation may hold an error message that explains why.
    ///
    /// - Returns: The public key or nil.
    
    public var publicKey: String? {
        
        return getStringFrom(
            PEM_write_bio: {
                (bio) -> Int32 in
                return PEM_write_bio_PUBKEY(bio, optr)
            }
        )
    }

    
    /// Create a new RSA key pair and assign it to this object.
    ///
    /// - Parameters:
    ///   - withLength: The size for the keys. It is advised to use at least 4096 bits.
    ///   - andExponent: An often used exponent is 2^16 + 1 = 65537
    ///
    /// - Returns: Either .success(true) or .error(message: String)
    
    public func assignNewRsa(withLength length: Int32, andExponent exponent: Int) -> Result<Bool, SecureSocketsError> {
        
        
        // Create a BIGNUM for the exponent
        
        var exp = BN_new()
        guard exp != nil else {
            return .failure(SecureSocketsError.message("\(#file).\(#function).\(#line): Failed to create a BigNumber"))
        }
        defer { BN_free(exp) }
        
        
        // Set the exponent value
        
        let result = BN_dec2bn(&exp, exponent.description)
        if result == 0 {
            return .failure(SecureSocketsError.message("\(#file).\(#function).\(#line): BigNumber could not set value"))
        }
        
        
        // Create the RSA key pair
        
        guard let rsa = RSA_new() else {
            return .failure(SecureSocketsError.message("\(#file).\(#function).\(#line): Could not create new RSA structure"))
        }
        // Will be freed when the pkey (later) is freed.
        
        
        // Generate the keys
        
        if RSA_generate_key_ex(rsa, length, exp, nil) == 0 {
            return .failure(SecureSocketsError.message("\(#file).\(#function).\(#line): RSA_generate_key_ex failure, error stack = \(SecureSockets.errPrintErrors())"))
        }
        
        
        // Assign the key-pair so that the keys can be extracted through PEM
        
        if EVP_PKEY_assign(optr, EVP_PKEY_RSA, UnsafeMutablePointer(rsa)) == 0 {
            
            // Normally the 'rsa' is freed when the 'pkey' is freed, but the assignment failed, so it seems reasonable to assume that the 'rsa' must be freed manually.
            // Since it is extremely unlikely that the assigment fails, this line of code is probably never executed during testing, so beware!
            defer { RSA_free(rsa) }
            return .failure(SecureSocketsError.message("\(#file).\(#function).\(#line): EVP_PKEY_assign failure, error stack = \(SecureSockets.errPrintErrors())"))
        }

        return .success(true)
    }
    
    
    /// Write the private key to file (encrypted if a privateKey passphrase is present).
    ///
    /// - Parameter to: The URL for the file to be written.
    ///
    /// - Returns: Either .success(true) or .error(message: String)

    public func writePrivateKey(to url: URL) -> Result<Bool, SecureSocketsError> { return writePrivateKey(to: url.path) }
    
    
    /// Write the private key to file (encrypted if a privateKey passphrase is present).
    ///
    /// - Parameter to: The path for the file to be written.
    ///
    /// - Returns: Either .success(true) or .error(message: String)

    public func writePrivateKey(to filepath: String) -> Result<Bool, SecureSocketsError> {
        
        
        // Open the file
        
        guard let file = fopen(filepath, "w") else {
            return .failure(SecureSocketsError.message("\(#file).\(#function).\(#line): Failed to open file \(filepath) for writing"))
        }
        defer { fclose(file) }

        
        // Write the key to file
        
        var result: Int32
        
        if var passphrase = privateKeyPassphrase, !passphrase.isEmpty {
            let count = passphrase.utf8.count
            result = withUnsafeMutablePointer(to: &passphrase) { (p) -> Int32 in
                let ptr = UnsafeMutableRawPointer(p).bindMemory(to: Int8.self, capacity: count)
                return PEM_write_PKCS8PrivateKey(file, optr, EVP_des_ede3_cbc(), ptr, Int32(count), nil, nil)
            }
        } else {
            result = PEM_write_PKCS8PrivateKey(file, optr, nil, nil, 0, nil, nil)
        }
        
        if result != 1 {
            return .failure(SecureSocketsError.message("\(#file).\(#function).\(#line): Failed to write the private key to file \(filepath)"))
        } else {
            return .success(true)
        }
    }
    
    
    /// Write the public key to file
    ///
    /// - Parameter to: The URL for the file to be written.
    ///
    /// - Returns: Either .success(true) or .error(message: String)

    public func writePublicKey(to url: URL) -> Result<Bool, SecureSocketsError> { return writePublicKey(to: url.path) }

    
    /// Write the public key to file
    ///
    /// - Parameter to: The path for the file to be written.
    ///
    /// - Returns: Either .success(true) or .error(message: String)

    public func writePublicKey(to filepath: String) -> Result<Bool, SecureSocketsError> {
        
        
        // Open the file
        
        guard let file = fopen(filepath, "w") else {
            return .failure(SecureSocketsError.message("\(#file).\(#function).\(#line): Failed to open file \(filepath) for writing"))
        }
        defer { fclose(file) }
        
        
        // Write the key to file

        if PEM_write_PUBKEY(file, optr) != 1 {
            return .failure(SecureSocketsError.message("\(#file).\(#function).\(#line): Failed to write the public key to file \(filepath)"))
        }
        
        return .success(true)
    }
}
