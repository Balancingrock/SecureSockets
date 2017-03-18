// =====================================================================================================================
//
//  File:       SecureSockets.Pkey.swift
//  Project:    SecureSockets
//
//  Version:    0.4.0
//
//  Author:     Marinus van der Lugt
//  Company:    http://balancingrock.nl
//  Website:    http://swiftfire.nl/projects/securesockets/securesockets.html
//  Blog:       http://swiftrien.blogspot.com
//  Git:        https://github.com/Balancingrock/SecureSockets
//
//  Copyright:  (c) 2017 Marinus van der Lugt, All rights reserved.
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
//  I strongly believe that voluntarism is the way for societies to function optimally. Thus I have choosen to leave it
//  up to you to determine the price for this code. You pay me whatever you think this code is worth to you.
//
//   - You can send payment via paypal to: sales@balancingrock.nl
//   - Or wire bitcoins to: 1GacSREBxPy1yskLMc9de2nofNv2SNdwqH
//
//  I prefer the above two, but if these options don't suit you, you can also send me a gift from my amazon.co.uk
//  wishlist: http://www.amazon.co.uk/gp/registry/wishlist/34GNMPZKAQ0OO/ref=cm_sw_em_r_wsl_cE3Tub013CKN6_wb
//
//  If you like to pay in another way, please contact me at rien@balancingrock.nl
//
//  (It is always a good idea to visit the website/blog/google to ensure that you actually pay me and not some imposter)
//
//  For private and non-profit use the suggested price is the price of 1 good cup of coffee, say $4.
//  For commercial use the suggested price is the price of 1 good meal, say $20.
//
//  You are however encouraged to pay more ;-)
//
//  Prices/Quotes for support, modifications or enhancements can be obtained from: rien@balancingrock.nl
//
// =====================================================================================================================
// PLEASE let me know about bugs, improvements and feature requests. (rien@balancingrock.nl)
// =====================================================================================================================
//
// History
//
// 0.4.0  - Added and improved functions
// 0.3.3  - Comment section update
//        - Reassigned access levels
// 0.3.1  - Updated documentation for use with jazzy.
// 0.3.0  - Fixed error message text
// 0.1.0  - Initial release
// =====================================================================================================================

import Foundation
import SwifterSockets
import COpenSsl


public func getStringFrom(PEM_write_bio closure: (OpaquePointer) -> Int32) -> String? {
    
    
    // Allocate BIO_mem area (don't use a file because that could expose vital data)
    
    guard let bio = BIO_new(BIO_s_mem()) else { return nil }
    defer { BIO_free(bio) }
    
    
    // Execute the PEM_write_bio... function
    
    let result = closure(bio)
    if result == 0 { return nil }
    
    
    // Move the data from the BIO_mem area into a Data type
    
    var data = Data()
    let buffer = UnsafeMutableRawPointer.allocate(bytes: 1024, alignedTo: 1)
    defer { buffer.deallocate(bytes: 1024, alignedTo: 1) }
    var nofBytes = BIO_read(bio, buffer, 1024)
    while nofBytes > 0 {
        data.append(buffer.assumingMemoryBound(to: UInt8.self), count: Int(nofBytes))
        nofBytes = BIO_read(bio, buffer, 1024)
    }
    
    
    // Convert the Data to a String type and return that
    
    return String.init(data: data, encoding: String.Encoding.utf8) ?? "String conversion error"
}


/// A wrapper class for the EVP_PKEY structure.

open class Pkey {
    
    
    public private(set) var optr: OpaquePointer!
    
    
    /// If this string is set, then a private key will be encrypted with this passphrase.
    
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
    
    
    /// - Returns: The private key if there is any. If the passphrase is set, then the private key will be encrypted with this passphrase before it is returned. If nil is returned errPrintErrors() may contain iformation about an error.
    
    public var privateKey: String? {
        
        return getStringFrom(
            
            PEM_write_bio: {
            
                (bio) -> Int32 in
            
                if let passphrase = privateKeyPassphrase, !passphrase.isEmpty {
                    return PEM_write_bio_PKCS8PrivateKey(bio, optr, EVP_des_ede3_cbc(), UnsafeMutablePointer<CChar>(mutating: passphrase), Int32(passphrase.utf8.count), nil, nil)
                } else {
                    return PEM_write_bio_PKCS8PrivateKey(bio, optr, nil, nil, 0, nil, nil)
                }
            }
        )
    }
    
    
    /// - Returns: The public key if there is any. If nil is returned errPrintErrors() may contain iformation about an error.
    
    public var publicKey: String? {
        
        return getStringFrom(
            PEM_write_bio: {
                (bio) -> Int32 in
                return PEM_write_bio_PUBKEY(bio, optr)
            }
        )
    }

    
    /// Create a new RSA key and assign it to this object.
    
    public func assignNewRsa(withLength length: Int32, andExponent exponent: Int) -> Result<Bool> {
        
        
        // Create a BIGNUM for the exponent
        
        var exp = BN_new()
        guard exp != nil else {
            return .error(message: "Securesockets.Pkey.Pkey.assignNewRsa: Failed to create a BigNumber")
        }
        defer { BN_free(exp) }
        
        
        // Set the exponent value
        
        var result = BN_dec2bn(&exp, exponent.description)
        if result == 0 {
            return .error(message: "Securesockets.Pkey.Pkey.assignNewRsa: BigNumber could not set value")
        }
        
        
        // Create the RSA key pair
        
        guard let rsa = RSA_new() else {
            return .error(message: "Securesockets.Pkey.Pkey.assignNewRsa: Could not create new RSA structure")
        }
        // Will be freed when the pkey (later) is freed.
        
        
        // Generate the keys
        
        if RSA_generate_key_ex(rsa, length, exp, nil) == 0 {
            return .error(message: SecureSockets.errPrintErrors())
        }
        
        
        // Assign the key-pair so that the keys can be extracted through PEM
        
        if EVP_PKEY_assign(optr, EVP_PKEY_RSA, UnsafeMutablePointer(rsa)) == 0 {
            
            // Normally the 'rsa' is freed when the 'pkey' is freed, but the assignment failed, so it seems reasonable to assume that the 'rsa' must be freed manually.
            // Since it is extremely unlikely that the assigment fails, this line of code is probably never executed during testing, so beware!
            defer { RSA_free(rsa) }
            return .error(message: SecureSockets.errPrintErrors())
        }

        return .success(true)
    }
    
    
    /// Write the private key to file (encrypted if a privateKey passphrase is present)

    public func writePrivateKey(to url: URL) -> Result<Bool> { return writePrivateKey(to: url.path) }
    
    
    /// Write the private key to file (encrypted if a privateKey passphrase is present)
    
    public func writePrivateKey(to filepath: String) -> Result<Bool> {
        
        
        // Open the file
        
        guard let file = fopen(filepath, "w") else {
            return .error(message: "Securesockets.Pkey.Pkey.writePrivateKeyToFile: Failed to open file \(filepath) for writing")
        }
        defer { fclose(file) }

        
        // Write the key to file
        
        var result: Int32
        
        if let passphrase = privateKeyPassphrase, !passphrase.isEmpty {
            result = PEM_write_PKCS8PrivateKey(file, optr, EVP_des_ede3_cbc(), UnsafeMutablePointer<CChar>(mutating: passphrase), Int32(passphrase.utf8.count), nil, nil)
        } else {
            result = PEM_write_PKCS8PrivateKey(file, optr, nil, nil, 0, nil, nil)
        }
        
        if result != 1 {
            return .error(message: "Securesockets.Pkey.Pkey.writePrivateKeyToFile: Failed to write the private key to file \(filepath)")
        } else {
            return .success(true)
        }
    }
    
    
    /// Write the public key to file
    
    public func writePublicKey(to url: URL) -> Result<Bool> { return writePublicKey(to: url.path) }

    
    /// Write the public key to file
    
    public func writePublicKey(to filepath: String) -> Result<Bool> {
        
        
        // Open the file
        
        guard let file = fopen(filepath, "w") else {
            return .error(message: "Securesockets.Pkey.Pkey.writePublicKeyToFile: Failed to open file \(filepath) for writing")
        }
        defer { fclose(file) }
        
        
        // Write the key to file

        if PEM_write_PUBKEY(file, optr) != 1 {
            return .error(message: "Securesockets.Pkey.Pkey.writePublicKeyToFile: Failed to write the public key to file \(filepath)")
        }
        
        return .success(true)
    }
}
