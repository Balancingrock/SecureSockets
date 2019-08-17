// =====================================================================================================================
//
//  File:       CertificateAndPrivateKeyFiles.swift
//  Project:    SecureSockets
//
//  Version:    1.0.0
//
//  Author:     Marinus van der Lugt
//  Company:    http://balancingrock.nl
//  Website:    http://swiftfire.nl/projects/securesockets/securesockets.html
//  Git:        https://github.com/Balancingrock/SecureSockets
//
//  Copyright:  (c) 2016-2019 Marinus van der Lugt, All rights reserved.
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
// 1.0.0 - Removed older history
// =====================================================================================================================

import Foundation


/// The specification of a certificate file and the corresponding private key file. Will also check if the certificate public key and the private key form a pair.

public struct CertificateAndPrivateKeyFiles {
    
    
    /// The file with the certificate.
    
    public let certificate: EncodedFile
    
    
    /// The file with the private key.
    
    public let privateKey: EncodedFile
    
    
    /// Creates a new association of certificate and private key. It will be checked if the private key is paired with the public key that is contained in the certificate.
    ///
    /// - Parameter
    ///   - certificateFile: A file containing a certificate.
    ///   - privateKeyFile: A file containing a private key.
    ///   - errorProcessing: A closure that will be executed if an error is detected.
    
    public init?(certificateFile: EncodedFile, privateKeyFile: EncodedFile, errorProcessing: ((String) -> Void)? = nil) {
        
        self.certificate = certificateFile
        self.privateKey = privateKeyFile
        
        
        // Create a temporary CTX
        
        guard let ctx = ServerCtx() else {
            errorProcessing?("Failed to create a ServerCtx, message = '\(errPrintErrors())'")
            return nil
        }
        
        
        // Load the certificate into the CTX
        
        switch ctx.useCertificate(file: certificate) {
        case let .error(message): errorProcessing?(message); return nil
        case .success: break
        }
        
        
        // Load the private key into the CTX
        
        switch ctx.usePrivateKey(file: privateKey) {
        case let .error(message): errorProcessing?(message); return nil
        case .success: break
        }
        
        
        // Test if they belong together
        
        switch ctx.checkPrivateKey() {
        case let .error(message): errorProcessing?(message); return nil
        case .success: break
        }
    }
    
    
    /// Creates a new association of certificate and private key. It will be checked if the private key is paired with the public key that is contained in the certificate.
    ///
    /// - Parameters:
    ///   - certificateFile: Path to a file containing a certificate in the PEM format.
    ///   - privateKeyFile: Path to a file containing a private key in the PEM format.
    ///   - errorProcessing: A closure that will be executed if an error is detected.
    
    public init?(pemCertificateFile: String, pemPrivateKeyFile: String, errorProcessing: ((String) -> Void)? = nil) {
        
        
        // Wrap the certificate and private key in an EncodedFile
        
        let certificateFile = EncodedFile(path: pemCertificateFile, encoding: .pem)
        let privateKeyFile = EncodedFile(path: pemPrivateKeyFile, encoding: .pem)
        
        
        // Create the object
        
        self.init(certificateFile: certificateFile, privateKeyFile: privateKeyFile, errorProcessing: errorProcessing)
    }
}
