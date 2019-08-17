// =====================================================================================================================
//
//  File:       FileEncoding.swift
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

import COpenSsl


/// The supported filetypes for keys and certificates.

public enum FileEncoding {
    
    
    // ANS1 contains 1 key or certificate per file.
    
    case ans1
    
    
    // PEM formats can contain multiple certificates and/or keys per file. Often only the first one is used.
    
    case pem
    
    
    // The SSL file encoding constant for this item.
    
    var asInt32: Int32 {
        switch self {
        case .ans1: return SSL_FILETYPE_ASN1
        case .pem:  return SSL_FILETYPE_PEM
        }
    }
}


/// The specification of a file containing a key or certificate.

public struct EncodedFile {
    
    
    /// The path of the file.
    
    let path: String
    
    
    /// The type of file.
    
    let encoding: Int32
    
    
    /// Creates a new EncodedFile.
    ///
    /// - Parameter
    ///   - path: The path of the file.
    ///   - encoding: The type of the file.
    
    public init(path: String, encoding: FileEncoding) {
        self.path = path
        self.encoding = encoding.asInt32
    }
}




