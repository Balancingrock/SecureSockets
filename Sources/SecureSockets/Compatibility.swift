// =====================================================================================================================
//
//  File:       Compatibility.swift
//  Project:    SecureSockets
//
//  Version:    1.1.1
//
//  Author:     Marinus van der Lugt
//  Company:    http://balancingrock.nl
//  Website:    http://swiftfire.nl/projects/securesockets/securesockets.html
//  Git:        https://github.com/Balancingrock/SecureSockets
//
//  Copyright:  (c) 2020 Marinus van der Lugt, All rights reserved.
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
// 1.1.1 - Initial version
//
// =====================================================================================================================

import Foundation
import Copenssl


// Note: Right now I see a difference between Xcode 11.5 and the Linux 18.04 distribution. I am not quite sure if this
// is a linux/macOS difference or a Swift version difference.

#if os(macOS) || os(iOS) || os(tvOS)

public typealias UnsafeMutablePointerBio = OpaquePointer
public typealias UnsafeMutablePointerEvpPkey = OpaquePointer
public typealias UnsafeMutablePointerSsl = OpaquePointer
public typealias UnsafePointerSsl = OpaquePointer
public typealias UnsafeMutablePointerSslCtx = OpaquePointer
public typealias UnsafeMutablePointerX509 = OpaquePointer
public typealias UnsafeMutablePointerX509Name = OpaquePointer

#endif

#if os(Linux)

public typealias UnsafeMutablePointerBio = UnsafeMutablePointer<Copenssl.BIO>
public typealias UnsafeMutablePointerEvpPkey = UnsafeMutablePointer<Copenssl.EVP_PKEY>
public typealias UnsafeMutablePointerSsl = UnsafeMutablePointer<Copenssl.SSL>
public typealias UnsafePointerSsl = UnsafePointer<Copenssl.SSL>
public typealias UnsafeMutablePointerSslCtx = UnsafeMutablePointer<Copenssl.SSL_CTX>
public typealias UnsafeMutablePointerX509 = UnsafeMutablePointer<Copenssl.X509>
public typealias UnsafeMutablePointerX509Name = UnsafeMutablePointer<Copenssl.X509_NAME>

#endif
