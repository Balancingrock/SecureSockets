// =====================================================================================================================
//
//  File:       SecureSockets.Accept.swift
//  Project:    SecureSockets
//
//  Version:    0.1.0
//
//  Author:     Marinus van der Lugt
//  Company:    http://balancingrock.nl
//  Website:    http://swiftfire.nl/pages/projects/securesockets/
//  Blog:       http://swiftrien.blogspot.com
//  Git:        https://github.com/Swiftrien/SecureSockets
//
//  Copyright:  (c) 2016-2017 Marinus van der Lugt, All rights reserved.
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
//  I strongly believe that the Non Agression Principle is the way for societies to function optimally. I thus reject
//  the implicit use of force to extract payment. Since I cannot negotiate with you about the price of this code, I
//  have choosen to leave it up to you to determine its price. You pay me whatever you think this code is worth to you.
//
//   - You can send payment via paypal to: sales@balancingrock.nl
//   - Or wire bitcoins to: 1GacSREBxPy1yskLMc9de2nofNv2SNdwqH
//
//  I prefer the above two, but if these options don't suit you, you can also send me a gift from my amazon.co.uk
//  whishlist: http://www.amazon.co.uk/gp/registry/wishlist/34GNMPZKAQ0OO/ref=cm_sw_em_r_wsl_cE3Tub013CKN6_wb
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
// v0.1.0 - Initial release
// =====================================================================================================================

import Foundation
import SwifterSockets
import COpenSsl


/// A handler with this signature can be invoked after the Ssl Accept (~ SSL_accept) completes.
///
/// - Parameter ssl: The SSL session.
/// - Parameter clientIp: The IP address of the client.
/// - Note: The return value of the closure can be used to deny a successfull Ssl Accept, but not to force an accept of a failed Ssl Accept. The main purpose of this is for logging and blacklisting.
/// - Returns: 'false' if the session should be terminated. 'true' otherwise.

public typealias SslSessionHandler = (_ ssl: Ssl, _ clientIp: String) -> Bool


/// The result for the accept function accept. Possible values are:
///
/// - accepted(socket: Int32, ssl: OpaquePointer, clientIp: String)
/// - error(message: String)
/// - timeout
/// - closed

public enum SslAcceptResult {
    
    
    /// A connection was accepted, the ssl session, the socket descriptor and the client IP adddress are enclosed
    
    case accepted(ssl: Ssl, socket: Int32, clientIp: String)
    
    
    /// An error occured, the error message is enclosed.
    
    case error(message: String)
    
    
    /// A timeout occured.
    
    case timeout
    
    
    /// Another thread closed the socket
    
    case closed
}


/// Accepts a secure connection request. First accepts a connection on TCP/IP level and then performs an SSL-Handshake with a call to SSL_accept.
///
/// - Parameter onSocket: The socket on which to accept incoming connection requests. This socket will not be closed by this function.
/// - Parameter useCtx: The context for the SSL structure that will be created for the connection.
/// - Parameter timeout: The maximum wait for a connection request.
/// - Parameter addressHandler: A closure that is invoked after the TCP/IP accept completes. Can be used to blacklist IP addresses or for logging purposes.
/// - Parameter sslSessionHandler: A closure that is invoked after the SSL_accept completes. Can be used for logging or other purposes.
///
/// - Returns: An AcceptResult.

public func sslAccept(
    onSocket acceptSocket: Int32,
    useCtx ctx: Ctx,
    timeout: TimeInterval,
    addressHandler: AddressHandler? = nil,
    sslSessionHandler: SslSessionHandler? = nil) -> SslAcceptResult {
    
    
    let timeoutTime = Date().addingTimeInterval(timeout)
    
    
    // =============================
    // Wait for a connection attempt
    // =============================
    
    let result = tipAccept(onSocket: acceptSocket, timeout: timeout, addressHandler: addressHandler)
    
    switch result {
    case .closed: return .closed
    case let .error(msg): return .error(message: msg)
    case .timeout: return .timeout
    case let .accepted(receiveSocket, clientIp):
        
        var closeReceiveSocketOnExit = true;
        defer { if closeReceiveSocketOnExit { close(receiveSocket) } }
        
        
        // =======================
        // Create a new SSL object
        // =======================
        
        guard let ssl = Ssl(context: ctx) else {
            let message = errPrintErrors()
            return .error(message: "SwifterSockets.Secure.accept: Failed to allocate a new SSL structure,\n\(message)")
        }
        
        switch ssl.setFd(receiveSocket) {
        case let .error(message): return .error(message: "SwifterSockets.Secure.accept: Could not set socket,\n\(message)")
        case .success: break
        }
        
        
        // ======================================
        // Wait for the SSL handshake to complete
        // ======================================
        
        SSL_ACCEPT_LOOP: while true {
            
            
            // ===================================
            // Try to establish the SSL connection
            // ===================================
            
            // Note: Unsure about the possible timeouts that apply to this call.
            
            let result = ssl.accept()
            switch result {
                
                
            // On success, return the new SSL structure
            case .completed:
                
                // An API user provided ssl session handler can reject this connection.
                
                if !(sslSessionHandler?(ssl, clientIp) ?? true) {
                    return .error(message: "SwifterSockets.Secure.accept: Ssl session rejected by SslSessionHandler")
                }
                
                
                // Prevent closing the socket
                
                closeReceiveSocketOnExit = false
                
                
                return .accepted(ssl: ssl, socket: receiveSocket, clientIp: clientIp)
                
                
            // Exit if the connection closed (i.e. there is no secure connection)
            case .zeroReturn: return .closed
                
                
            // Only waiting for a read or write is acceptable, everything else is an error
            case .wantRead:
                
                let selres = waitForSelect(socket: acceptSocket, timeout: timeoutTime, forRead: true, forWrite: false)
                
                switch selres {
                case .timeout: return .timeout
                case .closed: return .closed
                case let .error(message): return .error(message: "SwifterSockets.Secure.accept: Waiting for a read select returned an error,\n\(message)")
                case .ready: break
                }
                
                
            // Only waiting for a read or write is acceptable, everything else is an error
            case .wantWrite:
                
                let selres = waitForSelect(socket: acceptSocket, timeout: timeoutTime, forRead: false, forWrite: true)
                
                switch selres {
                case .timeout: return .timeout
                case .closed: return .closed
                case let .error(message): return .error(message: "SwifterSockets.Secure.accept: Waiting for a write select returned an error,\n\(message)")
                case .ready: break
                }
                
                
            // All of these are error's
            case .wantConnect, .wantAccept, .wantX509Lookup, .wantAsync, .wantAsyncJob, .syscall, .ssl, .bios_errno, .errorMessage, .undocumentedSslError, .undocumentedSslFunctionResult:
                return .error(message: "SwifterSockets.Secure.accept: An error occured,\n\(result.description)")
            }
        }
    }
}
