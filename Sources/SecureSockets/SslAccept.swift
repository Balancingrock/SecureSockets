// =====================================================================================================================
//
//  File:       SslAccept.swift
//  Project:    SecureSockets
//
//  Version:    1.1.1
//
//  Author:     Marinus van der Lugt
//  Company:    http://balancingrock.nl
//  Website:    http://swiftfire.nl/projects/securesockets/securesockets.html
//  Git:        https://github.com/Balancingrock/SecureSockets
//
//  Copyright:  (c) 2016-2020 Marinus van der Lugt, All rights reserved.
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
// 1.1.1 - Linux compatibility
// 1.0.1 - Documentation update
// 1.0.0 - Removed older history
// =====================================================================================================================

import Foundation
import SwifterSockets
import Copenssl


/// A closure with this signature can be invoked after an Ssl.accept completes.
///
/// - Note: The return value of the closure can be used to deny a successfull Ssl Accept, but not to force an accept of a failed Ssl Accept. The main purpose of this is for logging and blacklisting.
///
/// - Parameter ssl: The SSL session.
/// - Parameter clientIp: The IP address of the client.
///
/// - Returns: 'false' if the session should be terminated. 'true' to continue.

public typealias SslSessionHandler = (_ ssl: Ssl, _ clientIp: String) -> Bool


/// The result for the sslAccept function.

public enum SslAcceptResult {
    
    
    /// A session was accepted.
    ///
    /// - Parameter ssl: The ssl-session
    /// - Parameter socket: The socket that is used
    /// - Parameter clientIp: The IP adddress of the peer
    
    case accepted(ssl: Ssl, socket: Int32, clientIp: String)
    
    
    /// An error occured.
    ///
    /// Parameter message: A textual description of the error.
    
    case error(message: String)
    
    
    /// A timeout occured.
    
    case timeout
    
    
    /// Somebody else (another thread or the peer) closed the socket
    
    case closed
}


/// Accepts a secure connection request. First accepts a connection on TCP/IP level and then performs an SSL level accept.
///
/// - Parameters:
///   - acceptSocket: The socket on which to accept incoming connection requests. This socket will not be closed by this function.
///   - ctx: The context for the SSL structure that will be created for the accepted connection.
///   - timeout: The maximum wait for a connection request.
///   - addressHandler: A closure that is invoked after the TCP/IP accept completes. Can be used to blacklist IP addresses or for logging purposes.
///   - sslSessionHandler: A closure that is invoked after the SSL_accept completes. Can be used for logging or other purposes.
///
/// - Returns: See SslAcceptResult definition.

public func sslAccept(onSocket acceptSocket: Int32, useCtx ctx: Ctx, timeout: TimeInterval, addressHandler: AddressHandler? = nil, sslSessionHandler: SslSessionHandler? = nil) -> SslAcceptResult {
    
    
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
            return .error(message: "\(#file).\(#function).\(#line): Failed to allocate a new SSL structure,\n\(message)")
        }
        
        switch ssl.setFd(receiveSocket) {
        case let .failure(message): return .error(message: "\(#file).\(#function).\(#line): Could not set socket,\n\(message.localizedDescription)")
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
                    return .error(message: "SecureSockets.SslAccept.sslAccept: Ssl session rejected by SslSessionHandler")
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
                case let .error(message): return .error(message: "SecureSockets.SslAccept.sslAccept: Waiting for a read select returned an error,\n\(message)")
                case .ready: break
                }
                
                
            // Only waiting for a read or write is acceptable, everything else is an error
            case .wantWrite:
                
                let selres = waitForSelect(socket: acceptSocket, timeout: timeoutTime, forRead: false, forWrite: true)
                
                switch selres {
                case .timeout: return .timeout
                case .closed: return .closed
                case let .error(message): return .error(message: "SecureSockets.SslAccept.sslAccept: Waiting for a write select returned an error,\n\(message)")
                case .ready: break
                }
                
                
            // All of these are error's
            case .wantConnect, .wantAccept, .wantX509Lookup, .wantAsync, .wantAsyncJob, .syscall, .ssl, .bios_errno, .errorMessage, .undocumentedSslError, .undocumentedSslFunctionResult:
                return .error(message: "SecureSockets.SslAccept.sslAccept: An error occured,\n\(result.description)")
            }
        }
    }
}
