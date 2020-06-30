// =====================================================================================================================
//
//  File:       SslReceiverLoop.swift
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
// 1.0.0 - Removed older history
// =====================================================================================================================

import Foundation
import SwifterSockets
import Copenssl


/// Starts a receiver loop on an SSL session.
///
/// - Note: This operation does not close the socket or free the SSL structure when an error occurs.
///
/// - Note: This operation can resume transfers after a timeout occurs. I.e. after a timeout the operation can be called again with the same parameter values as before. This can be used to implement -for example- progress tracking.
///
/// - Parameters:
///   - ssl: The session to use.
///   - bufferSize: The size of the buffer that will be allocated for the data to be received.
///   - duration: The maximum duration of a single receive loop.
///   - receiver: The destination for the ReceiverProtocol method calls.

public func sslReceiverLoop(ssl: Ssl, bufferSize: Int, duration: TimeInterval, receiver: ReceiverProtocol?) {
    
    // Find programming errors
    
    assert (bufferSize > 0, "No space available in buffer")
    
    
    // The data buffer
    
    let buffer = UnsafeMutableRawPointer.allocate(byteCount: bufferSize, alignment: 8)
    
    
    // Get the socket that the SSL is bound to
    
    let socket = ssl.getFd()
    
    
    // ===============================================================================
    // This loop stays active as long as the consumer wants more and no error occured.
    // ===============================================================================
    
    var cont = true
    repeat {
        
        
        // Determine the timeout time
        
        let timeout = Date().addingTimeInterval(duration)
        
        
        // ==================================================
        // Use select for the timeout en to wait for activity
        // ==================================================
        
        let selres = waitForSelect(socket: socket, timeout: timeout, forRead: true, forWrite: true)
        
        switch selres {
            
        case .timeout:
            cont = receiver?.receiverLoop() ?? true
            
        case let .error(message):
            receiver?.receiverError(message)
            cont = false
            
        case .closed:
            receiver?.receiverClosed()
            cont = false
            
        case .ready:
            
            // =========
            // Read data
            // =========
            
            let result = ssl.read(buf: buffer.assumingMemoryBound(to: UInt8.self), num: Int32(bufferSize))
            
            switch result {
                
            // SSL has captured and decrypted data.
            case let .completed(bytesRead):
                cont = receiver?.receiverData(UnsafeBufferPointer<UInt8>(start:buffer.assumingMemoryBound(to: UInt8.self), count:Int(bytesRead))) ?? true
                
            // A clean shutdown of the connection occured. No more data forthcoming.
            case .zeroReturn:
                receiver?.receiverClosed()
                cont = false
                
            // Need to repeat the call to SSL_read with the exact same arguments as before.
            case .wantRead, .wantWrite: break
                
            // All off the following are error cases, none of these should happen.
            case .wantConnect, .wantAccept, .wantX509Lookup, .wantAsync, .wantAsyncJob, .syscall, .ssl, .undocumentedSslError, .undocumentedSslFunctionResult, .errorMessage, .bios_errno:
                
                receiver?.receiverError("An error occured during SSL_write, '\(result)' was reported.")
                cont = false
            }
        }
        
    } while cont
    
    buffer.deallocate()
}
