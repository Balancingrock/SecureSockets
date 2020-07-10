// =====================================================================================================================
//
//  File:       SslTransfer.swift
//  Project:    SecureSockets
//
//  Version:    1.1.6
//
//  Author:     Marinus van der Lugt
//  Company:    http://balancingrock.nl
//  Website:    http://swiftfire.nl/projects/securesockets/securesockets.html
//  Git:        https://github.com/Balancingrock/SecureSockets
//
//  Copyright:  (c) 2016-2020 Marinus van der Lugt, All rights reserved.
//
//  License:    MIT, see LICENSE file
//
//  And because I need to make a living:
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
// 1.1.6 - Updated LICENSE
// 1.1.1 - Linux compatibility
// 1.0.1 - Documentation update
// 1.0.0 - Removed older history
//
// =====================================================================================================================

import Foundation
import SwifterSockets
import Copenssl


/// Transmits the buffer content using a SSL session.
///
/// - Parameters:
///   - ssl: The ssl session to use.
///   - buffer: A pointer to a buffer containing the bytes to be transferred.
///   - timeout: The time in seconds for the complete transfer attempt.
///   - callback: The destination for the TransmitterProtocol methods calls.
///   - progress: The closure to invoke for progress monitoring. Note that progress monitoring for ssl connections is near impossible. While the progress closure can be invoked several times during a transfer it is not possible to indicate how many bytes have been transferred. For that reason on all calls, the bytesTransferred will be zero.
///
/// - Returns: See the TransferResult definition.

@discardableResult
public func sslTransfer(ssl: Ssl, buffer: UnsafeBufferPointer<UInt8>, timeout: TimeInterval, callback: TransmitterProtocol?, progress: TransmitterProgressMonitor?) -> TransferResult {
    
    
    let id = Int(bitPattern: buffer.baseAddress)
    
    
    // Get the socket
    
    let socket = ssl.getFd()
    if socket < 0 {
        _ = progress?(0, 0)
        callback?.transmitterError(id, "Missing filedescriptor from SSL")
        return .error(message: "SecureSockets.SslTransfer.sslTransfer: Missing filedescriptor from SSL")
    }
    
    
    // Check if there is data to transmit
    
    if buffer.count == 0 {
        _ = progress?(0, 0)
        callback?.transmitterReady(id)
        return .ready
    }
    
    
    // Set the cut-off for the timeout
    
    let timeoutTime = Date().addingTimeInterval(timeout)
    
    
    // =================================================================================
    // A loop is needed becuse the SSL layer can return with the request to 'call again'
    // =================================================================================
    
    while true {
        
        
        // ==================================================
        // Use select for the timout and to wait for activity
        // ==================================================
        
        let selres = waitForSelect(socket: socket, timeout: timeoutTime, forRead: true, forWrite: true)
        
        switch selres {
        case .timeout:
            _ = progress?(0, buffer.count)
            callback?.transmitterTimeout(id)
            return .timeout
        
        case let .error(message):
            _ = progress?(0, buffer.count)
            callback?.transmitterError(id, message)
            return .error(message: message)
            
        case .closed:
            _ = close(socket)
            _ = progress?(0, buffer.count)
            callback?.transmitterClosed(id)
            return .closed
        
        case .ready: break
        }
        
        
        // =====================
        // Call out to SSL_write
        // =====================
        
        let result = ssl.write(buf: UnsafeRawPointer(buffer.baseAddress!), num: Int32(buffer.count))
        
        switch result {
            
            
        // SSL has transmitted all data.
        case .completed:
            _ = progress?(0, buffer.count)
            callback?.transmitterReady(id)
            return .ready
            
            
        // A clean shutdown of the connection occured.
        case .zeroReturn:
            _ = close(socket)
            _ = progress?(0, buffer.count)
            callback?.transmitterClosed(id)
            return .closed
            
            
        // Need to repeat the call to SSL_read with the exact same arguments as before.
        case .wantRead, .wantWrite:
            if !(progress?(0, buffer.count) ?? true) {
                _ = progress?(buffer.count, buffer.count)
                callback?.transmitterReady(id)
                return .ready
            }
            break
            
            
        // All error cases, none of these should be possible.
        case .wantConnect, .wantAccept, .wantX509Lookup, .wantAsync, .wantAsyncJob, .syscall, .undocumentedSslError, .undocumentedSslFunctionResult, .ssl, .bios_errno, .errorMessage:
            
            return .error(message: "SecureSockets.SslTransfer.sslTransfer: error during SSL_write, '\(result)' was reported")
        }
    }
}


/// Transmits the content of the data object using a SSL session.
///
/// - Parameters:
///   - ssl: The ssl session to use.
///   - data: The data object containing the bytes to be transferred.
///   - timeout: The time in seconds for the complete transfer attempt.
///   - callback: The destination for the TransmitterProtocol methods calls.
///   - progress: The closure to invoke for progress monitoring. Note that progress monitoring for ssl connections is near impossible. While the progress closure can be invoked several times during a transfer it is not possible to indicate how many bytes have been transferred. For that reason on all calls, the bytesTransferred will be zero.
///
/// - Returns: See the TransferResult definition.

@discardableResult
public func sslTransfer(ssl: Ssl, data: Data, timeout: TimeInterval, callback: TransmitterProtocol?, progress: TransmitterProgressMonitor?) -> TransferResult {
    
    return data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> TransferResult in
        return sslTransfer(ssl: ssl, buffer: buffer.bindMemory(to: UInt8.self), timeout: timeout, callback: callback, progress: progress)
    }
}


/// Transmits the string utf-8 encoded using a SSL session.
///
/// - Parameters:
///   - ssl: The ssl session to use.
///   - string: The string to be transferred encoded as utf-8.
///   - timeout: The time in seconds for the complete transfer attempt.
///   - callback: The destination for the TransmitterProtocol methods calls.
///   - progress: The closure to invoke for progress monitoring. Note that progress monitoring for ssl connections is near impossible. While the progress closure can be invoked several times during a transfer it is not possible to indicate how many bytes have been transferred. For that reason on all calls, the bytesTransferred will be zero.
///
/// - Returns: See the TransferResult definition.

@discardableResult
public func sslTransfer(ssl: Ssl, string: String, timeout: TimeInterval, callback: TransmitterProtocol?, progress: TransmitterProgressMonitor?) -> TransferResult {
    
    if let data = string.data(using: String.Encoding.utf8) {
        return sslTransfer(ssl: ssl, data: data, timeout: timeout, callback: callback, progress: progress)
    } else {
        _ = progress?(0, 0)
        callback?.transmitterError(0, "Cannot convert string to UTF8")
        return .error(message: "SecureSockets.SslTransfer.sslTransfer: Cannot convert string to UTF8")
    }
}
