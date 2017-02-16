// =====================================================================================================================
//
//  File:       SecureSockets.Transmit.swift
//  Project:    SecureSockets
//
//  Version:    0.3.4
//
//  Author:     Marinus van der Lugt
//  Company:    http://balancingrock.nl
//  Website:    http://swiftfire.nl/projects/securesockets/securesockets.html
//  Blog:       http://swiftrien.blogspot.com
//  Git:        https://github.com/Balancingrock/SecureSockets
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
// 0.3.4  - Added callback and progress activations.
// 0.3.3  - Comment section update
// 0.3.1  - Updated documentation for use with jazzy.
// 0.3.0  - Fixed error message text (removed reference to SwifterSockets.Secure)
// 0.1.0  - Initial release
// =====================================================================================================================

import Foundation
import SwifterSockets
import COpenSsl


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
        return .error(message: "SecureSockets.Transmit.sslTransfer: Missing filedescriptor from SSL")
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
            
            return .error(message: "SecureSockets.Transmit.sslTransfer: error during SSL_write, '\(result)' was reported")
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
    
    return data.withUnsafeBytes { (ptr: UnsafePointer<UInt8>) -> TransferResult in
        let ubptr = UnsafeBufferPointer<UInt8>.init(start: ptr, count: data.count)
        return sslTransfer(ssl: ssl, buffer: ubptr, timeout: timeout, callback: callback, progress: progress)
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
        return .error(message: "SecureSockets.Transmit.sslTransfer: Cannot convert string to UTF8")
    }
}
