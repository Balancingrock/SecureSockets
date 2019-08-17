// =====================================================================================================================
//
//  File:       SslInterface.swift
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

import SwifterSockets
import COpenSsl


/// The structure that glues a Connection to an SSL interface.

public struct SslInterface: InterfaceAccess {
    
    public private(set) var ssl: Ssl?
    public private(set) var socket: Int32?
    
    
    /// An id that can be used for logging purposes and will differentiate between interfaces on a temporary basis.
    ///
    /// It should be guaranteed that no two interfaces with the same logId are active at the same time.
    
    public var logId: Int32 { return socket ?? -1 }
    
    
    // True when the connection is preent.
    
    public var isValid: Bool {
        get {
            if ssl == nil { return false }
            if socket == nil { return false }
            if socket! < 0 { return false }
            return true
        }
    }
    
    
    /// Creates a new SslInterface for a Connection object.
    ///
    /// - Parameters:
    ///   - ssl: The Ssl session.
    ///   - socket: The socket.
    
    public init(_ ssl: Ssl, _ socket: Int32) {
        self.ssl = ssl
        self.socket = socket
    }
    
    
    /// Closes and invalidates the interface.
    
    public mutating func close() {
        
        if isValid {
            ssl!.shutdown()
            closeSocket(socket)
            ssl = nil
            socket = nil
        }
    }
    
    
    /// Transfers the data in the buffer to the peer.
    ///
    /// - Parameters:
    ///   - buffer: The buffer with data to be transferred.
    ///   - timeout: The maximum duration of the transfer.
    ///   - callback: The destination for the TransmitterProtocol methods calls.
    ///   - progress: The closure to invoke for progress monitoring. Note that progress monitoring for ssl connections is near impossible. While the progress closure can be invoked several times during a transfer it is not possible to indicate how many bytes have been transferred. For that reason on all calls, the bytesTransferred will be zero.
    ///
    /// - Returns: See the definition of TransferResult.
    
    public func transfer(buffer: UnsafeBufferPointer<UInt8>, timeout: TimeInterval?, callback: TransmitterProtocol? = nil, progress: TransmitterProgressMonitor? = nil) -> TransferResult? {
        
        if isValid {
            
            return sslTransfer(
                ssl: ssl!,
                buffer: buffer,
                timeout: timeout ?? 10,
                callback: callback,
                progress: progress)
        }
        
        return nil
    }
    
    
    /// Starts a rceiver loop.
    ///
    /// - Parameters:
    ///   - bufferSize: The size of the buffer to allocate.
    ///   - duration: The loop duration.
    ///   - receiver: The destination for the ReceiverProtocol method calls.
    
    public func receiverLoop(bufferSize: Int, duration: TimeInterval, receiver: ReceiverProtocol) {
        
        if isValid {
            
            sslReceiverLoop(
                ssl: ssl!,
                bufferSize: bufferSize,
                duration: duration,
                receiver: receiver)
        }
    }
}
