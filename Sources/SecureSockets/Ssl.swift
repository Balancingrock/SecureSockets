// =====================================================================================================================
//
//  File:       Ssl.swift
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
// 1.1.0 - Switched to Swift.Result instead of BRUtils.Result
//       - Renamed Result to SslResult to avoid conflicts with Swift.Result
// 1.0.1 - Doumentation update
// 1.0.0 - Removed older history
//
// =====================================================================================================================

import Foundation
import SwifterSockets
import Copenssl


/// A wrapper class for an openSSL session (SSL).

public class Ssl {
    
    
    /// The return condition from several methods
    
    public enum SslResult: CustomStringConvertible, Equatable {
        
        
        /// openssl.org: The TLS/SSL I/O operation completed. This result code is returned if and only if ret > 0.
        
        case completed(Int32)
        
        
        /// openssl.org: The TLS/SSL connection has been closed. If the protocol version is SSL 3.0 or TLS 1.0, this result code is returned only if a closure alert has occurred in the protocol, i.e. if the connection has been closed cleanly. Note that in this case SSL_ERROR_ZERO_RETURN does not necessarily indicate that the underlying transport has been closed.
        
        case zeroReturn
        
        
        /// openssl.org: The operation did not complete; the same TLS/SSL I/O function should be called again later. If, by then, the underlying BIO has data available for reading (if the result code is SSL_ERROR_WANT_READ) or allows writing data (SSL_ERROR_WANT_WRITE), then some TLS/SSL protocol progress will take place, i.e. at least part of an TLS/SSL record will be read or written. Note that the retry may again lead to a SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition. There is no fixed upper limit for the number of iterations that may be necessary until progress becomes visible at application protocol level.
        ///
        /// For socket BIOs (e.g. when SSL_set_fd() was used), select() or poll() on the underlying socket can be used to find out when the TLS/SSL I/O function should be retried.
        ///
        /// Caveat: Any TLS/SSL I/O function can lead to either of SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE. In particular, SSL_read() or SSL_peek() may want to write data and SSL_write() may want to read data. This is mainly because TLS/SSL handshakes may occur at any time during the protocol (initiated by either the client or the server); SSL_read(), SSL_peek(), and SSL_write() will handle any pending handshakes.
        
        case wantRead, wantWrite
        
        
        /// openssl.org: The operation did not complete; the same TLS/SSL I/O function should be called again later. The underlying BIO was not connected yet to the peer and the call would block in connect()/accept(). The SSL function should be called again when the connection is established. These messages can only appear with a BIO_s_connect() or BIO_s_accept() BIO, respectively. In order to find out, when the connection has been successfully established, on many platforms select() or poll() for writing on the socket file descriptor can be used.
        
        case wantConnect, wantAccept
        
        
        /// openssl.org: The operation did not complete because an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again. The TLS/SSL I/O function should be called again later. Details depend on the application.
        
        case wantX509Lookup
        
        
        /// openssl.org: The operation did not complete because an asynchronous engine is still processing data. This will only occur if the mode has been set to SSL_MODE_ASYNC using SSL_CTX_set_mode or SSL_set_mode and an asynchronous capable engine is being used. An application can determine whether the engine has completed its processing using select() or poll() on the asynchronous wait file descriptor. This file descriptor is available by calling SSL_get_all_async_fds or SSL_get_changed_async_fds. The TLS/SSL I/O function should be called again later. The function must be called from the same thread that the original call was made from.
        
        case wantAsync
        
        
        /// openssl.org: The asynchronous job could not be started because there were no async jobs available in the pool (see ASYNC_init_thread(3)). This will only occur if the mode has been set to SSL_MODE_ASYNC using SSL_CTX_set_mode or SSL_set_mode and a maximum limit has been set on the async job pool through a call to ASYNC_init_thread. The application should retry the operation after a currently executing asynchronous operation for the current thread has completed.
        
        case wantAsyncJob
        
        
        /// openssl.org: Some I/O error occurred. The OpenSSL error queue may contain more information on the error. If the error queue is empty (i.e. ERR_get_error() returns 0), ret can be used to find out more about the error: If ret == 0, an EOF was observed that violates the protocol. If ret == -1, the underlying BIO reported an I/O error (for socket I/O on Unix systems, consult errno for details).
        
        case syscall
        
        
        /// openssl.org: A failure in the SSL library occurred, usually a protocol error. The OpenSSL error queue contains more information on the error.
        
        case ssl
        
        
        /// A bios error occured, the errno has details
        
        case bios_errno(Int32)
        
        
        /// An error happened that can only be expressed by text
        
        case errorMessage(String)
        
        
        /// An undocumented error was returned by SSL
        
        case undocumentedSslError(Int32)
        
        
        /// An illegal value was returned by an ssl function
        
        case undocumentedSslFunctionResult(Int32)
        
        
        /// Creates a Ssl.Result from a SSL_get_error result.
        ///
        /// - Parameter for: The result from a SSL_get_error call.
        
        public init(for value: Int32) {
            switch value {
            case SSL_ERROR_NONE: self = .completed(0)
            case SSL_ERROR_ZERO_RETURN: self = .zeroReturn
            case SSL_ERROR_WANT_READ: self = .wantRead
            case SSL_ERROR_WANT_WRITE: self = .wantWrite
            case SSL_ERROR_WANT_CONNECT: self = .wantConnect
            case SSL_ERROR_WANT_ACCEPT: self = .wantAccept
            case SSL_ERROR_WANT_X509_LOOKUP: self = .wantX509Lookup
            case SSL_ERROR_WANT_ASYNC: self = .wantAsync
            case SSL_ERROR_WANT_ASYNC_JOB: self = .wantAsyncJob
            case SSL_ERROR_SYSCALL: self = .syscall
            case SSL_ERROR_SSL: self = .ssl
            default: self = .undocumentedSslError(value)
            }
        }
        
        
        /// The textual description of the value
        
        public var description: String {
            switch self {
            case let .completed(num): return "SSL_ERROR_NONE: The TLS/SSL I/O operation completed with count \(num)."
            case .zeroReturn: return "SSL_ERROR_ZERO_RETURN: The TLS/SSL connection has been closed."
            case .wantRead: return "SSL_ERROR_WANT_READ: The operation did not complete."
            case .wantWrite: return "SSL_ERROR_WANT_WRITE: The operation did not complete."
            case .wantConnect: return "SSL_ERROR_WANT_CONNECT: The operation did not complete."
            case .wantAccept: return "SSL_ERROR_WANT_ACCEPT: The operation did not complete."
            case .wantX509Lookup: return "SSL_ERROR_WANT_X509_LOOKUP: The operation did not complete because an asynchronous engine is still processing data."
            case .wantAsync: return "SSL_ERROR_WANT_ASYNC: The operation did not complete because an asynchronous engine is still processing data."
            case .wantAsyncJob: return "SSL_ERROR_WANT_ASYNC_JOB: The asynchronous job could not be started because there were no async jobs available in the pool."
            case .syscall: return "SSL_ERROR_SYSCALL: Some I/O error occurred."
            case .ssl: return "SSL_ERROR_SSL: A failure in the SSL library occurred, usually a protocol error."
            //case .bios_eof: return "An EOF was received without a proper shutdown of the SSL connection."
            case let .bios_errno(num): return "A BIOS error occured '\(num)' = \(String(validatingUTF8: strerror(errno)) ?? "Unknown error code")"
            case let .undocumentedSslError(val): return "SSL returned an undocumented code '\(val)'"
            case let .undocumentedSslFunctionResult(val): return "The SSL function returned an undocumented code '\(val)'"
            case let .errorMessage(msg): return "Error message = '\(msg)'"
            }
        }
        
        
        /// The textual description of the value
        
        public var debugDescription: String { return description }
        
        /// Compares two ssl results, returns true when they are equal.
        
        public static func == (lhs: SslResult, rhs: SslResult) -> Bool {
            switch lhs {
            case let .completed(lnum): if case let .completed(rnum) = rhs { return lnum == rnum } else { return false }
            case .zeroReturn: if case .zeroReturn = rhs { return true } else { return false }
            case .wantRead: if case .wantRead = rhs { return true } else { return false }
            case .wantWrite: if case .wantWrite = rhs { return true } else { return false }
            case .wantConnect: if case .wantConnect = rhs { return true } else { return false }
            case .wantAccept: if case .wantAccept = rhs { return true } else { return false }
            case .wantX509Lookup: if case .wantX509Lookup = rhs { return true } else { return false }
            case .wantAsync: if case .wantAsync = rhs { return true } else { return false }
            case .wantAsyncJob: if case .wantAsyncJob = rhs { return true } else { return false }
            case .syscall: if case .syscall = rhs { return true } else { return false }
            case .ssl: if case .ssl = rhs { return true } else { return false }
            case let .errorMessage(lmsg): if case let .errorMessage(rmsg) = rhs { return lmsg == rmsg } else { return false }
            case let .bios_errno(lval): if case let .bios_errno(rval) = rhs { return lval == rval } else { return false }
            case let .undocumentedSslError(lval): if case let .undocumentedSslError(rval) = rhs { return lval == rval } else { return false }
            case let .undocumentedSslFunctionResult(lval): if case let .undocumentedSslFunctionResult(rval) = rhs { return lval == rval } else { return false }
            }
        }
        
        
        /// Compares two ssl results, returns true when they are not equal.
        
        public static func != (lhs: SslResult, rhs: SslResult) -> Bool {
            return !(lhs == rhs)
        }
    }
    
    
    /// The pointer to the OpenSSL session structure.
    
    public private(set) var optr: OpaquePointer!
    
    
    /// The Ctx used by this session.
    
    public var ctx: Ctx? {
        
        if let ctx_ptr = SSL_get_SSL_CTX(optr) {
            
            // Increment the reference counter because Ctx will decrement it when the Ctx is freed.
            
            SSL_CTX_up_ref(ctx_ptr)
            
            return Ctx(ctx: ctx_ptr)
            
        } else {
            
            return nil
        }
    }
    
    
    // Free the session structure
    
    deinit { SSL_free(optr) }
    
    
    /// Creates a new session.
    ///
    /// If nil, use errPrintErrors() to find out why.
    ///
    /// - Parameter context: The Ctx to be used when creating a new Ssl.
    
    public init?(context: Ctx) {
        
        if let ssl = SSL_new(context.optr) {
            optr = ssl
        } else {
            return nil
        }
    }
    
    
    /// Assign the given name to the session. For a client session this will be the name used to request a domain certificate.
    ///
    /// - Parameter name: The name of the requested domain.
    
    public func setTlsextHostname(_ name: UnsafePointer<Int8>) {
        SSL_ctrl(optr, SSL_CTRL_SET_TLSEXT_HOSTNAME, Int(TLSEXT_NAMETYPE_host_name), UnsafeMutableRawPointer(mutating: name))
    }
    
    
    /// Assign a socket (file descriptor) to this session
    ///
    /// - Parameter sock: The file descriptor (socket) to be used.
    ///
    /// - Returns: Either .success(true) or .error(message: String)
    
    public func setFd(_ sock: Int32) -> SecureSocketsResult<Bool> {
        ERR_clear_error()
        if SSL_set_fd(optr, sock) != 1 {
            return .failure(SecureSocketsError("Failed to set socket\n\(errPrintErrors())"))
        }
        return .success(true)
    }
    
    
    /// Return the socket used in this session.
    ///
    /// - Returns: The file descriptor of this session.
    
    public func getFd() -> Int32 {
        return SSL_get_fd(optr)
    }
    
    
    /// Returns a SslResult for the parameter returned by SSL_connect(), SSL_accept(), SSL_doHandshake(), SSL_read(), SSL_peek() or SSL_write().
    ///
    /// openSSL: In addition to ssl and ret, SSL_get_error() inspects the current thread's OpenSSL error queue. Thus, SSL_get_error() must be used in the same thread that performed the TLS/SSL I/O operation, and no other OpenSSL function calls should appear in between. The current thread's error queue must be empty before the TLS/SSL I/O operation is attempted, or SSL_get_error() will not work reliably.
    ///
    /// - Parameter ret: The return value from one of the SSL_.... routines.
    ///
    /// - Returns: The corresponding SslResult.
    
    public func getError(_ ret: Int32) -> SslResult {
        return SslResult(for: SSL_get_error(optr, ret))
    }
    
    
    /// Establish a secure connection on the given socket. The socket must already be connected to the server at the TCP/IP level.
    ///
    /// - Parameters
    ///   - socket: The socket on which to make the connect attempt.
    ///   - timeout: The maximum duration of the attempt.
    ///
    /// - Returns: See the definition of SelectResult.
    
    public func connect(socket: Int32, timeout: Date) -> SelectResult {
        
        ERR_clear_error()
        
        SSL_CONNECT: while true {
            
            let res = SSL_connect(optr)
            
            if res == 1 { return .ready }
            
            let result = getError(res)
            
            switch result {
                
            case .completed: break SSL_CONNECT
                
            case .wantRead, .wantWrite:
                
                // Loop, but use select for timeout purposes
                
                let selres = waitForSelect(socket: socket, timeout: timeout, forRead: true, forWrite: true)
                
                switch selres {
                case .timeout: return .timeout
                case .closed: return .error(message: "\(#file).\(#function).\(#line): Connection was unexpectedly closed,\n\n\(errPrintErrors())")
                case .ready: break // Continues the SSL_CONNECT loop
                case let .error(message): return .error(message: "\(#file).\(#function).\(#line): Socket error,\n\n \(message)")
                }
                
            default:
                return .error(message: "\(#file).\(#function).\(#line): Error,\n\n\(errPrintErrors())")
            }
        }
        
        return .ready
    }
    
    
    /// Accepts an SSL_connect() from a client. It waits for a TLS/SSL client to initiate the TLS/SSL handshake. The communication channel must already have been set and assigned to the ssl.
    ///
    /// - Returns: The SslResult for the operation.
    
    public func accept() -> SslResult {
        
        ERR_clear_error()
        
        let res = SSL_accept(optr)
        
        switch res {
            
        case 0:
            
            // openssl.org: The TLS/SSL handshake was not successful but was shut down controlled and by the specifications of the TLS/SSL protocol. Call SSL_get_error() with the return value ret to find out the reason.
            
            return getError(res)
            
            
        case 1:
            
            // openssl.org: The TLS/SSL handshake was successfully completed, a TLS/SSL connection has been established.
            
            return SslResult.completed(0)
            
            
        case let (x) where x < 0:
            
            // openssl.org: The TLS/SSL handshake was not successful because a fatal error occurred either at the protocol level or a connection failure occurred. The shutdown was not clean. It can also occur of action is need to continue the operation for non-blocking BIOs. Call SSL_get_error() with the return value ret to find out the reason.
            
            return getError(res)
            
            
        case let (x) where x > 1:
            
            return SslResult.undocumentedSslFunctionResult(res)
            
            
        default: fatalError("All cases are covered, this should be impossible")
        }
    }
    
    
    /// Will wait for a SSL/TLS handshake to take place. If the connection is in client mode, the handshake will be started.
    ///
    /// - Returns: The SslResult for the operation.
    
    public func doHandshake() -> SslResult {
        
        ERR_clear_error()
        
        let res = SSL_do_handshake(optr)
        
        if res == 1 { return .completed(0) }
        
        return getError(res)
    }
    
    
    /// Controlled shutdown of the session
    
    public func shutdown() {
        SSL_shutdown(optr)
    }
    
    
    /// The name of the server
    ///
    /// - Returns: The name of the server or nil if not available.
    
    public func getServerName() -> UnsafePointer<Int8>? {
        return SSL_get_servername(optr, TLSEXT_NAMETYPE_host_name)
    }
    
    
    /// Return the certificate of the peer, if one was received
    ///
    /// - Returns: An X509 formatted certificate or nil.
    
    public func getPeerCertificate() -> X509? {
        return X509(ssl: self)
    }
    
    
    /// The result of the certificate verification (if there was a certificate)
    ///
    /// - Returns: Either .success(true) or .error(message: String)
    
    public func getVerifyResult() -> SecureSocketsResult<Bool> {
        
        let verifyResult = X509.VerificationResult(for: Int32(SSL_get_verify_result(optr)))
        
        if verifyResult != .x509_v_ok {
            return .failure(SecureSocketsError("Verification failed\n\(verifyResult.description)"))
        } else {
            return .success(true)
        }
    }
    
    
    /// Tries to read num bytes from the peer.
    ///
    /// - Parameters:
    ///   - buf: A pointer to a memory area containing at least 'num' bytes.
    ///   - num: The maximum number of bytes to read.
    ///
    /// - Returns: The SslResult code from the operation.
    
    public func read(buf: UnsafeMutableRawPointer, num: Int32) -> SslResult {
        
        
        // Clear the openSSL error stack
        
        ERR_clear_error()
        
        
        // Clear possible POSIX errors
        
        errno = 0
        
        
        // Read using the ssl session
        
        let res = SSL_read(optr, buf, num)
        
        switch res {
            
        case let (x) where x > 0:
            
            // openssl.org: The read operation was successful; the return value is the number of bytes actually read from the TLS/SSL connection.
            
            return SslResult.completed(res)
            
            
        case 0:
            
            // openssl.org: The read operation was not successful. The reason may either be a clean shutdown due to a "close notify" alert sent by the peer (in which case the SSL_RECEIVED_SHUTDOWN flag in the ssl shutdown state is set (see SSL_shutdown, SSL_set_shutdown). It is also possible, that the peer simply shut down the underlying transport and the shutdown is incomplete. Call SSL_get_error() with the return value ret to find out, whether an error occurred or the connection was shut down cleanly (SSL_ERROR_ZERO_RETURN).
            
            let result = getError(res)
            
            if result == SslResult.syscall {
                
                // openssl.org: Some non-recoverable I/O error occurred. The OpenSSL error queue may contain more information on the error. For socket I/O on Unix systems, consult errno for details.
                
                // Collect all possible error information
                
                var message = errPrintErrors()
                
                if errno != 0 { message += "\nIO error (errno) = " + (String(validatingUTF8: strerror(errno)) ?? "Unknown error code '\(errno)'") }
                
                return SslResult.errorMessage(message)
            }
            
            return result
            
            
        case let (x) where x < 0:
            
            // openssl.org: The read operation was not successful, because either an error occurred or action must be taken by the calling process. Call SSL_get_error() with the return value ret to find out the reason.
            
            return getError(res)
            
            
        default: fatalError("All cases are covered, this should be impossible")
        }
    }
    
    
    /// Writes num bytes from the buffer to the ssl session for transfer to the peer.
    ///
    /// - Parameters:
    ///   - buf: A pointer to a memory area containing at least 'num' bytes.
    ///   - num: The maximum number of bytes to read.
    ///
    /// - Returns: The result code from the operation.
    
    public func write(buf: UnsafeRawPointer, num: Int32) -> SslResult {
        
        
        // Clear the openSSL error stack
        
        ERR_clear_error()
        
        
        // Perform the write
        
        let res = SSL_write(optr, buf, num)
        
        
        // Check if all data was written
        
        if res > 0 { return .completed(res) }
        
        
        // If an error occured, get the error result.
        
        return getError(res)
    }
}

