// =====================================================================================================================
//
//  File:       SecureSockets.Server.swift
//  Project:    SecureSockets
//
//  Version:    0.4.12
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
// 0.4.12 - Migration to Swift 4
// 0.4.3  - Result type was moved from SwifterSockets to BRUtils
// 0.4.2  - Bugfix: Start command would not be possible with only serverCtx and contained a erroneous force unwrap
// 0.3.3  - Comment section update
//        - Reassigned access levels
// 0.3.1  - Updated documentation for use with jazzy.
// 0.3.0  - Fixed error message text (removed reference to SwifterSockets.Secure)
// 0.1.0  - Initial release
// =====================================================================================================================

import Foundation
import SwifterSockets
import COpenSsl
import BRUtils


/// Starts listening on the given port for SSL connection requests.
///
/// When no trusted client certificates are present, the server will accept uncertified clients. If client certificates are specified, then only clients with those certificates are accepted.
///
/// To listen for incoming requests, at least one Ctx is needed, the serverCtx. A default serverCtx will be provided if the serverCtx parameter is absent or nil. The default configuration for a generated serverCtx is: use TLS server method, no SSLv2, no SSLv3, enable all openSSL bugfixes, and if a trustedClientCertificate is present the SSL_VERIFY_PEER and SSL_VERIFY_FAIL_IF_NO_PEER_CERT are also set (i.e. client certificates are enforced if present).
///
/// - Note: Calling this operation with all parameters set to default values is invalid. At a minimum specify either _serverCtx_ or _certificateAndPrivateKeyFiles_.

/// - Parameters:
///   - port: The number of the port to listen on.
///   - maxPendingConnectionRequest: The number of connections that can be kept pending before they are accepted. A connection request can be put into a queue before it is accepted or rejected. This argument specifies the size of the queue. If the queue is full further connection requests will be rejected.
///   - certificateAndPrivateKeyFiles: The certificate and private key for the server to use. If a serverCtx is provided with the certificate and private key already set, then leave this parameter nil.
///   - trustedClientCertificates: An optional list of paths to certificates (either files or folders) of trusted clients.
///   - serverCtx: An optional Ctx that will be used for the server. A default ServerCtx will be created if this parameter is nil.
///   - domainCtxs: An optional list of domain Ctx's to be used for SNI. Each domain with a certificate should provide a Ctx with the certificate and private key for that domain.

/// - Returns: Either .success(socket: Int32, ctx: Ctx) or .error(message: String)

public func setupSslServer(onPort port: String, maxPendingConnectionRequest: Int32, certificateAndPrivateKeyFiles: CertificateAndPrivateKeyFiles? = nil, trustedClientCertificates: [String]? = nil, serverCtx: Ctx? = nil, domainCtxs: [Ctx]? = nil) -> Result<(socket: Int32, ctx: Ctx)> {
    
    
    // Prevent errors
    
    if (serverCtx == nil) && (certificateAndPrivateKeyFiles == nil) {
        assert(false, "SecureSockets.Server.setupSslServer: createServerWideCtx and certificateAndPrivateKeyFiles cannot both be nil") // debug only
        return .error(message: "SecureSockets.Server.setupSslServer: createServerWideCtx and certificateAndPrivateKeyFiles cannot both be nil")
    }
    
    
    // Create or let a CTX be created
    
    guard let ctx = serverCtx ?? ServerCtx() else {
        return .error(message: "SecureSockets.Server.setupSslServer: Failed to create a CTX")
    }
    
    
    // Add the certificate and private key - if present
    
    if let ck = certificateAndPrivateKeyFiles {
        
        // Set the certificate
        
        switch ctx.useCertificate(file: ck.certificate) {
        case let .error(message): return .error(message: "SecureSockets.Server.setupSslServer: Failed to use certificate at path: \(ck.certificate.path),\n\n\(message)")
        case .success: break
        }
        
        
        // Set the private key
        
        switch ctx.usePrivateKey(file: ck.privateKey) {
        case let .error(message): return .error(message: "SecureSockets.Server.setupSslServer: Failed to use private key at path: \(ck.privateKey.path),\n\n\(message)")
        case .success: break
        }
    }
    
    
    // Optional: Add trusted client certificates
    
    if trustedClientCertificates?.count ?? 0 > 0 {
        
        for certpath in trustedClientCertificates! {
            
            switch ctx.loadVerify(location: certpath) {
            case let .error(message): return .error(message: "SecureSockets.Server.setupSslServer: Failed to set trusted certificate  at path: \(certpath),\n\n\(message)")
            case .success: break
            }
        }
        
        
        // Also instruct the CTX to allow only connections from verfied clients
        
        ctx.setVerifyPeer()
    }
    
    
    // Add the domain CTX's if present
    
    if let domainCtxs = domainCtxs {
        for dctx in domainCtxs { ctx.addDomainCtx(dctx) }
    }
    
    
    // Start listening.
    
    switch setupTipServer(onPort: port, maxPendingConnectionRequest: maxPendingConnectionRequest) {
    case let .error(msg): return .error(message: "SecureSockets.Server.setupSslServer: Failed to start listening on port: \(port),\n\n\(msg)")
    case let .success(desc): return .success((socket: desc, ctx: ctx))
    }
}



/// A secure socket layer server.

public class SslServer: ServerProtocol {
    
    
    /// Options with which the secure server can be initialized.
    
    public enum Option {
        
        
        /// The port on which the server will be listening.
        ///
        /// Default = "443"
        
        case port(String)
        
        
        /// The maximum number of connection requests that will be queued.
        ///
        /// Default = 20
        
        case maxPendingConnectionRequests(Int)
        
        
        /// This specifies the duration of the accept loop when no connection requests arrive.
        ///
        /// Default = 5 seconds
        
        case acceptLoopDuration(TimeInterval)
        
        
        /// The server socket operations (Accept loop and "errorProcessor") will run synchronously on this queue.
        ///
        /// Default = serial with default qos.
        
        case acceptQueue(DispatchQueue)
        
        
        /// This closure will be invoked after a connection is accepted. It will run on the acceptQueue and block further accepts until it finishes.
        ///
        /// Default = nil
        
        case connectionObjectFactory(ConnectionObjectFactory?)
        
        
        /// This specifies the quality of service for the transmission dispatch queue. Each client wil create its own serial transfer queue when data must be transmitted to the client. This parameter specifies the QoS of that dispatch queue.
        ///
        /// Default = .default
        
        case transmitQueueQoS(DispatchQoS)
        
        
        /// This specifies the timout given to the transmit operation (once a connection has been established)
        ///
        /// Default = 1 seconds
        
        case transmitTimeout(TimeInterval)
        
        
        /// This closure will be called when the accept loop wraps around without any activity.
        ///
        /// Default = nil
        
        case aliveHandler(TipServer.AliveHandler?)
        
        
        /// This closure will be called to inform the callee of possible error's during the accept loop. The accept loop will try to continue after reporting an error.
        ///
        /// Default = nil
        
        case errorHandler(ErrorHandler?)
        
        
        /// This closure is started right after a connection has been accepted, but before the SSL handshake occurs. If it returns 'true' processing resumes as normal and SSL handshake is initiated. If it returns false, the connection will be terminated.
        ///
        /// Default = nil
        
        case addressHandler(AddressHandler?)
        
        
        /// This closure is started right after the SSL handshake was completed, before the connection object factory is called. If it returns 'true' processing resumes as normal and the connection object factor is called. If it returns false, the connection will be terminated.
        ///
        /// Default = nil
        
        case sslSessionHandler(SslSessionHandler?)
        
        
        /// The certificate and private key for the server to use.
        ///
        /// Default = nil

        case certificateAndPrivateKeyFiles(CertificateAndPrivateKeyFiles?)
        
        
        /// An optional list of paths to certificates (either files or folders).
        ///
        /// Default = nil
        
        case trustedClientCertificates([String]?)
        
        
        /// An optional serverCtx. Use this if the default setup is insufficient.
        ///
        /// Default = nil
        
        case serverCtx(Ctx?)
        
        
        /// A list of server Ctx's that can be used for the SNI protocol extension. There should be one Ctx for each domain that has a certificate associated with it.
        
        case domainCtxs([Ctx]?)
    }
    
    
    // Optioned properties
    
    public private(set) var port: String = "443"
    public private(set) var maxPendingConnectionRequests: Int = 20
    public private(set) var acceptLoopDuration: TimeInterval = 5
    public private(set) var acceptQueue: DispatchQueue!
    public private(set) var connectionObjectFactory: ConnectionObjectFactory?
    public private(set) var transmitQueueQoS: DispatchQoS = .default
    public private(set) var transmitTimeout: TimeInterval = 1
    public private(set) var aliveHandler: TipServer.AliveHandler?
    public private(set) var errorHandler: ErrorHandler?
    public private(set) var addressHandler: AddressHandler?
    public private(set) var sslSessionHandler: SslSessionHandler?
    public private(set) var certificateAndPrivateKeyFiles: CertificateAndPrivateKeyFiles?
    public private(set) var trustedClientCertificates: [String]?
    public private(set) var serverCtx: Ctx?
    public private(set) var domainCtxs: [Ctx]?
    
    
    // Interface properties
    
    public private(set) var socket: Int32?
    
    
    /// - Returns true when the server is running
    
    public var isRunning: Bool { return socket != nil }
    
    
    // Internal properties
    
    private var _stop = false
    private var ctx: Ctx?
    
    
    /// Creates a new SslServer but does not set any options. The default SslServer is not capable of running. Use 'setOption' to provided the minimum configuration.
    ///
    /// As a minimum set either the serverCtx or the certificateAndPrivateKeyFiles.
    
    public init() {}
    
    
    /// Create a new server socket with the given options.
    ///
    /// - Parameter options: A set of configuration options.
    
    public init?(_ options: Option ...) {
        switch setOptions(options) {
        case .error: return nil
        case .success: break
        }
    }
    
    
    /// Set one or more SslServer options. Can only be used while the server is not running.
    ///
    /// - Parameter options: An array with SslServer options.
    ///
    /// - Returns: Either .success(true) or .error(message: String).
    
    public func setOptions(_ options: [Option]) -> Result<Bool> {
        
        guard ctx == nil else { return .error(message: "SecureSockets.Server.Server.setOptions: Socket is already active, no changes made") }
        
        for option in options {
        
            switch option {
            case let .port(str): port = str
            case let .maxPendingConnectionRequests(num): maxPendingConnectionRequests = num
            case let .acceptLoopDuration(dur): acceptLoopDuration = dur
            case let .acceptQueue(queue): acceptQueue = queue
            case let .connectionObjectFactory(acch): connectionObjectFactory = acch
            case let .transmitQueueQoS(q): transmitQueueQoS = q
            case let .transmitTimeout(dur): transmitTimeout = dur
            case let .aliveHandler(cl): aliveHandler = cl
            case let .errorHandler(cl): errorHandler = cl
            case let .addressHandler(cl): addressHandler = cl
            case let .sslSessionHandler(cl): sslSessionHandler = cl
            case let .certificateAndPrivateKeyFiles(kc): certificateAndPrivateKeyFiles = kc
            case let .trustedClientCertificates(strs): trustedClientCertificates = strs
            case let .serverCtx(cl): serverCtx = cl
            case let .domainCtxs(cb): domainCtxs = cb
            }
        }
        return .success(true)
    }
    
    
    /// Set one or more SslServer options. Can only be used while the server is not running.
    ///
    /// - Parameter options: A set of SslServer options.
    ///
    /// - Returns: Either .success(true) or .error(message: String).
    
    public func setOptions(_ options: Option ...) -> Result<Bool> {
        return setOptions(options)
    }
    
    
    /// Add to the trusted client certificate(s).
    ///
    /// - Parameter at: The path to a file with the certificate(s) or a directory with certificate(s).
    ///
    /// - Returns: Either .success(true) or .error(message: String).
    
    public func addTrustedClientCertificate(at path: String) -> Result<Bool> {
        
        return ctx?.loadVerify(location: path) ?? .error(message: "SecureSockets.Server.Server.addTrustedClientCertificate: No ctx present")
    }

    
    // MARK: - ServerProtocol
    
    
    /// Starts the server.
    ///
    /// If no accept queue is set, a serial queue will be created with DispatchQos.default as the priority.
    /// If no receiver queue is set, a concurrent queue will be created with DispatchQos.default as the priority.
    /// If the server is running, this operation will have no effect.
    ///
    /// - Returns: Either .success(true) or .error(message: String).
    
    public func start() -> Result<Bool> {
        
        if certificateAndPrivateKeyFiles == nil && serverCtx == nil { return .error(message: "SecureSockets.Server.Server.start: Missing server certificate & private key files") }
        if connectionObjectFactory == nil { return .error(message: "SecureSockets.Server.Server.start: Missing ConnectionObjectFactory closure") }
        
        
        // Exit if already running
        
        if ctx != nil { return .success(true) }
        
        
        // Create accept queue if necessary
        
        if acceptQueue == nil {
            acceptQueue = DispatchQueue(label: "Accept queue for port \(port)", qos: .default, attributes: DispatchQueue.Attributes(), autoreleaseFrequency: DispatchQueue.AutoreleaseFrequency.inherit, target: nil)
        }
        
        
        // Setup Server
        
        let result = setupSslServer(
            onPort: port,
            maxPendingConnectionRequest: Int32(maxPendingConnectionRequests),
            certificateAndPrivateKeyFiles: certificateAndPrivateKeyFiles,
            trustedClientCertificates: trustedClientCertificates,
            serverCtx: serverCtx,
            domainCtxs: domainCtxs)
        
        switch result {
            
        case let .error(message):
            
            return .error(message: message)
            
            
        case let .success(socket_in, ctx_in):
            
            socket = socket_in
            ctx = ctx_in
            
            
            // Start accepting
            
            _stop = false
            acceptQueue!.async() {
                
                [unowned self] in
                
                ACCEPT_LOOP: while !self._stop {
                    
                    switch sslAccept(onSocket: self.socket!, useCtx: self.ctx!, timeout: self.acceptLoopDuration, addressHandler: self.addressHandler, sslSessionHandler: self.sslSessionHandler) {
                        
                    // Normal
                    case let .accepted(ssl, socket, clientAddress):
                        let intf = SslInterface(ssl, socket)
                        if let connectedClient = self.connectionObjectFactory!(intf, clientAddress) {
                            connectedClient.startReceiverLoop()
                        }
                        
                    // Failed to establish a connection, try again.
                    case .closed: self.errorHandler?("Client unexpectedly closed during accept")
                        
                    // If the user provided an error processor, use that
                    case let .error(message): self.errorHandler?(message)
                        
                    // Normal, try again
                    case .timeout: self.aliveHandler?()
                    }
                }
                
                // Free ssl and system resources
                
                closeSocket(self.socket)
                self.socket = nil
            }
            
            return .success(true)
        }
    }
    
    
    /// Instructs the server to stop accepting new requests. Notice that it might take some time for all activity to cease due to the accept loop duration, receiver timeout and reply processing time.
    
    public func stop() {
        _stop = true
    }
}
