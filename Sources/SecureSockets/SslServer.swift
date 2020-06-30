// =====================================================================================================================
//
//  File:       SslServer.swift
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
// 1.1.0 - Switched to Swift.Result instead of BRUtils.Result
// 1.0.1 - Document updates
// 1.0.0 - Removed older history
//
// =====================================================================================================================

import Foundation
import SwifterSockets
import Copenssl


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

public func setupSslServer(onPort port: String, maxPendingConnectionRequest: Int32, certificateAndPrivateKeyFiles: CertificateAndPrivateKeyFiles? = nil, trustedClientCertificates: [String]? = nil, serverCtx: Ctx? = nil, domainCtxs: [Ctx]? = nil) -> SecureSocketsResult<(socket: Int32, ctx: Ctx)> {
    
    
    // Prevent errors
    
    if (serverCtx == nil) && (certificateAndPrivateKeyFiles == nil) {
        assert(false, "SecureSockets.SslServer.setupSslServer: createServerWideCtx and certificateAndPrivateKeyFiles cannot both be nil") // debug only
        return .failure(SecureSocketsError("createServerWideCtx and certificateAndPrivateKeyFiles cannot both be nil"))
    }
    
    
    // Create or let a CTX be created
    
    guard let ctx = serverCtx ?? ServerCtx() else {
        return .failure(SecureSocketsError("Failed to create a CTX"))
    }
    
    
    // Add the certificate and private key - if present
    
    if let ck = certificateAndPrivateKeyFiles {
        
        // Set the certificate
        
        switch ctx.useCertificate(file: ck.certificate) {
        case let .failure(message): return .failure(SecureSocketsError("Failed to use certificate at path: \(ck.certificate.path)\n\(message.localizedDescription)"))
        case .success: break
        }
        
        
        // Set the private key
        
        switch ctx.usePrivateKey(file: ck.privateKey) {
        case let .failure(message): return .failure(SecureSocketsError("Failed to use private key at path: \(ck.privateKey.path),\n\(message.localizedDescription)"))
        case .success: break
        }
    }
    
    
    // Optional: Add trusted client certificates
    
    if trustedClientCertificates?.count ?? 0 > 0 {
        
        for certpath in trustedClientCertificates! {
            
            switch ctx.loadVerify(location: certpath) {
            case let .failure(message): return .failure(SecureSocketsError("Failed to set trusted certificate at path: \(certpath)\n\(message.localizedDescription)"))
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
    case let .failure(msg): return .failure(SecureSocketsError("Failed to start listening on port: \(port)\n\(msg.localizedDescription)"))
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
        
        
        /// This closure is started right after the SSL handshake was completed, before the connection object factory is called. If it returns 'true' processing resumes as normal and the connection object factory is called. If it returns false, the connection will be terminated.
        ///
        /// Default = nil
        
        case sslSessionHandler(SslSessionHandler?)
        
        
        /// The certificate and private key for the server to use.
        ///
        /// Default = nil

        case certificateAndPrivateKeyFiles(CertificateAndPrivateKeyFiles?)
        
        
        /// An optional list of paths to certificates for trusted clients (either files or folders).
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
    // ===================
    
    
    /// See `SslServer.Option.port`

    public private(set) var port: String = "443"
    
    
    /// See `SslServer.Option.maxPendingConnectionRequests`
    
    public private(set) var maxPendingConnectionRequests: Int = 20
    
    
    /// See `SslServer.Option.acceptLoopDuration`

    public private(set) var acceptLoopDuration: TimeInterval = 5

    
    /// See `SslServer.Option.acceptQueue`

    public private(set) var acceptQueue: DispatchQueue!
    
    
    /// See `SslServer.Option.connectionObjectFactory`

    public private(set) var connectionObjectFactory: ConnectionObjectFactory?
    
    
    /// See `SslServer.Option.transmitQueueQoS`

    public private(set) var transmitQueueQoS: DispatchQoS = .default
    
    
    /// See `SslServer.Option.transmitTimeout`

    public private(set) var transmitTimeout: TimeInterval = 1
    
    
    /// See `SslServer.Option.aliveHandler`

    public private(set) var aliveHandler: TipServer.AliveHandler?
    
    
    /// See `SslServer.Option.errorHandler`

    public private(set) var errorHandler: ErrorHandler?
    
    
    /// See `SslServer.Option.addressHandler`

    public private(set) var addressHandler: AddressHandler?
    
    
    /// See `SslServer.Option.sslSessionHandler`

    public private(set) var sslSessionHandler: SslSessionHandler?
    
    
    /// See `SslServer.Option.certificateAndPrivateKeyFiles`

    public private(set) var certificateAndPrivateKeyFiles: CertificateAndPrivateKeyFiles?
    
    
    /// See `SslServer.Option.trustedClientCertificates`

    public private(set) var trustedClientCertificates: [String]?
    
    
    /// See `SslServer.Option.serverCtx`

    public private(set) var serverCtx: Ctx?
    
    
    /// See `SslServer.Option.domainCtxs`

    public private(set) var domainCtxs: [Ctx]?
    
    
    /// The socket on which the SSL server is running. Nil if the server is not running.
    
    public private(set) var socket: Int32?
    
    
    /// True when the server is running, false if not.
    
    public var isRunning: Bool { return socket != nil }
    
    
    // Internal properties
    
    private var _stop = false
    private var ctx: Ctx?
    
    
    /// Creates a new SslServer but does not set any options. The default SslServer is not capable of running. Use 'setOptions' to provided the minimum configuration.
    ///
    /// As a minimum set either the serverCtx or the certificateAndPrivateKeyFiles.
    
    public init() {}
    
    
    /// Create a new server socket with the given options.
    ///
    /// - Parameter options: A set of configuration options.
    
    public init?(_ options: Option ...) {
        switch setOptions(options) {
        case .failure: return nil
        case .success: break
        }
    }
    
    
    /// Set one or more SslServer options. Can only be used while the server is not running.
    ///
    /// - Parameter options: An array with SslServer options.
    ///
    /// - Returns: Either .success(true) or .error(message: String).
    
    public func setOptions(_ options: [Option]) -> SecureSocketsResult<Bool> {
        
        guard ctx == nil else { return .failure(SecureSocketsError("Socket is already active, no changes made")) }
        
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
    
    public func setOptions(_ options: Option ...) -> SecureSocketsResult<Bool> {
        return setOptions(options)
    }
    
    
    /// Add to the trusted client certificate(s).
    ///
    /// - Parameter at: The path to a file with the certificate(s) or a directory with certificate(s).
    ///
    /// - Returns: Either .success(true) or .error(message: String).
    
    public func addTrustedClientCertificate(at path: String) -> SecureSocketsResult<Bool> {
        
        return ctx?.loadVerify(location: path) ?? .failure(SecureSocketsError("No ctx present"))
    }

    
    // MARK: - ServerProtocol
    
    
    /// Starts the server.
    ///
    /// If no accept queue is set, a serial queue will be created with DispatchQos.default as the priority.
    /// If no receiver queue is set, a concurrent queue will be created with DispatchQos.default as the priority.
    /// If the server is running, this operation will have no effect.
    ///
    /// - Returns: Either .success(true) or .error(message: String).
    
    public func start() -> SwifterSocketsResult<Bool> {
        
        if certificateAndPrivateKeyFiles == nil && serverCtx == nil {
            return .failure(SwifterSocketsError("Missing server certificate & private key files"))
        }
        if connectionObjectFactory == nil {
            return .failure(SwifterSocketsError("Missing ConnectionObjectFactory closure"))
        }
        
        
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
            
        case let .failure(message):
            
            return .failure(SwifterSocketsError(message.localizedDescription))
            
            
        case let .success((socket_in, ctx_in)):
            
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
