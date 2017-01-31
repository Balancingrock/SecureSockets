// =====================================================================================================================
//
//  File:       SecureSockets.Server.swift
//  Project:    SecureSockets
//
//  Version:    0.3.0
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
// v0.3.0  - Fixed error message text (removed reference to SwifterSockets.Secure)
// v0.1.0  - Initial release
// =====================================================================================================================

import Foundation
import SwifterSockets
import COpenSsl


/// Starts listening on the given port.
///
/// When no trusted client certificates are present, the server will accept uncertified clients. If client certificates are specified, then only clients with those certificates are accepted.
///
/// To listen for incoming requests, at least one SSL-Context (CTX) is needed. This is called the server CTX. A default server CTX will be provided if the serverCtx parameter is absent or nil. The default configuration is: use TLS server method, no SSLv2, no SSLv3, enable all openSSL bugfixes, and if a trustedClientCertificate is present the SSL_VERIFY_PEER and SSL_VERIFY_FAIL_IF_NO_PEER_CERT are also set (i.e. client certificates are enforced if present).
///
/// - Note: Calling this operation with all parameters set to default values is invalid. At a minimum specify either _serverCtx_ __or__ _certificateAndPrivateKeyFiles_.
///
/// - Parameter onPort: A string identifying the number of the port to listen on.
/// - Parameter maxPendingConnectionRequest: The number of connections that can be kept pending before they are accepted. A connection request can be put into a queue before it is accepted or rejected. This argument specifies the size of the queue. If the queue is full further connection requests will be rejected.
/// - Parameter certificateAndPrivateKeyFiles: The certificate and private key for the server to use. If a serverCtx is provided with the certificate and private key already set, then leave this parameter nil.
/// - Parameter trustedClientCertificates: An optional list of paths to certificates (either files or folders) of trusted clients.
/// - Parameter serverCtx: An optional CTX that will be used for the server CTX. If it is 'nil' then a default ServerCtx will be created.
/// - Parameter domainCtxs: An optional list of domain CTXs to be used for SNI. Each domain with a certificate should provide a CTX with the certificate and private key for that domain.
///
/// - Returns: The SSL session on which is beiing listened or a string with the error description.

public func setupSslServer(
    onPort port: String,
    maxPendingConnectionRequest: Int32,
    certificateAndPrivateKeyFiles: CertificateAndPrivateKeyFiles? = nil,
    trustedClientCertificates: [String]? = nil,
    serverCtx: Ctx? = nil,
    domainCtxs: [Ctx]? = nil) -> Result<(socket: Int32, ctx: Ctx)> {
    
    
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
    case let .success(desc): return .success(socket: desc, ctx: ctx)
    }
}



/// A secure server.

public class SslServer: ServerProtocol {
    
    
    /// Options with which the secure server can be initialized.
    
    public enum Option {
        
        
        /// The port on which the server will be listening.
        /// - Note: Default = "443"
        
        case port(String)
        
        
        /// The maximum number of connection requests that will be queued.
        /// - Note: Default = 20
        
        case maxPendingConnectionRequests(Int)
        
        
        /// This specifies the duration of the accept loop when no connection requests arrive.
        /// - Note: By implication this also specifies the minimum time between two 'pulsHandler' invocations.
        /// - Note: Default = 5 seconds
        
        case acceptLoopDuration(TimeInterval)
        
        
        /// The server socket operations (Accept loop and "errorProcessor") run synchronously on this queue.
        /// - Note: Default = serial with default qos.
        
        case acceptQueue(DispatchQueue)
        
        
        /// This closure will be invoked after a connection is accepted. It will run on the acceptQueue and block further accepts until it finishes.
        /// - Note: Default = nil
        
        case connectionObjectFactory(ConnectionObjectFactory?)
        
        
        /// This specifies the quality of service for the transmission dispatch queue. Each client wil create its own transfer queue (serial thread) when data must be transmitted to the client. This parameter specifies the QoS of that dispatch queue.
        /// - Note: Default = .default
        
        case transmitQueueQoS(DispatchQoS)
        
        
        /// This specifies the timout given to the transmit operation (once a connection has been established)
        /// - Note: Default = 1 seconds
        
        case transmitTimeout(TimeInterval)
        
        
        /// This closure will be called when the accept loop wraps around without any activity.
        /// - Note: Default = nil
        
        case aliveHandler(TipServer.AliveHandler?)
        
        
        /// This closure will be called to inform the callee of possible error's during the accept loop. The accept loop will try to continue after reporting an error.
        /// - Note: Default = nil
        
        case errorHandler(ErrorHandler?)
        
        
        /// This closure is started right after a connection has been accepted, before the SSL handshake occurs. If it returns 'true' processing resumes as normal and SSL handshake is initiated. If it returns false, the connection will be terminated.
        
        case addressHandler(AddressHandler?)
        
        
        /// This closure is started right after the SSL handshake was completed, before the connection object factory is called. If it returns 'true' processing resumes as normal and the connection object factor is called. If it returns false, the connection will be terminated.
        
        case sslSessionHandler(SslSessionHandler?)
        
        
        /// The certificate and private key for the server to use. Is ignored if a ctxSetup closure is present.
        
        case certificateAndPrivateKeyFiles(CertificateAndPrivateKeyFiles?)
        
        
        /// An optional list of paths to certificates (either files or folders). Is ignored if a ctxSetup closure is present.
        
        case trustedClientCertificates([String]?)
        
        
        /// An optional closure to create the server-wide CTX. Use this if the default setup is insufficient. See 'setupServer' for a description of the default setup.
        /// - Note: If present, it will only be invoked for the server CTX.
        
        case serverCtx(Ctx?)
        
        
        /// A list of server CTXs that can be used for the SNI protocol extension. There should be one context for each domain that has a certificate associated with it.
        
        case domainCtxs([Ctx]?)
    }
    
    
    // Optioned properties
    
    private(set) var port: String = "443"
    private(set) var maxPendingConnectionRequests: Int = 20
    private(set) var acceptLoopDuration: TimeInterval = 5
    private(set) var acceptQueue: DispatchQueue!
    private(set) var connectionObjectFactory: ConnectionObjectFactory?
    private(set) var transmitQueueQoS: DispatchQoS = .default
    private(set) var transmitTimeout: TimeInterval = 1
    private(set) var aliveHandler: TipServer.AliveHandler?
    private(set) var errorHandler: ErrorHandler?
    private(set) var addressHandler: AddressHandler?
    private(set) var sslSessionHandler: SslSessionHandler?
    private(set) var certificateAndPrivateKeyFiles: CertificateAndPrivateKeyFiles?
    private(set) var trustedClientCertificates: [String]?
    private(set) var serverCtx: Ctx?
    private(set) var domainCtxs: [Ctx]?
    
    
    // Interface properties
    
    private(set) var socket: Int32?
    public var isRunning: Bool { return socket != nil }
    
    
    // Internal properties
    
    private var _stop = false
    private var ctx: Ctx?
    
    
    /// Allow the creation of placeholder objects.
    
    public init() {}
    
    
    /// Create a new server socket with the given options. Only initializes internal data. Does not allocate system resources.
    
    public init?(_ options: Option ...) {
        switch setOptions(options) {
        case .error: return nil
        case .success: break
        }
    }
    
    
    /// Set one or more options. Note that once "start" has been called, it is no longer possible to set options without first calling "stop".
    
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
    
    
    /// Set one or more options. Note that once "startAccept" has been called, it is no longer possible to set options without first calling "stopAccepting".
    
    public func setOptions(_ options: Option ...) -> Result<Bool> {
        return setOptions(options)
    }
    
    
    /// Starts the server.
    ///
    /// If no accept queue is set, a serial queue will be created with DispatchQos.default as the priority.
    /// If no receiver queue is set, a concurrent queue will be created with DispatchQos.default as the priority.
    /// If the server is running, this operation will have no effect.
    ///
    /// - Returns: Either .success(true) or .error(message: String).
    
    public func start() -> Result<Bool> {
        
        if certificateAndPrivateKeyFiles == nil { return .error(message: "SecureSockets.Server.Server.start: Missing server certificate & private key files") }
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
            certificateAndPrivateKeyFiles: certificateAndPrivateKeyFiles!,
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
    
    
    /// Instructs the server socket to stop accepting new connection requests. Notice that it might take some time for all activity to cease due to the accept loop duration, receiver timeout and consumer processing time.
    
    public func stop() {
        _stop = true
    }
    
    
    /// Add to the trusted client certificate(s).
    ///
    /// - Parameter at: The path to a file with the certificate(s) or a directory with certificate(s).
    /// - Returns: Either .success(true) or .error(message: String).
    
    public func addTrustedClientCertificate(at path: String) -> Result<Bool> {
        
        return ctx?.loadVerify(location: path) ?? .error(message: "SecureSockets.Server.Server.addTrustedClientCertificate: No ctx present")
    }
}
