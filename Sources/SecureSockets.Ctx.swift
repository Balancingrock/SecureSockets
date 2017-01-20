// =====================================================================================================================
//
//  File:       SecureSockets.Ctx.swift
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


/// A wrapper class for the openSSL context. This wrapper avoids having to handle the openssl free/up_ref.

public class Ctx {
    
    
    /// The pointer to the openSSL context structure
    
    private(set) var optr: OpaquePointer
    
    
    // Free's the openSSl structure
    
    deinit { SSL_CTX_free(optr) }
    
    
    /// Initialises a new object from the given opaquepointer that was generated or retrieved using an openSSL call. The ref count of the  structure pointed will be decremented (and thus possibly deallocated) when the Ctx object is freed. It should not be nil, nor should the ref count be 0.
    
    public init(ctx: OpaquePointer) { self.optr = ctx }
    
    
    /// The certificate for this context (if any).
    
    public var x509: X509? { return X509(ctx: self) }
    
    
    // The list with CTX's for the domains. This list is used for the SNI protocol extension. Each CTX must have a certificate and private key (belonging to the certificate) set.
    
    private var domainCtxs = [Ctx]()
    
    
    /// Assigns the certificate in the given file.
    /// - Parameter file: An encoded file in PEM or ASN1 format with the certificate.
    /// - Returns: .success(true) or an .error(message: String).
    
    public func useCertificate(file encodedFile: EncodedFile) -> Result<Bool> {
        
        ERR_clear_error()
        
        if SSL_CTX_use_certificate_file(optr, encodedFile.path, encodedFile.encoding) != 1 {
            
            return .error(message: "SwifterSockets.Secure.Ctx.useCertificate: Could not add certificate to CTX,\n\n\(errPrintErrors())")
            
        } else {
            
            return .success(true)
        }
    }
    
    
    /// Assigns the private key in the given file.
    /// - Parameter file: An encoded file in PEM or ASN1 format with the private key.
    /// - Returns: .success(true) or an .error(message: String).
    
    public func usePrivateKey(file encodedFile: EncodedFile) -> Result<Bool> {
        
        ERR_clear_error()
        
        if SSL_CTX_use_PrivateKey_file(optr, encodedFile.path, encodedFile.encoding) != 1 {
            
            return .error(message: "SwifterSockets.Secure.Ctx.usePrivateKey: Could not add private key to CTX,\n\n\(errPrintErrors())")
            
        } else {
            
            return .success(true)
        }
    }
    
    
    /// Verifies if the private key and the certificate that were last set belong together. The certificate contains a public key. The private key most recently set will be tested for compatibilty with the public key in the certificate that was most recently set.
    /// - Returns: .success(true) or an .error(message: String).
    
    public func checkPrivateKey() -> Result<Bool> {
        
        ERR_clear_error()
        
        if SSL_CTX_check_private_key(optr) != 1 {
            
            return .error(message: "SwifterSockets.Secure.Ctx.checkPrivateKey: Private Key check failed,\n\n\(errPrintErrors)")
            
        } else {
            
            return .success(true)
        }
    }
    
    
    /// Adds the file or folder at the given path to the list of trusted certificates.
    /// - Note: There is no test performed on the trusted certificated, the paths are accepted as is.
    /// - Parameter location: The path of the file or folder containing the trusted certificates.
    /// - Returns: .success(true) or an .error(message: String)
    
    public func loadVerify(location path: String) -> Result<Bool> {
        
        var isDirectory: ObjCBool = false
        
        if FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory) {
            
            ERR_clear_error()
            
            if isDirectory.boolValue {
                
                if SSL_CTX_load_verify_locations(optr, nil, path) != 1 {
                    
                    return .error(message: "SwifterSockets.Secure.Ctx.loadVerifyLocation: Could not set verify location for folder \(path),\n\n'\(errPrintErrors())")
                }
                
            } else {
                
                if SSL_CTX_load_verify_locations(optr, path, nil) != 1 {
                    
                    return .error(message: "SwifterSockets.Secure.Ctx.loadVerifyLocation: Could not set verify location for file \(path),\n\n'\(errPrintErrors())")
                }
            }
            
        } else {
            
            return .error(message: "SwifterSockets.Secure.Ctx.loadVerifyLocation: File or folder no longer exists at \(path)")
        }
        
        return .success(true)
    }
    
    
    /// Sets the 'SSL_VERIFY_PEER' and 'SSL_VERIFY_FAIL_IF_NO_PEER_CERT' options to true. This enforces a verification of the certificate from the peer. The peer can be either a server or client.
    
    public func setVerifyPeer() {
        
        SSL_CTX_set_verify(optr, SSL_VERIFY_PEER + SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nil)
    }
    
    
    /// This adds a domain context. The added context should have a certificate and private key. Note that no checks are made if the certificate is already in use by another domainCtx.
    ///
    /// - Parameter ctx: The ctx to be added.
    
    public func addDomainCtx(_ ctx: Ctx) {
        
        
        // If this is the first domain added, then install the SNI callback.
        
        if domainCtxs.count == 0 {
            sslCtxSetTlsExtServernameCallback(optr, sni_callback, UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque()))
        }
        
        
        // Add the ctx
        
        domainCtxs.append(ctx)
    }
    
    
    // The callback from openSSL. This callback must be installed before the server is started.
    
    private let sni_callback: @convention(c) (_ ssl: OpaquePointer?, _ num: UnsafeMutablePointer<Int32>?, _ arg: UnsafeMutableRawPointer?) -> Int32 = {
        
        (ssl_ptr, _, arg) -> Int32 in
        
        
        // Get the reference to 'self'
        
        let ourself = Unmanaged<Ctx>.fromOpaque(arg!).takeUnretainedValue()
        
        
        // Get the String with the host name from the SSL session
        
        guard let hostname = SSL_get_servername(ssl_ptr, TLSEXT_NAMETYPE_host_name) else { return SSL_TLSEXT_ERR_NOACK }
        
        
        // Check if the current certificate contains the hostname
        
        if let ctx_ptr = SSL_get_SSL_CTX(ssl_ptr) {
            
            if let x509_ptr = SSL_CTX_get0_certificate(ctx_ptr) {
                
                if X509_check_host(x509_ptr, hostname, 0, 0, nil) == 1 {
                    
                    return SSL_TLSEXT_ERR_OK
                }
            }
        }
        
        
        // Check if there is another CXT with a certificate containing the hostname
        
        var foundCtx: Ctx?
        for testCtx in ourself.domainCtxs {
            if testCtx.x509?.checkHost(hostname) ?? false {
                foundCtx = testCtx
                break
            }
        }
        guard let newCtx = foundCtx else  { return SSL_TLSEXT_ERR_NOACK }
        
        
        // Set the new CTX to the current SSL session
        
        if SSL_set_SSL_CTX(ssl_ptr, newCtx.optr) == nil {
            // The new ctx did not have a certificate (found by source code inspection of ssl_lib.c)
            // This should be impossible since that would have caused this CTX to be rejected
            return SSL_TLSEXT_ERR_NOACK
        }
        
        
        return SSL_TLSEXT_ERR_OK
    }
}


/// A context for a server setup with the default options.
/// - Note: If the creations fails, the SwifterSockets.Secure.errPrintErrors may have more information on the cause.

public final class ServerCtx: Ctx {
    
    /// If the creations fails, the SwifterSockets.Secure.errPrintErrors may have more information on the cause.
    
    public init?() {
        
        ERR_clear_error()
        
        
        // Create server context
        
        guard let context = SSL_CTX_new(TLS_server_method()) else { return nil }
        
        super.init(ctx: context)
        
        
        // Set default options
        
        SSL_CTX_set_options(optr, (UInt(SSL_OP_NO_SSLv2) + UInt(SSL_OP_NO_SSLv3) + UInt(SSL_OP_ALL)))
    }
}


/// A context for a client setup with the default options.
/// - Note: If the creations fails, the SwifterSockets.Secure.errPrintErrors may have more information on the cause.

public final class ClientCtx: Ctx {
    
    /// If the creations fails, the SwifterSockets.Secure.errPrintErrors may have more information on the cause.
    
    public init?() {
        
        ERR_clear_error()
        
        
        // Create client context
        
        guard let context = SSL_CTX_new(TLS_client_method()) else { return nil }
        
        super.init(ctx: context)
        
        
        // Set default options
        
        SSL_CTX_set_options(optr, (UInt(SSL_OP_NO_SSLv2) + UInt(SSL_OP_NO_SSLv3) + UInt(SSL_OP_ALL)))
    }
}
