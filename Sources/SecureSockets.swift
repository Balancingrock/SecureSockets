// =====================================================================================================================
//
//  File:       SecureSockets.swift
//  Project:    SecureSockets
//
//  Version:    0.3.1
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
//  I strongly believe that the Non Agression Principle is the way for societies to function optimally. I thus reject
//  the implicit use of force to extract payment. Since I cannot negotiate with you about the price of this code, I
//  have choosen to leave it up to you to determine its price. You pay me whatever you think this code is worth to you.
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
// v0.3.3  - Added logId to the SslInterface
// v0.3.1  - Updated documentation for use with jazzy.
// v0.1.0  - Initial release
// =====================================================================================================================
//
// When encountering error messages of the following kind
//
// 4308471808:error:14094410:
// SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:ssl/record/rec_layer_s3.c:1362:SSL alert number 40
//
// the following may be of help.
//
// Document: https://tools.ietf.org/html/draft-ietf-tls-tls13-18
//
// This document is the current spec for TLS1.3 and expires April 29, 2017.
//
// From the above document, annex A.2 Alert messages:
//
// When an error message is generated, the last part will often contain a number, eg: "SSL alert number 40"
// This number can be mapped to one of the textual representations below.
// The way I use these is to open the document referenced by the link above in a browser, and then search for the
// textual description in the document. eg: search for "handshake_failure" for the example.
//
// close_notify(0),
// end_of_early_data(1),
// unexpected_message(10),
// bad_record_mac(20),
// decryption_failed_RESERVED(21),
// record_overflow(22),
// decompression_failure_RESERVED(30),
// handshake_failure(40),
// no_certificate_RESERVED(41),
// bad_certificate(42),
// unsupported_certificate(43),
// certificate_revoked(44),
// certificate_expired(45),
// certificate_unknown(46),
// illegal_parameter(47),
// unknown_ca(48),
// access_denied(49),
// decode_error(50),
// decrypt_error(51),
// export_restriction_RESERVED(60),
// protocol_version(70),
// insufficient_security(71),
// internal_error(80),
// inappropriate_fallback(86),
// user_canceled(90),
// no_renegotiation_RESERVED(100),
// missing_extension(109),
// unsupported_extension(110),
// certificate_unobtainable(111),
// unrecognized_name(112),
// bad_certificate_status_response(113),
// bad_certificate_hash_value(114),
// unknown_psk_identity(115),
// certificate_required(116),
// (255)
//
// =====================================================================================================================

import Foundation
import SwifterSockets
import COpenSsl


// Temporary variable used to concatenate error messages

fileprivate var sslErrorMessages: Array<String> = []


// This operation is not threadsafe. It is intended for use during debugging. Occasional use in production seems acceptable.

fileprivate func sslErrorMessageReader(message: UnsafePointer<Int8>?, _ : Int, _ : UnsafeMutableRawPointer?) -> Int32 {
    if let message = message {
        let str = String.init(cString: message)
        sslErrorMessages.append(str)
    }
    return 1
}


/// Clears the openSSL error stack.

public func errClearError() {
    ERR_clear_error()
}


/// Collects the openSSL errors in this thread since the previous call or a preceding 'errClearError'.
///
/// - Returns: The openSSL error message(s) that have occured in the current thread.

public func errPrintErrors() -> String {
    
    
    // Empty the error message container
    
    sslErrorMessages.removeAll()
    
    
    // Dump all error messages from the thread's error stack in the error message container
    
    ERR_print_errors_cb(sslErrorMessageReader, nil)
    
    
    // Concatenate all error messages
    
    let str = sslErrorMessages.reduce("") { $0 + "\n" + $1  }
    
    
    // Clear the thread's error stack
    
    ERR_clear_error()
    
    
    // Return the result
    
    return str
}


/// The supported filetypes for keys and certificates.

public enum FileEncoding {
    
    
    // ANS1 contains 1 key or certificate per file.
    
    case ans1
    
    
    // PEM formats can contain multiple certificates and/or keys per file. Often only the first one is used.
    
    case pem
    
    
    // The SSL file encoding constant for this item.
    
    var asInt32: Int32 {
        switch self {
        case .ans1: return SSL_FILETYPE_ASN1
        case .pem:  return SSL_FILETYPE_PEM
        }
    }
}


/// The specification of a file containing a key or certificate.

public struct EncodedFile {
    
    
    /// The path of the file.
    
    let path: String
    
    
    /// The type of file.
    
    let encoding: Int32
    
    
    /// Creates a new EncodedFile.
    ///
    /// - Parameter
    ///   - path: The path of the file.
    ///   - encoding: The type of the file.
    
    public init(path: String, encoding: FileEncoding) {
        self.path = path
        self.encoding = encoding.asInt32
    }
}


/// The specification of a certificate file and the corresponding private key file. Will also check if the certificate public key and the private key form a pair.

public struct CertificateAndPrivateKeyFiles {
    
    
    /// The file with the certificate.
    
    let certificate: EncodedFile
    
    
    /// The file with the private key.
    
    let privateKey: EncodedFile
    
    
    /// Creates a new association of certificate and private key. It will be checked if the private key is paired with the public key that is contained in the certificate.
    ///
    /// - Parameter
    ///   - certificateFile: A file containing a certificate.
    ///   - privateKeyFile: A file containing a private key.
    ///   - errorProcessing: A closure that will be executed if an error is detected.
    
    public init?(certificateFile: EncodedFile, privateKeyFile: EncodedFile, errorProcessing: ((String) -> Void)? = nil) {
        
        self.certificate = certificateFile
        self.privateKey = privateKeyFile
        
        
        // Create a temporary CTX
        
        guard let ctx = ServerCtx() else {
            errorProcessing?("Failed to create a ServerCtx, message = '\(errPrintErrors())'")
            return nil
        }
        
        
        // Load the certificate into the CTX
        
        switch ctx.useCertificate(file: certificate) {
        case let .error(message): errorProcessing?(message); return nil
        case .success: break
        }
        
        
        // Load the private key into the CTX
        
        switch ctx.usePrivateKey(file: privateKey) {
        case let .error(message): errorProcessing?(message); return nil
        case .success: break
        }
        
        
        // Test if they belong together
        
        switch ctx.checkPrivateKey() {
        case let .error(message): errorProcessing?(message); return nil
        case .success: break
        }
    }
    
    
    /// Creates a new association of certificate and private key. It will be checked if the private key is paired with the public key that is contained in the certificate.
    ///
    /// - Parameters:
    ///   - certificateFile: Path to a file containing a certificate in the PEM format.
    ///   - privateKeyFile: Path to a file containing a private key in the PEM format.
    ///   - errorProcessing: A closure that will be executed if an error is detected.
    
    public init?(pemCertificateFile: String, pemPrivateKeyFile: String, errorProcessing: ((String) -> Void)? = nil) {
        
        
        // Wrap the certificate and private key in an EncodedFile
        
        let certificateFile = EncodedFile(path: pemCertificateFile, encoding: .pem)
        let privateKeyFile = EncodedFile(path: pemPrivateKeyFile, encoding: .pem)
        
        
        // Create the object
        
        self.init(certificateFile: certificateFile, privateKeyFile: privateKeyFile, errorProcessing: errorProcessing)
    }
}


/// The structure that glues a Connection to an SSL interface.

public struct SslInterface: InterfaceAccess {
    
    private(set) var ssl: Ssl?
    private(set) var socket: Int32?

    
    /// An id that can be used for logging purposes and will differentiate between interfaces on a temporary basis.
    ///
    /// It should be guaranteed that no two interfaces with the same logId are active at the same time.
    
    public var logId: Int32 { return socket ?? -1 }

    
    // True when the connection is preent.
    
    var isValid: Bool {
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
    ///   - progress: The closure to invoke for progress updates.
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
