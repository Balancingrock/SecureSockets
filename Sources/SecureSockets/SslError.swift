// =====================================================================================================================
//
//  File:       SslError.swift
//  Project:    SecureSockets
//
//  Version:    1.0.1
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
// 1.0.1 - Documentation update
// 1.0.0 - Removed older history
// =====================================================================================================================

import Foundation

import COpenSsl


/// When encountering error messages of the following kind
///
/// __4308471808:error:14094410: SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:ssl/record/rec_layer_s3.c:1362:SSL alert number 40__
///
/// The following may be of help.
///
/// Document: https://tools.ietf.org/html/rfc8446
///
/// This document is the current spec for TLS1.3 and expires April 29, 2017.
///
/// From the above document, annex A.2 Alert messages:
///
/// When an error message is generated, the last part will often contain a number, eg: "SSL alert number 40"
/// This number can be mapped to one of the textual representations below.
/// The way I use these is to open the document referenced by the link above in a browser, and then search for the
/// textual description in the document. eg: search for "handshake_failure" for the example.
///
/// close_notify(0),
/// end_of_early_data(1),
/// unexpected_message(10),
/// bad_record_mac(20),
/// decryption_failed_RESERVED(21),
/// record_overflow(22),
/// decompression_failure_RESERVED(30),
/// handshake_failure(40),
/// no_certificate_RESERVED(41),
/// bad_certificate(42),
/// unsupported_certificate(43),
/// certificate_revoked(44),
/// certificate_expired(45),
/// certificate_unknown(46),
/// illegal_parameter(47),
/// unknown_ca(48),
/// access_denied(49),
/// decode_error(50),
/// decrypt_error(51),
/// export_restriction_RESERVED(60),
/// protocol_version(70),
/// insufficient_security(71),
/// internal_error(80),
/// inappropriate_fallback(86),
/// user_canceled(90),
/// no_renegotiation_RESERVED(100),
/// missing_extension(109),
/// unsupported_extension(110),
/// certificate_unobtainable(111),
/// unrecognized_name(112),
/// bad_certificate_status_response(113),
/// bad_certificate_hash_value(114),
/// unknown_psk_identity(115),
/// certificate_required(116),
/// (255)


/// Temporary variable used to concatenate error messages

fileprivate var sslErrorMessages: Array<String> = []


/// This operation is not threadsafe. It is intended for use during debugging. Occasional use in production seems acceptable.

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
