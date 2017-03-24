// =====================================================================================================================
//
//  File:       SecureSockets.X509.swift
//  Project:    SecureSockets
//
//  Version:    0.4.2
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
// 0.4.2  - Added checkValidityDate
//        - Added loadCertificates
//        - Added init(file:)
// 0.4.0  - Added and improved functions
//        - Fixed bug where the issuer data was written to the subject.
// 0.3.3  - Comment section update
//        - Added logId to the SslInterface
// 0.3.1  - Updated documentation for use with jazzy.
// 0.3.0  - Fixed error message text
// 0.1.0  - Initial release
// =====================================================================================================================

import Foundation
import SwifterSockets
import COpenSsl


/// The string for the NID element in the given X509_NAME structure.
///
/// - Parameters:
//    - x509Name: A pointer to the X509_NAME
///   - with: An integer indicating the NID element (see openssl/objects.h)
///
/// - Returns: nil if the value is not present. The String value if it was read correctly.

public func valueFrom(x509Name: OpaquePointer!, with nid: Int32) -> String? {
    
    
    // Get the position of the common name in the subject
    
    let position = X509_NAME_get_index_by_NID(x509Name, nid, -1)
    if position == -1 { return nil }
    
    
    // Get the entry for the common name
    
    let entry = X509_NAME_get_entry(x509Name, position)
    
    
    // Get the ANS1 data for the common name
    
    let ans1String = X509_NAME_ENTRY_get_data(entry)
    
    
    // Convert the ANS1 string to a [UInt8]
    
    var ptr: UnsafeMutablePointer<UInt8>?
    let len = ASN1_STRING_to_UTF8(&ptr, ans1String)
    if (len < 0) || (ptr == nil) { return nil }
    
    
    // View [UInt8] as a buffer pointer
    
    let buf = UnsafeMutableBufferPointer(start: ptr!, count: Int(len))
    
    
    // Create native string
    
    let str = String.init(bytes: buf, encoding: String.Encoding.utf8)
    
    
    // Free the original data
    
    CRYPTO_free(UnsafeMutableRawPointer(ptr), "", 0)
    
    
    // And create a string from the c-string
    
    return str
}


/// The Subject Alt Names stored in the extension.
///
/// - Parameter from: An OpaquePointer to an x509 structure that was created by -or retrieved from- OpenSSL.
///
/// - Returns: nil if no subject alt names could be read, an array with Strings if subject alt names were read.

public func getX509SubjectAltNames(from x509: OpaquePointer!) -> [String]? {
    
    
    // Get the alternative names from the cert (there may be none!)
    
    guard let names = OpaquePointer(X509_get_ext_d2i(x509, NID_subject_alt_name, nil, nil)) else { return nil }
    
    
    // Storage for the names that are found
    
    var altNames = [String]()
    
    
    // Loop over all names (keep in mind that 'names' is an OpaquePointer)
    
    let count = sk_GENERAL_NAMES_num(names)
    for i in 0 ..< count {
        
        
        // Get name at index i
        
        let aName = sk_GENERAL_NAME_value(names, i)
        
        
        // If it is a domain name, add it to the results
        
        if aName!.pointee.type == GEN_DNS {
            
            
            // Convert it to a native String
            
            guard let cstr = ASN1_STRING_get0_data(aName!.pointee.d.dNSName) else { return nil }
            
            
            // Check for nul characters in the string (= malformed certificate)
            
            let str = String(cString: cstr)
            guard Int32(str.utf8.count) == ASN1_STRING_length(aName!.pointee.d.dNSName) else { return nil }
            
            
            // Append the name
            
            altNames.append(str)
        }
        
        
        // Free the GENERAL NAMES structure
        
        //skGeneralNamePopFree(names)
    }
    
    return altNames
}


/// A wrapper class for a x509 structure.

open class X509 {
    
    
    /// The result of a certificate verification
    
    enum VerificationResult: Int {
        
        /// The operation was successful.
        case x509_v_ok = 0
        
        /// Unspecified error; should not happen.
        case x509_v_err_unspecified
        
        /// The issuer certificate of a looked up certificate could not be found. This normally means the list of trusted certificates is not complete.
        case x509_v_err_unable_to_get_issuer_cert
        
        /// The CRL of a certificate could not be found.
        case x509_v_err_unable_to_get_crl
        
        /// The certificate signature could not be decrypted. This means that the actual signature value could not be determined rather than it not matching the expected value, this is only meaningful for RSA keys.
        case x509_v_err_unable_to_decrypt_cert_signature
        
        /// The CRL signature could not be decrypted: this means that the actual signature value could not be determined rather than it not matching the expected value. Unused.
        case x509_v_err_unable_to_decrypt_crl_signature
        
        /// The public key in the certificate SubjectPublicKeyInfo could not be read.
        case x509_v_err_unable_to_decode_issuer_public_key
        
        /// The signature of the certificate is invalid.
        case x509_v_err_cert_signature_failure
        
        /// The signature of the certificate is invalid.
        case x509_v_err_crl_signature_failure
        
        /// The certificate is not yet valid: the notBefore date is after the current time.
        case x509_v_err_cert_not_yet_valid
        
        /// The certificate has expired: that is the notAfter date is before the current time.
        case x509_v_err_cert_has_expired
        
        /// The CRL is not yet valid.
        case x509_v_err_crl_not_yet_valid
        
        /// The CRL has expired.
        case x509_v_err_crl_has_expired
        
        /// The certificate notBefore field contains an invalid time.
        case x509_v_err_error_in_cert_not_before_field
        
        /// The certificate notAfter field contains an invalid time.
        case x509_v_err_error_in_cert_not_after_field
        
        /// The CRL lastUpdate field contains an invalid time.
        case x509_v_err_error_in_crl_last_update_field
        
        /// The CRL nextUpdate field contains an invalid time.
        case x509_v_err_error_in_crl_next_update_field
        
        /// An error occurred trying to allocate memory. This should never happen.
        case x509_v_err_out_of_mem
        
        /// The passed certificate is self-signed and the same certificate cannot be found in the list of trusted certificates.
        case x509_v_err_depth_zero_self_signed_cert
        
        /// The certificate chain could be built up using the untrusted certificates but the root could not be found locally.
        case x509_v_err_self_signed_cert_in_chain
        
        /// The issuer certificate could not be found: this occurs if the issuer certificate of an untrusted certificate cannot be found.
        case x509_v_err_unable_to_get_issuer_cert_locally
        
        /// No signatures could be verified because the chain contains only one certificate and it is not self signed.
        case x509_v_err_unable_to_verify_leaf_signature
        
        /// The certificate chain length is greater than the supplied maximum depth. Unused.
        case x509_v_err_cert_chain_too_long
        
        /// The certificate has been revoked.
        case x509_v_err_cert_revoked
        
        /// A CA certificate is invalid. Either it is not a CA or its extensions are not consistent with the supplied purpose.
        case x509_v_err_invalid_ca
        
        /// The basicConstraints pathlength parameter has been exceeded.
        case x509_v_err_path_length_exceeded
        
        /// The supplied certificate cannot be used for the specified purpose.
        case x509_v_err_invalid_purpose
        
        /// the root CA is not marked as trusted for the specified purpose.
        case x509_v_err_cert_untrusted
        
        /// The root CA is marked to reject the specified purpose.
        case x509_v_err_cert_rejected
        
        /// not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option.
        case x509_v_err_subject_issuer_mismatch
        
        /// Not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option.
        case x509_v_err_akid_skid_mismatch
        
        /// Not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option.
        case x509_v_err_akid_issuer_serial_mismatch
        
        /// Not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option.
        case x509_v_err_keyusage_no_certsign
        
        /// Unable to get CRL issuer certificate.
        case x509_v_err_unable_to_get_crl_issuer
        
        /// Unhandled critical extension.
        case x509_v_err_unhandled_critical_extension
        
        /// Key usage does not include CRL signing.
        case x509_v_err_keyusage_no_crl_sign
        
        /// Unhandled critical CRL extension.
        case x509_v_err_unhandled_critical_crl_extension
        
        /// Invalid non-CA certificate has CA markings.
        case x509_v_err_invalid_non_ca
        
        /// Proxy path length constraint exceeded.
        case x509_v_err_proxy_path_length_exceeded
        
        /// Proxy certificate subject is invalid. It MUST be the same as the issuer with a single CN component added.
        case x509_v_err_proxy_subject_name_violation
        
        /// Key usage does not include digital signature.
        case x509_v_err_keyusage_no_digital_signature
        
        /// Proxy certificates not allowed, please use -allow_proxy_certs.
        case x509_v_err_proxy_certificates_not_allowed
        
        /// Invalid or inconsistent certificate extension.
        case x509_v_err_invalid_extension
        
        /// Invalid or inconsistent certificate policy extension.
        case x509_v_err_invalid_policy_extension
        
        /// No explicit policy.
        case x509_v_err_no_explicit_policy
        
        /// Different CRL scope.
        case x509_v_err_different_crl_scope
        
        /// Unsupported extension feature.
        case x509_v_err_unsupported_extension_feature
        
        /// RFC 3779 resource not subset of parent's resources.
        case x509_v_err_unnested_resource
        
        /// Permitted subtree violation.
        case x509_v_err_permitted_violation
        
        /// Excluded subtree violation.
        case x509_v_err_excluded_violation
        
        /// Name constraints minimum and maximum not supported.
        case x509_v_err_subtree_minmax
        
        /// Application verification failure. Unused.
        case x509_v_err_application_verification
        
        /// Unsupported name constraint type.
        case x509_v_err_unsupported_constraint_type
        
        /// Unsupported or invalid name constraint syntax.
        case x509_v_err_unsupported_constraint_syntax
        
        /// Unsupported or invalid name syntax.
        case x509_v_err_unsupported_name_syntax
        
        /// CRL path validation error.
        case x509_v_err_crl_path_validation_error
        
        /// Path loop.
        case x509_v_err_path_loop
        
        /// Suite B: certificate version invalid.
        case x509_v_err_suite_b_invalid_version
        
        /// Suite B: invalid public key algorithm.
        case x509_v_err_suite_b_invalid_algorithm
        
        /// Suite B: invalid ECC curve.
        case x509_v_err_suite_b_invalid_curve
        
        /// Suite B: invalid signature algorithm.
        case x509_v_err_suite_b_invalid_signature_algorithm
        
        /// Suite B: curve not allowed for this LOS.
        case x509_v_err_suite_b_los_not_allowed
        
        /// Suite B: cannot sign P-384 with P-256.
        case x509_v_err_suite_b_cannot_sign_p_384_with_p_256
        
        /// Hostname mismatch.
        case x509_v_err_hostname_mismatch
        
        /// Email address mismatch.
        case x509_v_err_email_mismatch
        
        /// IP address mismatch.
        case x509_v_err_ip_address_mismatch
        
        /// DANE TLSA authentication is enabled, but no TLSA records matched the certificate chain. This error is only possible in s_client.
        case x509_v_err_dane_no_match
        
        /// An unknown (undocumented) error was returned
        case unknown
        
        
        /// A readable description of this result.
        
        public var description: String {
            
            switch self {
            case .x509_v_ok: return "X509_V_OK: The operation was successful."
            case .x509_v_err_unspecified: return "X509_V_ERR_UNSPECIFIED: Unspecified error; should not happen."
            case .x509_v_err_unable_to_get_issuer_cert: return "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: The issuer certificate of a looked up certificate could not be found. This normally means the list of trusted certificates is not complete."
            case .x509_v_err_unable_to_get_crl: return "X509_V_ERR_UNABLE_TO_GET_CRL: The CRL of a certificate could not be found."
            case .x509_v_err_unable_to_decrypt_cert_signature: return "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: The certificate signature could not be decrypted. This means that the actual signature value could not be determined rather than it not matching the expected value, this is only meaningful for RSA keys."
            case .x509_v_err_unable_to_decrypt_crl_signature: return "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: The CRL signature could not be decrypted: this means that the actual signature value could not be determined rather than it not matching the expected value. Unused."
            case .x509_v_err_unable_to_decode_issuer_public_key: return "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: The public key in the certificate SubjectPublicKeyInfo could not be read."
            case .x509_v_err_cert_signature_failure: return "X509_V_ERR_CERT_SIGNATURE_FAILURE: The signature of the certificate is invalid."
            case .x509_v_err_crl_signature_failure: return "X509_V_ERR_CRL_SIGNATURE_FAILURE: The signature of the certificate is invalid."
            case .x509_v_err_cert_not_yet_valid: return "X509_V_ERR_CERT_NOT_YET_VALID: The certificate is not yet valid: the notBefore date is after the current time."
            case .x509_v_err_cert_has_expired: return "X509_V_ERR_CERT_HAS_EXPIRED: The certificate has expired: that is the notAfter date is before the current time."
            case .x509_v_err_crl_not_yet_valid: return "X509_V_ERR_CRL_NOT_YET_VALID: The CRL is not yet valid."
            case .x509_v_err_crl_has_expired: return "X509_V_ERR_CRL_HAS_EXPIRED: The CRL has expired."
            case .x509_v_err_error_in_cert_not_before_field: return "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: The certificate notBefore field contains an invalid time."
            case .x509_v_err_error_in_cert_not_after_field: return "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: The certificate notAfter field contains an invalid time."
            case .x509_v_err_error_in_crl_last_update_field: return "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: The CRL lastUpdate field contains an invalid time."
            case .x509_v_err_error_in_crl_next_update_field: return "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: The CRL nextUpdate field contains an invalid time."
            case .x509_v_err_out_of_mem: return "X509_V_ERR_OUT_OF_MEM: An error occurred trying to allocate memory. This should never happen."
            case .x509_v_err_depth_zero_self_signed_cert: return "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: The passed certificate is self-signed and the same certificate cannot be found in the list of trusted certificates."
            case .x509_v_err_self_signed_cert_in_chain: return "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: The certificate chain could be built up using the untrusted certificates but the root could not be found locally."
            case .x509_v_err_unable_to_get_issuer_cert_locally: return "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: The issuer certificate could not be found: this occurs if the issuer certificate of an untrusted certificate cannot be found."
            case .x509_v_err_unable_to_verify_leaf_signature: return "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: No signatures could be verified because the chain contains only one certificate and it is not self signed."
            case .x509_v_err_cert_chain_too_long: return "X509_V_ERR_CERT_CHAIN_TOO_LONG: The certificate chain length is greater than the supplied maximum depth. Unused."
            case .x509_v_err_cert_revoked: return "X509_V_ERR_CERT_REVOKED:The certificate has been revoked."
            case .x509_v_err_invalid_ca: return "X509_V_ERR_INVALID_CA: A CA certificate is invalid. Either it is not a CA or its extensions are not consistent with the supplied purpose."
            case .x509_v_err_path_length_exceeded: return "X509_V_ERR_PATH_LENGTH_EXCEEDED: The basicConstraints pathlength parameter has been exceeded."
            case .x509_v_err_invalid_purpose: return "X509_V_ERR_INVALID_PURPOSE: The supplied certificate cannot be used for the specified purpose."
            case .x509_v_err_cert_untrusted: return "X509_V_ERR_CERT_UNTRUSTED: the root CA is not marked as trusted for the specified purpose."
            case .x509_v_err_cert_rejected: return "X509_V_ERR_CERT_REJECTED: The root CA is marked to reject the specified purpose."
            case .x509_v_err_subject_issuer_mismatch: return "X509_V_ERR_SUBJECT_ISSUER_MISMATCH: not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option."
            case .x509_v_err_akid_skid_mismatch: return "X509_V_ERR_AKID_SKID_MISMATCH: Not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option."
            case .x509_v_err_akid_issuer_serial_mismatch: return "X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: Not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option."
            case .x509_v_err_keyusage_no_certsign: return "X509_V_ERR_KEYUSAGE_NO_CERTSIGN: Not used as of OpenSSL 1.1.0 as a result of the deprecation of the -issuer_checks option."
            case .x509_v_err_unable_to_get_crl_issuer: return "X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: Unable to get CRL issuer certificate."
            case .x509_v_err_unhandled_critical_extension: return "X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION: Unhandled critical extension."
            case .x509_v_err_keyusage_no_crl_sign: return "X509_V_ERR_KEYUSAGE_NO_CRL_SIGN: Key usage does not include CRL signing."
            case .x509_v_err_unhandled_critical_crl_extension: return "X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION: Unhandled critical CRL extension."
            case .x509_v_err_invalid_non_ca: return "X509_V_ERR_INVALID_NON_CA: Invalid non-CA certificate has CA markings."
            case .x509_v_err_proxy_path_length_exceeded: return "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED: Proxy path length constraint exceeded."
            case .x509_v_err_proxy_subject_name_violation: return "X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION: Proxy certificate subject is invalid. It MUST be the same as the issuer with a single CN component added."
            case .x509_v_err_keyusage_no_digital_signature: return "X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: Key usage does not include digital signature."
            case .x509_v_err_proxy_certificates_not_allowed: return "X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED: Proxy certificates not allowed, please use -allow_proxy_certs."
            case .x509_v_err_invalid_extension: return "X509_V_ERR_INVALID_EXTENSION: Invalid or inconsistent certificate extension."
            case .x509_v_err_invalid_policy_extension: return "X509_V_ERR_INVALID_POLICY_EXTENSION: Invalid or inconsistent certificate policy extension."
            case .x509_v_err_no_explicit_policy: return "X509_V_ERR_NO_EXPLICIT_POLICY: No explicit policy."
            case .x509_v_err_different_crl_scope: return "X509_V_ERR_DIFFERENT_CRL_SCOPE: Different CRL scope."
            case .x509_v_err_unsupported_extension_feature: return "X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE: Unsupported extension feature."
            case .x509_v_err_unnested_resource: return "X509_V_ERR_UNNESTED_RESOURCE: RFC 3779 resource not subset of parent's resources."
            case .x509_v_err_permitted_violation: return "X509_V_ERR_PERMITTED_VIOLATION: Permitted subtree violation."
            case .x509_v_err_excluded_violation: return "X509_V_ERR_EXCLUDED_VIOLATION: Excluded subtree violation."
            case .x509_v_err_subtree_minmax: return "X509_V_ERR_SUBTREE_MINMAX: Name constraints minimum and maximum not supported."
            case .x509_v_err_application_verification: return "X509_V_ERR_APPLICATION_VERIFICATION: Application verification failure. Unused."
            case .x509_v_err_unsupported_constraint_type: return "X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: Unsupported name constraint type."
            case .x509_v_err_unsupported_constraint_syntax: return "X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: Unsupported or invalid name constraint syntax."
            case .x509_v_err_unsupported_name_syntax: return "X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: Unsupported or invalid name syntax."
            case .x509_v_err_crl_path_validation_error: return "X509_V_ERR_CRL_PATH_VALIDATION_ERROR: CRL path validation error."
            case .x509_v_err_path_loop: return "X509_V_ERR_PATH_LOOP: Path loop."
            case .x509_v_err_suite_b_invalid_version: return "X509_V_ERR_SUITE_B_INVALID_VERSION: Suite B: certificate version invalid."
            case .x509_v_err_suite_b_invalid_algorithm: return "X509_V_ERR_SUITE_B_INVALID_ALGORITHM: Suite B: invalid public key algorithm."
            case .x509_v_err_suite_b_invalid_curve: return "X509_V_ERR_SUITE_B_INVALID_CURVE: Suite B: invalid ECC curve."
            case .x509_v_err_suite_b_invalid_signature_algorithm: return "X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM: Suite B: invalid signature algorithm."
            case .x509_v_err_suite_b_los_not_allowed: return "X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED: Suite B: curve not allowed for this LOS."
            case .x509_v_err_suite_b_cannot_sign_p_384_with_p_256: return "X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256: Suite B: cannot sign P-384 with P-256."
            case .x509_v_err_hostname_mismatch: return "X509_V_ERR_HOSTNAME_MISMATCH: Hostname mismatch."
            case .x509_v_err_email_mismatch: return "X509_V_ERR_EMAIL_MISMATCH: Email address mismatch."
            case .x509_v_err_ip_address_mismatch: return "X509_V_ERR_IP_ADDRESS_MISMATCH: IP address mismatch."
            case .x509_v_err_dane_no_match: return "X509_V_ERR_DANE_NO_MATCH: DANE TLSA authentication is enabled, but no TLSA records matched the certificate chain. This error is only possible in s_client."
            case .unknown: return "Unknown error code"
            }
        }
        
        
        /// A new value from an Int32.
        
        public init(for value: Int32) {
            
            switch value {
            case X509_V_OK: self = .x509_v_ok
            case X509_V_ERR_UNSPECIFIED: self = .x509_v_err_unspecified
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: self = .x509_v_err_unable_to_get_issuer_cert
            case X509_V_ERR_UNABLE_TO_GET_CRL: self = .x509_v_err_unable_to_get_crl
            case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE: self = .x509_v_err_unable_to_decrypt_cert_signature
            case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE: self = .x509_v_err_unable_to_decrypt_crl_signature
            case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: self = .x509_v_err_unable_to_decode_issuer_public_key
            case X509_V_ERR_CERT_SIGNATURE_FAILURE: self = .x509_v_err_cert_signature_failure
            case X509_V_ERR_CRL_SIGNATURE_FAILURE: self = .x509_v_err_crl_signature_failure
            case X509_V_ERR_CERT_NOT_YET_VALID: self = .x509_v_err_cert_not_yet_valid
            case X509_V_ERR_CERT_HAS_EXPIRED: self = .x509_v_err_cert_has_expired
            case X509_V_ERR_CRL_NOT_YET_VALID: self = .x509_v_err_crl_not_yet_valid
            case X509_V_ERR_CRL_HAS_EXPIRED: self = .x509_v_err_crl_has_expired
            case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD: self = .x509_v_err_error_in_cert_not_before_field
            case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD: self = .x509_v_err_error_in_cert_not_after_field
            case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD: self = .x509_v_err_error_in_crl_last_update_field
            case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD: self = .x509_v_err_error_in_crl_next_update_field
            case X509_V_ERR_OUT_OF_MEM: self = .x509_v_err_out_of_mem
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: self = .x509_v_err_depth_zero_self_signed_cert
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: self = .x509_v_err_self_signed_cert_in_chain
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: self = .x509_v_err_unable_to_get_issuer_cert_locally
            case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE: self = .x509_v_err_unable_to_verify_leaf_signature
            case X509_V_ERR_CERT_CHAIN_TOO_LONG: self = .x509_v_err_cert_chain_too_long
            case X509_V_ERR_CERT_REVOKED: self = .x509_v_err_cert_revoked
            case X509_V_ERR_INVALID_CA: self = .x509_v_err_invalid_ca
            case X509_V_ERR_PATH_LENGTH_EXCEEDED: self = .x509_v_err_path_length_exceeded
            case X509_V_ERR_INVALID_PURPOSE: self = .x509_v_err_invalid_purpose
            case X509_V_ERR_CERT_UNTRUSTED: self = .x509_v_err_cert_untrusted
            case X509_V_ERR_CERT_REJECTED: self = .x509_v_err_cert_rejected
            case X509_V_ERR_SUBJECT_ISSUER_MISMATCH: self = .x509_v_err_subject_issuer_mismatch
            case X509_V_ERR_AKID_SKID_MISMATCH: self = .x509_v_err_akid_skid_mismatch
            case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH: self = .x509_v_err_akid_issuer_serial_mismatch
            case X509_V_ERR_KEYUSAGE_NO_CERTSIGN: self = .x509_v_err_keyusage_no_certsign
            case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER: self = .x509_v_err_unable_to_get_crl_issuer
            case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION: self = .x509_v_err_unhandled_critical_extension
            case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN: self = .x509_v_err_keyusage_no_crl_sign
            case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION: self = .x509_v_err_unhandled_critical_crl_extension
            case X509_V_ERR_INVALID_NON_CA: self = .x509_v_err_invalid_non_ca
            case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED: self = .x509_v_err_proxy_path_length_exceeded
            case X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION: self = .x509_v_err_proxy_subject_name_violation
            case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE: self = .x509_v_err_keyusage_no_digital_signature
            case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED: self = .x509_v_err_proxy_certificates_not_allowed
            case X509_V_ERR_INVALID_EXTENSION: self = .x509_v_err_invalid_extension
            case X509_V_ERR_INVALID_POLICY_EXTENSION: self = .x509_v_err_invalid_policy_extension
            case X509_V_ERR_NO_EXPLICIT_POLICY: self = .x509_v_err_no_explicit_policy
            case X509_V_ERR_DIFFERENT_CRL_SCOPE: self = .x509_v_err_different_crl_scope
            case X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE: self = .x509_v_err_unsupported_extension_feature
            case X509_V_ERR_UNNESTED_RESOURCE: self = .x509_v_err_unnested_resource
            case X509_V_ERR_PERMITTED_VIOLATION: self = .x509_v_err_permitted_violation
            case X509_V_ERR_EXCLUDED_VIOLATION: self = .x509_v_err_excluded_violation
            case X509_V_ERR_SUBTREE_MINMAX: self = .x509_v_err_subtree_minmax
            case X509_V_ERR_APPLICATION_VERIFICATION: self = .x509_v_err_application_verification
            case X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE: self = .x509_v_err_unsupported_constraint_type
            case X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX: self = .x509_v_err_unsupported_constraint_syntax
            case X509_V_ERR_UNSUPPORTED_NAME_SYNTAX: self = .x509_v_err_unsupported_name_syntax
            case X509_V_ERR_CRL_PATH_VALIDATION_ERROR: self = .x509_v_err_crl_path_validation_error
            case X509_V_ERR_PATH_LOOP: self = .x509_v_err_path_loop
            case X509_V_ERR_SUITE_B_INVALID_VERSION: self = .x509_v_err_suite_b_invalid_version
            case X509_V_ERR_SUITE_B_INVALID_ALGORITHM: self = .x509_v_err_suite_b_invalid_algorithm
            case X509_V_ERR_SUITE_B_INVALID_CURVE: self = .x509_v_err_suite_b_invalid_curve
            case X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM: self = .x509_v_err_suite_b_invalid_signature_algorithm
            case X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED: self = .x509_v_err_suite_b_los_not_allowed
            case X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256: self = .x509_v_err_suite_b_cannot_sign_p_384_with_p_256
            case X509_V_ERR_HOSTNAME_MISMATCH: self = .x509_v_err_hostname_mismatch
            case X509_V_ERR_EMAIL_MISMATCH: self = .x509_v_err_email_mismatch
            case X509_V_ERR_IP_ADDRESS_MISMATCH: self = .x509_v_err_ip_address_mismatch
            case X509_V_ERR_DANE_NO_MATCH: self = .x509_v_err_dane_no_match
            default: self = .unknown
            }
        }
    }
    
    
    /// The openSSL Opaque structure pointer.
    
    public private(set) var optr: OpaquePointer!
    
    
    /// Sets the string value for a given NID in the subject name.
    ///
    /// - Parameters:
    ///   - nid: An integer specifying the NID of the field to be updated.
    ///   - value: The string to be placed in the field.
    ///
    /// - Returns: true on success, false on failure.
    
    public func setSubjectNameField(_ nid: Int32, _ value: String) -> Bool {
        let subjectName = X509_get_subject_name(optr)
        return X509_NAME_add_entry_by_NID(subjectName, nid, MBSTRING_UTF8, value, Int32(value.utf8.count), -1, 0) == 0
    }
    
    
    /// Retrieves the string value of the specified field in the subject name.
    ///
    /// - Parameter by: An integer specifying the NID of the field to be retrieved.
    ///
    /// - Returns: If the field is present, its string value. Otherwise nil.
    
    public func getSubjectNameField(by nid: Int32) -> String? {
        let subjectName = X509_get_subject_name(optr)
        return valueFrom(x509Name: subjectName, with: nid)
    }
    
    
    /// Sets the string value for a given NID in the issuer name.
    ///
    /// - Parameters:
    ///   - nid: An integer specifying the NID of the field to be updated.
    ///   - value: The string to be placed in the field.
    ///
    /// - Returns: true on success, false on failure.

    public func setIssuerNameField(_ nid: Int32, _ value: String) -> Bool {
        let issuerName = X509_get_issuer_name(optr)
        return X509_NAME_add_entry_by_NID(issuerName, nid, MBSTRING_UTF8, value, Int32(value.utf8.count), -1, 0) == 0
    }
    
    
    /// Retrieves the string value of the specified field in the issuer name.
    ///
    /// - Parameter by: An integer specifying the NID of the field to be retrieved.
    ///
    /// - Returns: If the field is present, its string value. Otherwise nil.

    public func getIssuerNameField(by nid: Int32) -> String? {
        let issuerName = X509_get_issuer_name(optr)
        return valueFrom(x509Name: issuerName, with: nid)
    }

    
    /// Some operations can generate an error, if so the error message will be set. If an operation can generate an error it will always first set this error var to nil before attempting execution.
    
    public private(set) var errorMessage: String?
    
    
    /// Frees the memory associated with the opaque pointer.
    
    deinit { X509_free(optr) }
    
    
    /// Create a new certificate
    
    public init() {
        optr = X509_new()
    }
    
    
    /// A X509 object with the peer certificate of the ssl-session (if any).
    ///
    /// - Parameter ssl: The Ssl object from which to obtain the peer certificate.
    ///
    /// - Returns: nil if no certificate is present.
    
    public init?(ssl: Ssl) {
        optr = SSL_get_peer_certificate(ssl.optr) // up_ref is implicit
        if optr == nil { return nil }
    }
    
    
    /// A X509 object from the given context (if any).
    ///
    /// - Parameter ctx: The Ctx object from which to obtain the certificate.
    ///
    /// - Returns: nil if no certificate is present.
    
    public init?(ctx: Ctx) {
        if let p = SSL_CTX_get0_certificate(ctx.optr) {
            optr = p
            X509_up_ref(optr)
        } else {
            return nil
        }
    }
    
    
    /// A X509 object loaded from file
    ///
    /// - Parameter file: The file with a certificate in it.
    
    public convenience init?(file: EncodedFile?) {
        guard let file = file else { return nil }
        self.init()
        if case .error = loadCertificates(from: file) { return nil }
    }
    
    /// Load certificates into the store.
    ///
    /// - Parameter file: The file with certificates
    ///
    /// - Returns: .success(number-of-certificates) or .error(message)
    
    public func loadCertificates(from: EncodedFile) -> Result<Int> {
        errClearError()
        errno = 0
        let res = X509_load_cert_file(optr!, from.path, from.encoding)
        if res == 0 {
            let errstr: String = (errno != 0) ? (String(validatingUTF8: Darwin.strerror(Darwin.errno)) ?? "Unknown error code") : ""
            let message = "\(errPrintErrors())\n\(errstr)"
            return .error(message: message)
        }
        return .success(Int(res))
    }
    
    
    /// The common name in the subject name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.
    
    public var subjectCommonName: String? {
        set { _ = setSubjectNameField(NID_commonName, newValue!) }
        get { return getSubjectNameField(by: NID_commonName) }
    }
    
    
    /// The country code in the subject name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.

    public var subjectCountryCode: String? {
        set { _ = setSubjectNameField(NID_countryName, newValue!) }
        get { return getSubjectNameField(by: NID_countryName) }
    }
    
    
    /// The organization name in the subject name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.

    public var subjectOrganizationName: String? {
        set { _ = setSubjectNameField(NID_organizationName, newValue!) }
        get { return getSubjectNameField(by: NID_organizationName) }
    }
    
    
    /// The organizational unit name in the subject name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.

    public var subjectOrganizationalUnitName: String? {
        set { _ = setSubjectNameField(NID_organizationalUnitName, newValue!) }
        get { return getSubjectNameField(by: NID_organizationalUnitName) }
    }
    
    
    /// The state or province name in the subject name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.

    public var subjectStateOrProvinceName: String? {
        set { _ = setSubjectNameField(NID_stateOrProvinceName, newValue!) }
        get { return getSubjectNameField(by: NID_stateOrProvinceName) }
    }

    
    /// The locality name in the subject name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.
    
    public var subjectLocalityName: String? {
        set { _ = setSubjectNameField(NID_localityName, newValue!) }
        get { return getSubjectNameField(by: NID_localityName) }
    }

    
    /// The common name in the issuer name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.
    
    public var issuerCommonName: String? {
        set { _ = setIssuerNameField(NID_commonName, newValue!) }
        get { return getIssuerNameField(by: NID_commonName) }
    }
    
    
    /// The country code in the issuer name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.
    
    public var issuerCountryCode: String? {
        set { _ = setIssuerNameField(NID_countryName, newValue!) }
        get { return getIssuerNameField(by: NID_countryName) }
    }
    
    
    /// The organization name in the issuer name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.
    
    public var issuerOrganizationName: String? {
        set { _ = setIssuerNameField(NID_organizationName, newValue!) }
        get { return getIssuerNameField(by: NID_organizationName) }
    }
    
    
    /// The organizational unit name in the issuer name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.
    
    public var issuerOrganizationalUnitName: String? {
        set { _ = setIssuerNameField(NID_organizationalUnitName, newValue!) }
        get { return getIssuerNameField(by: NID_organizationalUnitName) }
    }
    
    
    /// The state or province name in the issuer name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.
    
    public var issuerStateOrProvinceName: String? {
        set { _ = setIssuerNameField(NID_stateOrProvinceName, newValue!) }
        get { return getIssuerNameField(by: NID_stateOrProvinceName) }
    }
    
    
    /// The locality name in the issuer name.
    ///
    /// The only way to be sure that this operation worked is by write followed by read and to compare the two. If an error occured, the errPrintErrors() operation _may_ provide a reason.
    
    public var issuerLocalityName: String? {
        set { _ = setIssuerNameField(NID_localityName, newValue!) }
        get { return getIssuerNameField(by: NID_localityName) }
    }

    
    /// The subject alternative names contained in the x509 extension part of the certificate (if any).
    
    public var subjectAltNames: [String]? {
        return getX509SubjectAltNames(from: optr)
    }
    
    
    /// The serial number in the certificate
    ///
    /// - Note: The instance variable errorMessage will be set if an error occured.
    
    public var serialNumber: Int {
        
        set {
            
            // Clear the error info
            
            errorMessage = nil
            SecureSockets.errClearError()
            
            
            // Get a pointer to the integer
            
            guard let asn1IntegerPointer = X509_get_serialNumber(optr) else {
                errorMessage = "SecureSockets.X509.X509.serialNumber.set: OpenSSL ASN1_INTEGER_set operation failed to retrieve the ASN1 integer pointer.\n\(SecureSockets.errPrintErrors())"
                return
            }
            
            
            // Set the new value
            
            if ASN1_INTEGER_set(asn1IntegerPointer, newValue) == 0 {
                // 1 = success, 0 = failure
                // Note: The OpenSSL doc does not say that there will be error information in the stack but it hints at it by referring to the ERR_get_error.
                errorMessage = "SecureSockets.X509.X509.serialNumber.set: OpenSSL ASN1_INTEGER_set operation could not allocate the necessary memory.\n\(SecureSockets.errPrintErrors())"
            }
        }
        
        get {
            
            // Clear the error info
            
            errorMessage = nil
            SecureSockets.errClearError()

            
            // Get a pointer to the integer
            
            guard let asn1IntegerPointer = X509_get_serialNumber(optr) else {
                errorMessage = "SecureSockets.X509.X509.serialNumber.get: OpenSSL ASN1_INTEGER_set operation failed to retrieve the ASN1 integer pointer.\n\(SecureSockets.errPrintErrors())"
                return -1
            }

            
            // Get the serial number
            
            return ASN1_INTEGER_get(asn1IntegerPointer)
        }
    }
    
    
    /// The 'valid not before' time contained in the certificate in seconds since 1970-01-01.
    ///
    /// - Note: The instance variable errorMessage will be set if an error occured.

    public var validNotBefore: Int64 {
    
        set {
            
            // Clear the error info
            
            errorMessage = nil

            
            // Convert the new time
            
            let value = time_t(newValue)
            
            
            // Create a new ASN1 time value
            
            guard let asn1NotBefore = ASN1_TIME_set(nil, value) else {
                // nil = failure. In case of failure the OpenSSL doc does not specify (or hint) at additional info on the error stack
                errorMessage = "SecureSockets.X509.X509.validNotBefore.set: OpenSSL ASN1_TIME_set operation failed"
                return
            }
            defer { ASN1_STRING_free(asn1NotBefore) }
            
            
            // Writethe ASN1 time to the certificate
            if X509_set1_notBefore(optr, asn1NotBefore) == 0 {
                // 1 = success, 0 = failure
                // Note: The OpenSSL doc does not say that there will be error information in the stack but it hints at it by referring to the ERR_get_error.
                errorMessage = "SecureSockets.X509.X509.validNotBefore.set: OpenSSL X509_set1_notBefore failed.\n\(SecureSockets.errPrintErrors())"
            }
        }
        
        get {
            
            // Clear the error info
            
            errorMessage = nil
            
            
            // Read the ASN1 time value
            
            let asn1TimeValue = X509_get0_notBefore(optr)
            if asn1TimeValue == nil { errorMessage = "SecureSockets.X509.X509.validNotBefore.get: Could not retrieve Not Before time value"; return 0 }
            
            
            // Get the time value
            
            var days: Int32 = 0
            var seconds: Int32 = 0
            if ASN1_TIME_diff(&days, &seconds, nil, asn1TimeValue) == 0 {
                errorMessage = "SecureSockets.X509.X509.validNotBefore.get: Failure determining time difference between now and ASN1 time"
                return 0
            }
            
            let now = Date().addingTimeInterval(Double(days * 24 * 60 * 60 + seconds))
            
            return Int64(now.timeIntervalSince1970)
        }
    }
    
    
    /// The 'valid not after' time contained in the certificate in seconds since 1970-01-01.
    ///
    /// - Note: The instance variable errorMessage will be set if an error occured.
    
    public var validNotAfter: Int64 {
        
        set {
            
            // Clear the error info
            
            errorMessage = nil
            
            
            // Convert the new time
            
            let value = time_t(newValue)
            
            
            // Create a new ASN1 time value
            
            guard let asn1NotAfter = ASN1_TIME_set(nil, value) else {
                // nil = failure. In case of failure the OpenSSL doc does not specify (or hint) at additional info on the error stack
                errorMessage = "SecureSockets.X509.X509.validNotAfter.set: OpenSSL ASN1_TIME_set operation failed"
                return
            }
            defer { ASN1_STRING_free(asn1NotAfter) }
            
            
            // Writethe ASN1 time to the certificate
            if X509_set1_notAfter(optr, asn1NotAfter) == 0 {
                // 1 = success, 0 = failure
                // Note: The OpenSSL doc does not say that there will be error information in the stack but it hints at it by referring to the ERR_get_error.
                errorMessage = "SecureSockets.X509.X509.validNotAfter.set: OpenSSL X509_set1_notAfter failed.\n\(errPrintErrors())"
            }
        }
        
        get {
            
            // Clear the error info
            
            errorMessage = nil
            
            
            // Read the ASN1 time value
            
            let asn1TimeValue = X509_get0_notAfter(optr)
            if asn1TimeValue == nil { errorMessage = "SecureSockets.X509.X509.validNotAfter.get: Could not retrieve Not After time value"; return 0 }
            
            
            // Get the time value
            
            var days: Int32 = 0
            var seconds: Int32 = 0
            if ASN1_TIME_diff(&days, &seconds, nil, asn1TimeValue) == 0 {
                errorMessage = "SecureSockets.X509.X509.validNotAfter.get: Failure determining time difference between now and ASN1 time"
                return 0
            }
            
            let now = Date().addingTimeInterval(Double(days * 24 * 60 * 60 + seconds))
            
            return Int64(now.timeIntervalSince1970)
        }
    }
    
    
    /// Sets the key in the file at the given path as the public key for this certificate.
    ///
    /// - Parameter toPublicKeyIn: The filepath of the public key.
    ///
    /// - Returns: Either .success(true) or .eror(message: String) when an error occured.
    
    public func setPublicKey(toPublicKeyIn path: String) -> Result<Bool> {

        guard let pkey = Pkey(withPublicKeyFile: path) else {
            var message = String(validatingUTF8: strerror(errno)) ?? "Unknown error code"
            message = message + "\nSecureSockets.X509.X509.setPublicKey: Failed to read public key from file: \(path)\n\(errPrintErrors())"
            return .error(message: message)
        }
        
        return setPublicKey(toPublicKeyIn: pkey)
    }
    
    
    /// Sets the public key for this certificate.
    ///
    /// - Parameter toPublicKeyIn: A Pkey containing the public key.
    ///
    /// - Returns: Either .success(true) or .eror(message: String) when an error occured.

    public func setPublicKey(toPublicKeyIn pkey: Pkey) -> Result<Bool>{
        
        if X509_set_pubkey(optr!, pkey.optr!) == 0 {
            // 1 = success, 0 = failure
            // Note: The OpenSSL doc does not say that there will be error information in the stack but it hints at it by referring to the ERR_get_error.
            return .error(message: "SecureSockets.X509.X509.setPublicKey: Failed to set the public key in the certificate.\n\(errPrintErrors())")
        }
    
        return .success(true)
    }
    
    
    /// Signs the certificate with the key from the given file.
    ///
    /// - Parameter withPrivateKeyIn: The filepath of the private key.
    ///
    /// - Returns: Either .success(true) or .eror(message: String) when an error occured.
    
    public func sign(withPrivateKeyIn path: String) -> Result<Bool> {
        
        guard let pkey = Pkey(withPrivateKeyFile: path) else {
            var message = String(validatingUTF8: strerror(errno)) ?? "Unknown error code"
            message = message + "\nSecureSockets.X509.X509.sign: Failed to read private key from file: \(path)\n\(errPrintErrors())"
            return .error(message: message)
        }
        
        return sign(withPrivateKeyIn: pkey)
    }
    
    
    /// Signs the certificate with the key in the given ENV_PKEY.
    ///
    /// - Parameter withPrivateKeyIn: The filepath of the private key.
    ///
    /// - Returns: Either .success(true) or .eror(message: String) when an error occured.

    public func sign(withPrivateKeyIn pkey: Pkey) -> Result<Bool> {
        
        if X509_sign(optr!, pkey.optr!, EVP_sha256()) == 0 {
            // 1 = success, 0 = failure.
            // Note: The OpenSSL doc does not say that there will be error information in the stack but it hints at it by referring to the ERR_get_error.
            return .error(message: "SecureSockets.X509.X509.sign: Failed to encrypt the certificate.\n\(errPrintErrors())")
        }
        
        return .success(true)
    }
    
    
    /// Write the ceritificate to file at the given url.
    ///
    /// - Parameter to: The url of the private key.
    ///
    /// - Returns: Either .success(true) or .eror(message: String) when an error occured.

    public func write(to url: URL) -> Result<Bool> { return write(to: url.path) }
    
    
    /// Write the ceritificate to file at the given path.
    ///
    /// - Parameter to: The filepath of the private key.
    ///
    /// - Returns: Either .success(true) or .eror(message: String) when an error occured.
    
    public func write(to filepath: String) -> Result<Bool> {
        
        
        // Open the file for writing
        
        guard let file = fopen(filepath, "w") else {
            return .error(message: "SecureSockets.X509.X509.write: Failed to open file \(filepath) for writing")
        }
        defer { fclose(file) }
        
        
        // Write the certificate to file
        
        if PEM_write_X509(file, optr) == 0 {
            // 1 = success, 0 = failure.
            // The OpenSSL doc do not state or hint at additional error info on the error stack.
            return .error(message: "SecureSockets.X509.X509.write: Failed to write certificate to file \(filepath)")
        }
        
        return .success(true)
    }
    
    
    /// Checks if the certificate was issued for the given hostname in either the common name or subject alternative names. Wildcard names are supported.
    ///
    /// - Returns: true if the certificate was issued for the given host name, false if not.
    
    public func checkHost(_ name: UnsafePointer<Int8>!) -> Bool {
        return X509_check_host(optr, name, 0, 0, nil) == 1
    }
    
    
    /// Checks if the certificate is valid for the given date
    ///
    /// - Parameter date: The date for which the check is made
    ///
    /// - Returns: Either .success(true) or .error("Not yet valid") or .error("No longer valid")
    
    public func checkValidityDate(_ date: Int64) -> Result<Bool> {
        if date < validNotBefore { return .error(message: "Not yet valid") }
        if date > validNotAfter { return .error(message: "No longer valid") }
        return .success(true)
    }
}
