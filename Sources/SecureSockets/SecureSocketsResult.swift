// =====================================================================================================================
//
//  File:       SecureSocketsResult.swift
//  Project:    SecureSockets
//
//  Version:    1.1.0
//
//  Author:     Marinus van der Lugt
//  Company:    http://balancingrock.nl
//  Website:    http://swiftfire.nl/projects/securesockets/securesockets.html
//  Git:        https://github.com/Balancingrock/SecureSockets
//
//  Copyright:  (c) 2020 Marinus van der Lugt, All rights reserved.
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
// 1.1.0 - Initial version
//
// =====================================================================================================================

import Foundation


/// Used for the failure option of Swift.Result

public enum SecureSocketsError: Error {
    case message(String)
    var errorDescription: String? {
        switch self {
        case .message(let str): return str
        }
    }
    static func withMessage(file: String = #file, function: String = #function, line: Int = #line, _ str: String) -> SecureSocketsError {
        return SecureSocketsError.message("\(file).\(function).\(line): \(str)")
    }
}


/// Typealias for a result with a secure socket failure case.

public typealias SecureSocketsResult<T> = Result<T, SecureSocketsError>



