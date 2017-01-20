import XCTest
@testable import SecureSockets

class SecureSocketsTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(SecureSockets().text, "Hello, World!")
    }


    static var allTests : [(String, (SecureSocketsTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
