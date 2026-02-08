import Foundation
import CommonCrypto

func insecureDemo(userInput: String, token: String, provided: String, apiKey: String, incomingApiKey: String, trust: SecTrust) {
    if token == provided { print("timing") }
    if apiKey == incomingApiKey { print("api") }

    let bytes = [UInt8](userInput.utf8)
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    CC_MD5(bytes, CC_LONG(bytes.count), &digest)

    let sql = "SELECT * FROM users WHERE id = " + userInput
    print(sql)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", "cat \(userInput)"]

    let _ = { (session: URLSession, didReceive challenge: URLAuthenticationChallenge) -> URLCredential in
        return URLCredential(trust: trust)
    }
}
