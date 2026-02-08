import Foundation
import CommonCrypto

func insecureDemo(
    userInput: String,
    token: String,
    provided: String,
    apiKey: String,
    incomingApiKey: String,
    password: String,
    expectedPassword: String,
    trust: SecTrust
) {
    if token == provided { print("timing") }
    if apiKey == incomingApiKey { print("api") }
    if password == expectedPassword { print("password") }

    let authHeader = "Authorization: Bearer \(userInput)"
    print("Authorization: \(authHeader)")

    let bytes = [UInt8](userInput.utf8)
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    CC_MD5(bytes, CC_LONG(bytes.count), &digest)

    var digestSha1 = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    CC_SHA1(bytes, CC_LONG(bytes.count), &digestSha1)

    let tokenGuess = Int.random(in: 100000...999999)
    print(tokenGuess)

    let sql = "SELECT * FROM users WHERE id = " + userInput
    print(sql)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", "cat \(userInput)"]

    let filePath = "/data/" + userInput
    let leaked = try? String(contentsOfFile: filePath)
    print(leaked ?? "")

    if let redirectUrl = URL(string: userInput) { UIApplication.shared.open(redirectUrl) }

    let insecureConfig: [String: Any] = ["NSAllowsArbitraryLoads": true]
    print(insecureConfig)

    let insecureUrl = URL(string: "http://example.com/api")!
    URLSession.shared.dataTask(with: insecureUrl)
    URLSession.shared.dataTask(with: URL(string: "http://example.com/fallback")!)

    let _ = { (_: URLSession, didReceive _: URLAuthenticationChallenge) -> URLCredential in
        return URLCredential(trust: trust)
    }
}
