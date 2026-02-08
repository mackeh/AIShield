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
    if token.lowercased() == provided.lowercased() { print("case-normalized") }

    let authHeader = "Authorization: Bearer \(userInput)"
    print("Authorization: \(authHeader)")
    let bearerHeader = "Authorization: Bearer " + userInput
    print(bearerHeader)

    let bytes = [UInt8](userInput.utf8)
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    CC_MD5(bytes, CC_LONG(bytes.count), &digest)

    var digestSha1 = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    CC_SHA1(bytes, CC_LONG(bytes.count), &digestSha1)

    _ = CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeECB), CCAlgorithm(kCCAlgorithmDES), CCPadding(ccPKCS7Padding), nil, nil, 8, nil, 0, 0, CCModeOptions(), nil)
    let weakRSAAttrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 1024]
    print(weakRSAAttrs)

    let tokenGuess = Int.random(in: 100000...999999)
    print(tokenGuess)

    let sql = "SELECT * FROM users WHERE id = " + userInput
    print(sql)
    let formattedSql = String(format: "SELECT * FROM users WHERE id = %@", userInput)
    print(formattedSql)

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

    let bindAddress = "http://0.0.0.0:8080"
    print(bindAddress)

    let _ = { (_: URLSession, didReceive _: URLAuthenticationChallenge) -> URLCredential in
        return URLCredential(trust: trust)
    }
}
