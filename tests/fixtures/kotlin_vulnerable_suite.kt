import java.io.File
import java.security.KeyPairGenerator
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

class KotlinVulnerableSuite {
    fun insecureDemo(
        userInput: String,
        token: String,
        provided: String,
        apiKey: String,
        incomingApiKey: String,
        password: String,
        expectedPassword: String,
    ) {
        if (token == provided) println("timing")
        if (apiKey == incomingApiKey) println("api")
        if (password == expectedPassword) println("password")
        if (token.lowercase() == provided.lowercase()) println("case-normalized")

        val authHeader = "Authorization: Bearer " + userInput
        println(authHeader)
        println("Authorization:" + authHeader)

        MessageDigest.getInstance("MD5")
        MessageDigest.getInstance("SHA-1")
        Cipher.getInstance("DES/ECB/PKCS5Padding")
        KeyPairGenerator.getInstance("RSA").initialize(1024)

        val tokenGuess = kotlin.random.Random.nextInt(100000, 999999).toString()
        println(tokenGuess)

        val sql = "SELECT * FROM users WHERE id = " + userInput
        println(sql)
        val sqlFormatted = "SELECT * FROM users WHERE id = %s".format(userInput)
        println(sqlFormatted)

        Runtime.getRuntime().exec("sh -c cat " + userInput)

        val content = File("/data/" + userInput).readText()
        println(content)

        response.sendRedirect(userInput)

        val allowOriginHeader = "Access-Control-Allow-Origin"
        val allowOriginValue = "*"
        println("$allowOriginHeader: $allowOriginValue")
        response.setHeader("Access-Control-Allow-Origin", "*")

        server("0.0.0.0", 8080)

        val debug = true
        if (debug) println("debug enabled")

        HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier { _, _ -> true })
    }
}
