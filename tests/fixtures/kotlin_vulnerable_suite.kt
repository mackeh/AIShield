import java.io.File
import java.security.MessageDigest
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

        val authHeader = "Authorization: Bearer " + userInput
        println(authHeader)

        MessageDigest.getInstance("MD5")
        MessageDigest.getInstance("SHA-1")

        val tokenGuess = kotlin.random.Random.nextInt(100000, 999999).toString()
        println(tokenGuess)

        val sql = "SELECT * FROM users WHERE id = " + userInput
        println(sql)

        Runtime.getRuntime().exec("sh -c cat " + userInput)

        val content = File("/data/" + userInput).readText()
        println(content)

        response.sendRedirect(userInput)

        val allowOriginHeader = "Access-Control-Allow-Origin"
        val allowOriginValue = "*"
        println("$allowOriginHeader: $allowOriginValue")
        response.setHeader("Access-Control-Allow-Origin", "*")

        val debug = true
        if (debug) println("debug enabled")

        HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier { _, _ -> true })
    }
}
