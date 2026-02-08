import java.security.MessageDigest
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

class KotlinVulnerableSuite {
    fun insecureDemo(userInput: String, token: String, provided: String, apiKey: String, incomingApiKey: String) {
        if (token == provided) println("timing")
        if (apiKey == incomingApiKey) println("api")

        MessageDigest.getInstance("MD5")

        val sql = "SELECT * FROM users WHERE id = " + userInput
        println(sql)

        Runtime.getRuntime().exec("sh -c cat " + userInput)

        HttpsURLConnection.setDefaultHostnameVerifier(HostnameVerifier { _, _ -> true })
    }
}
