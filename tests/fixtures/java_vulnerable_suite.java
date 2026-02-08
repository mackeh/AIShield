import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Random;
import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;
import javax.script.ScriptEngine;

class JavaVulnerableSuite {
    void insecureDemo(String userInput, String token, String provided, Statement stmt, HttpServletRequest request, HttpServletResponse response, Logger logger, HttpServer server, HttpsURLConnection conn, ScriptEngine engine) throws Exception {
        Runtime.getRuntime().exec("sh -c cat " + userInput);

        String cmd = "cat " + userInput;
        Runtime.getRuntime().exec(cmd);

        MessageDigest.getInstance("MD5");
        MessageDigest.getInstance("SHA1");
        Cipher.getInstance("DES/ECB/PKCS5Padding");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);

        String query = "SELECT * FROM users WHERE id = " + userInput;
        stmt.executeQuery(query);

        if (token == provided) {
            System.out.println("timing-unsafe compare");
        }

        String apiKey = request.getHeader("X-Api-Key");
        String incomingApiKey = request.getParameter("apiKey");
        if (apiKey.equals(incomingApiKey)) {
            System.out.println("api key compare");
        }

        String password = request.getParameter("password");
        String expectedPassword = request.getHeader("X-Expected-Password");
        if (password.equals(expectedPassword)) {
            System.out.println("password compare");
        }

        if (token.toLowerCase().equals(provided.toLowerCase())) {
            System.out.println("case normalized compare");
        }

        String authorization = "Bearer " + token;
        System.out.println(authorization);

        Random r = new Random();
        int code = r.nextInt(1000000);
        System.out.println(code);

        engine.eval(userInput);
        response.sendRedirect(request.getParameter("next"));

        HashMap<String, String> config = new HashMap<>();
        config.put("cors", "*");
        boolean debug = true;
        conn.setHostnameVerifier((h,s) -> true);
        server.setAddress("0.0.0.0");
        logger.info("Authorization: " + request.getHeader("Authorization"));
        System.out.println(config + ":" + debug);
    }
}
