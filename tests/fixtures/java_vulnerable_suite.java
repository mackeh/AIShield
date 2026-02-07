import java.security.MessageDigest;
import java.sql.Statement;
import java.util.Random;

class JavaVulnerableSuite {
    void insecureDemo(String userInput, String token, String provided, Statement stmt) throws Exception {
        Runtime.getRuntime().exec("sh -c cat " + userInput);

        MessageDigest.getInstance("MD5");

        String query = "SELECT * FROM users WHERE id = " + userInput;
        stmt.executeQuery(query);

        if (token == provided) {
            System.out.println("timing-unsafe compare");
        }

        Random r = new Random();
        int code = r.nextInt(1000000);
        System.out.println(code);
    }
}
