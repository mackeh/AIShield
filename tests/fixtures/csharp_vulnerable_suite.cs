using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;

class CsharpVulnerableSuite
{
    void InsecureDemo(string userInput, string token, string provided, string apiKey, string incomingApiKey, string password, HttpClientHandler handler, SqlConnection conn, HttpContext ctx)
    {
        // AUTH: timing-unsafe token compare
        if (token == provided) { Console.WriteLine("timing"); }
        // AUTH: insecure api key compare
        if (apiKey == incomingApiKey) { Console.WriteLine("api"); }
        // AUTH: insecure password compare
        if (password == provided) { Console.WriteLine("password match"); }
        // AUTH: hardcoded bearer token
        var authorization = "Bearer " + token;
        // AUTH: case-normalized token compare
        if (token.ToLower() == provided.ToLower()) { Console.WriteLine("normalized"); }

        // CRYPTO: weak hash MD5
        using var md5 = MD5.Create();
        var hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        // CRYPTO: weak hash SHA1
        using var sha = SHA1.Create();
        var sha1hash = sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        // CRYPTO: weak cipher DES
        var des = new DESCryptoServiceProvider();
        // CRYPTO: predictable random
        var rng = new Random();
        var code = rng.Next(1000000);
        // CRYPTO: weak RSA key size
        var rsa = new RSACryptoServiceProvider(1024);

        // INJECTION: SQL string concat
        var query = "SELECT * FROM users WHERE id = " + userInput;
        var command = new SqlCommand(query, conn);
        // INJECTION: process shell command
        var psi = new ProcessStartInfo("sh", "-c cat " + userInput);
        Process.Start(psi);
        // INJECTION: path traversal
        var data = File.ReadAllText("/var/data/" + userInput);
        // INJECTION: open redirect
        ctx.Response.Redirect(ctx.Request.Query["next"]);
        // INJECTION: LDAP string concat
        var filter = "(uid=" + userInput + ")";

        // MISCONFIG: TLS validation disabled
        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
        // MISCONFIG: CORS wildcard
        ctx.Response.Headers.Add("Access-Control-Allow-Origin", "*");
        // MISCONFIG: debug mode
        var debug = true;
        // MISCONFIG: listen all interfaces
        var endpoint = "0.0.0.0:8080";
        // MISCONFIG: sensitive header logging
        Console.WriteLine("log: " + ctx.Request.Headers["Authorization"]);

        Console.WriteLine(hash.Length + command.CommandText.Length + data.Length + code + filter.Length + endpoint.Length);
    }
}
