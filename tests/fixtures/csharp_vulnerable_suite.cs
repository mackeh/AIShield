using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;

class CsharpVulnerableSuite
{
    void InsecureDemo(string userInput, string token, string provided, string apiKey, string incomingApiKey, string password, HttpClientHandler handler, SqlConnection conn)
    {
        if (token == provided) { Console.WriteLine("timing"); }
        if (apiKey == incomingApiKey) { Console.WriteLine("api"); }

        using var md5 = MD5.Create();
        var hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

        var query = "SELECT * FROM users WHERE id = " + userInput;
        var command = new SqlCommand(query, conn);

        var psi = new ProcessStartInfo("sh", "-c cat " + userInput);
        Process.Start(psi);

        handler.ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true;
        Console.WriteLine(hash.Length + command.CommandText.Length);
    }
}
