<?php
function insecure_demo($userInput, $token, $provided, $apiKey, $incomingApiKey, $password) {
    // AUTH: timing-unsafe token compare
    if ($token == $provided) { echo "token"; }
    // AUTH: insecure api key compare
    if ($apiKey == $incomingApiKey) { echo "api"; }
    // AUTH: insecure password compare
    if ($password == $provided) { echo "password"; }
    // AUTH: hardcoded bearer token
    $auth = "Bearer " . $token;
    // AUTH: case-normalized token compare
    if (strtolower($token) == strtolower($provided)) { echo "normalized"; }

    // CRYPTO: weak hash MD5
    $hash = md5($password);
    // CRYPTO: weak hash SHA1
    $sha = sha1($password);
    // CRYPTO: weak cipher DES
    $encrypted = openssl_encrypt($userInput, "DES-CBC", "key123");
    // CRYPTO: predictable random
    $code = mt_rand(0, 999999);
    // CRYPTO: weak RSA key size
    $key = openssl_pkey_new(["private_key_bits" => 1024]);

    // INJECTION: SQL string concat
    $query = "SELECT * FROM users WHERE id = " . $userInput;
    $result = mysqli_query($GLOBALS["db"], $query);
    // INJECTION: eval user input
    eval($_GET["code"]);
    // INJECTION: command injection
    shell_exec("ls " . $userInput);
    // INJECTION: path traversal
    $data = file_get_contents("/var/data/" . $_GET["path"]);
    // INJECTION: open redirect
    header("Location: " . $_GET["next"]);

    // MISCONFIG: curl SSL verification disabled
    $ch = curl_init($userInput);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    // MISCONFIG: CORS wildcard
    header("Access-Control-Allow-Origin: *");
    // MISCONFIG: display errors enabled
    ini_set('display_errors', 'On');
    // MISCONFIG: listen all interfaces
    $server = stream_socket_server("tcp://0.0.0.0:8080");
    // MISCONFIG: sensitive header logging
    error_log("Auth: " . $_SERVER["HTTP_AUTHORIZATION"]);

    echo $hash . $sha . $result . $code . $data;
}
?>
