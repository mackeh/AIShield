<?php
function insecure_demo($userInput, $token, $provided, $apiKey, $incomingApiKey, $password) {
    if ($token == $provided) { echo "token"; }
    if ($apiKey == $incomingApiKey) { echo "api"; }

    $hash = md5($password);

    $query = "SELECT * FROM users WHERE id = " . $userInput;
    $result = mysqli_query($GLOBALS["db"], $query);

    eval($_GET["code"]);

    $ch = curl_init($userInput);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

    echo $hash . $result;
}
?>
