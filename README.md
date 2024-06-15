<p align="center">
<p align="center">
  <a href="https://github.com/i-rin-eam">
    <img src="https://avatars.githubusercontent.com/u/154800878?s=400&u=5d18880cc28646190a19a971bfcdbc54644eab07&v=4" alt="Logo" width="100" height="100">
  </a> 
<h2 align='center'>Send Firebase Push Notifications from Server using the new FCM HTTP v1 API</h12>
</p>

## Step 1: Here is `firebase.php` code.
```php
<?php

// Include the get-access-token.php
require 'get-access-token.php';

// Path to your service account key file
$serviceAccountKeyFile = 'service-account-file.json';

// Obtain the OAuth 2.0 Bearer Token
$accessToken = getAccessToken($serviceAccountKeyFile);

// FCM message details
$token = 'your_target_device_token';
$title = "কি খবর তোমাদের?";
$body = "ভালো আছি ভালো থেকো, আকাশের ঠিকানায় চিঠি লিখো........";

$url = "https://fcm.googleapis.com/v1/projects/{project-id}/messages:send";

// Prepare FCM message data
$datamsg = array(
    'title' => $title,
    'body' => $body
);
$arrayToSend = array('token' => $token, 'data' => $datamsg);

$json = json_encode(['message' => $arrayToSend]);

// Prepare headers
$headers = array();
$headers[] = 'Content-Type: application/json';
$headers[] = 'Authorization: Bearer ' . $accessToken;

// Initialize curl session
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

// Send the request
$response = curl_exec($ch);

// Check for curl errors
if ($response === FALSE) {
    die('FCM Send Error: ' . curl_error($ch));
}

// Close curl session
curl_close($ch);

?>
```
## Step 2: Here is `get-access-token.php` code.
```php
<?php

// Function to get OAuth 2.0 Bearer Token
function getAccessToken($serviceAccountKeyFile)
{
    $serviceAccount = json_decode(file_get_contents($serviceAccountKeyFile), true);
    $jwt = generateJWT($serviceAccount);
    $url = 'https://oauth2.googleapis.com/token';

    $post = [
        'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion' => $jwt,
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

    $response = curl_exec($ch);
    curl_close($ch);

    if (!$response) {
        die('Error obtaining access token');
    }

    $data = json_decode($response, true);

    if (isset($data['access_token'])) {
        return $data['access_token'];
    } else {
        die('Error obtaining access token');
    }
}

// Function to generate JWT
function generateJWT($serviceAccount)
{
    $header = [
        'alg' => 'RS256',
        'typ' => 'JWT',
    ];

    $now = time();
    $exp = $now + 3600; // 1 hour expiration

    $payload = [
        'iss' => $serviceAccount['client_email'],
        'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
        'aud' => 'https://oauth2.googleapis.com/token',
        'iat' => $now,
        'exp' => $exp,
    ];

    $base64UrlHeader = base64UrlEncode(json_encode($header));
    $base64UrlPayload = base64UrlEncode(json_encode($payload));

    $signatureInput = $base64UrlHeader . '.' . $base64UrlPayload;
    $signature = '';
    openssl_sign($signatureInput, $signature, $serviceAccount['private_key'], 'sha256');

    $base64UrlSignature = base64UrlEncode($signature);

    return $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;
}

function base64UrlEncode($data)
{
    return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
}

?>
```
## Authors

**MD YEAMIN** - Android Software Developer <a href="https://www.youtube.com/@LearnWithYeamin">**(Learn With Yeamin)**</a> 

<h1 align="center">Thank You ❤️</h1>
