<?php
// You can enable error reporting for debugging
// ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(0);//(E_ALL); // Set this E_ALL to have all errors printed

//Insure the following include points to the location of the RSA.php on your server
require_once('phpseclib/Crypt/RSA.php'); // The Library required to check our signatures from phpseclib
include_once('GSSDK.php');
//include_once('config.php');

$errors="<br />Your request can not be completed due to missing values: <br /><br />";
$dataCenter='';
$apiKey='';
$id_token='';

// Clean JWT
function sanitize($str)
{
    return str_replace(['-','_'], ['+','/'], $str);
    // return $str;
}
function base64Decode($str)
{
    return base64_decode($str);
    // return $str;
}
// echo "id_token" . $_GET['id_token'];
// Retrieve Data Center from URL params
if (isset($_GET['dataCenter']) && $_GET['dataCenter'] !== "") {
    $dataCenter = $_GET['dataCenter'];
} else {
    $dataCenter = 'undefined';
    $errors .='dataCenter was undefined.<br />';
    echo $errors;
    return;
}
// Retrieve ApiKey from URL params
if (isset($_GET['apiKey']) && $_GET['apiKey'] !== "") {
    $apiKey = $_GET['apiKey'];
} else {
    $apiKey = 'undefined';
    $errors .='apiKey was undefined.<br />';
    echo $errors;
    return;
}
// Retrieve JWT from URL params
if (isset($_GET['id_token']) && $_GET['id_token'] !== "") {
    $id_token = $_GET['id_token'];
} else {
    $id_token = 'undefined';
    $errors .='tokenData was undefined.<br />';
    echo $errors;
    return;
}

// Split the Token into 3 parts (separated by '.') -> Header, Payload, Signature
// $id_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtleWlkIjoiUkVRME1VUTVOME5DUlRKRU16azNNMFUxUmtORFEwVTBRME0xUkVGQlJqaERNamRFTlVGQlFnIn0.eyJpc3MiOiJodHRwczovL2ZpZG0uZ2lneWEuY29tL2p3dC8zX2FTVVV5T1JuV19JQ1dIc3V4RDVjVVZCanRuY044d3dqbnJmLUZ1MWhpU05ucUQtM3ZXWHZnbnFoSS16MVRna2cvIiwiYXBpS2V5IjoiM19hU1VVeU9SbldfSUNXSHN1eEQ1Y1VWQmp0bmNOOHd3am5yZi1GdTFoaVNObnFELTN2V1h2Z25xaEktejFUZ2tnIiwiaWF0IjoxNDk1MTc5NzUwLCJleHAiOjE0OTUyMTU3NTAsInN1YiI6ImNlOWViOTg3MGMwMjQ0MzI4MjFmMzQ0NjE5NjA2OGVlIiwicHJvZmlsZS5sYXN0TmFtZSI6Ik5hcnZhcnRlIiwicHJvZmlsZS5maXJzdE5hbWUiOiJNaWNoYWVsIn0.Gdc4nAdUGLbHNIr73WoxQC_Atxlp30GugjE1KUgg6eJmw01ILFz0YlM1j1_fLkoR0DietYouAVOemIUnxLRPcwxTtskur1aea8uzo7aA0TAM-quihbaHsiWJW2PWSyTrcIgdXJ9b2c4EL2BbSXcaUD0eXQ5PTFd34yj9brWbk0Blf5cco0uEiUPf8O-RS7DRXzaLDTKP3dSGO2qgxsJiHb9ffDtZKGwby5W52AmSDSbrO7RiogVL61dKj98g9YgoML-er5BCYOdJbMRHtydKrlMYQ2-yup42tU8NsIW3oq7F2w4zjV-rjB5iv968O49r_yGvX60QhthV5R4w5zr35g";
$splitToken =  explode(".",$id_token);
$header = $splitToken[0];
$payload = $splitToken[1];
$tokenData = $header . '.' . $payload; // first two parts concanated
$signature = $splitToken[2];

// Get Key ID from header
$keyId = json_decode(base64Decode($header))->keyid;

// Get JWT Public Key -> Modulus & Exponent
$getJWTPublicKeys = file_get_contents('https://fidm.' . $dataCenter . '/oidc/op/v1.0/' . $apiKey . '/.well-known/jwks');
$JWTPublicKeys = json_decode($getJWTPublicKeys);
foreach ($JWTPublicKeys->keys as $JWTPubliKey) {
  if ($JWTPubliKey->kid = $keyId) {
    $modulus = $JWTPubliKey->n;
    $exponent = $JWTPubliKey->e;
  }
}
// Format Signature, Modulus and Exponent
$signature = base64Decode(sanitize($signature));
$modulus = base64Decode(sanitize($modulus));
$exponent = base64Decode(sanitize($exponent));

// echo "modulus: " . $getJWTPublicKey["modulus"];
// echo "modulus: " . bin2hex($modulus);
// echo "exponent: " . bin2hex($exponent);
// echo "signature: " . bin2hex($signatureb64);

echo $json;
// Validate signature
$rsa = new Crypt_RSA();
$rsa->loadKey([
    'n' => new Math_BigInteger($modulus, 256),
    'e' => new Math_BigInteger($exponent, 256)
]);

$rsa->setHash('sha256');
$rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);


echo $rsa->verify($tokenData, $signature) ?
    '<span style="color: green; font-weight: bold; font-size: 20px;">  => Valid Signature!</span>' :
    '<span style="color: red; font-weight: bold; font-size: 20px;">  => Invalid Signature!</span>';

// /********************************************/
// /* Get Public Key -> Modulus and Exponent */
// /********************************************/
// function getJWTPublicKey($dataCenter, $apiKey, $userKey, $currentSecret) {
//   // Step 1 - Defining the request
//   $getJWTPublicKeyMethod = "accounts.getJWTPublicKey";
//   $getJWTPublicKeyRequest = new GSRequest($apiKey,$currentSecret,$getJWTPublicKeyMethod,null,true,$userKey);
//   //Step 2 - Set Data center
//   $getJWTPublicKeyRequest->setAPIDomain($dataCenter);
//   // Step 3 - Sending the request
//   $getJWTPublicKeyResponse = $getJWTPublicKeyRequest->send();
//   // Step 4 - handling the request's response.
//   if($getJWTPublicKeyResponse->getErrorCode()==0) {
//     // Get Modulus and Exponent
//     return array("modulus" => $getJWTPublicKeyResponse->getString("n"), "exponent" => $getJWTPublicKeyResponse->getString("e"));
//   } else {
//     return $getJWTPublicKeyResponse->getErrorMessage();
//   }
// }
?>
