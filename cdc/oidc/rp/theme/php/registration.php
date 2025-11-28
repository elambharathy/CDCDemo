<?php

require_once('GSSDK.php');
require_once('config.php');
//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
global $errorCode;
global $message;
global $log;
?>
<!DOCTYPE html>
<html>
    <head>
        <title>Gigya PHP Rest Demo Site</title>
    </head>
    <?php
      // Retrieve api key from URL
      if (isset($_GET['apiKey'])) $apiKey = $_GET['apiKey'];

      // Build initRegistration request
      $gsr = new GSRequest($apiKey,null,"accounts.initRegistration",null,true,null);
      $gsr->setAPIDomain($dataCenter);

      // Execute Request
      $gsResponse = $gsr->send();

      // Retrieve response attributes
      if($gsResponse->getErrorCode()==0) {
        $errorCode = $gsResponse->getErrorCode();
      } else {
        $errorCode = $gsResponse->getErrorCode();
        $message = $gsResponse->getErrorMessage();
        $log = $gsResponse->getResponseText();
      }
    ?>
    <body>
        <div class="" id="main_wrapper">
        <div class="" id="logoDiv">
        </div>
        <h2>Gigya PHP Rest Demo Site</h2>
        <input id="apiKey" value='<?php echo $apiKey; ?>' />
        <input id="errorCode" value='<?php echo $errorCode; ?>' />
        <input id="errorMessage" value='<?php echo $message; ?>' />
        <input id="log" value='<?php echo $log; ?>' />
      </div>
</body>
</html>
