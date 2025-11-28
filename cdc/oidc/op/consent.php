<?php
//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

include_once('GSSDK.php');
?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Open ID Connect Consent Page</title>
    <!--script type="text/javascript" src="https://cdns.gigya.com/js/gigya.js?apiKey=4_S2nqbib5zmlDXhDef3Yhbw"></script-->
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.9.2/jquery-ui.min.js"></script>
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/hmac-sha1.js"></script>
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/components/enc-base64-min.js"></script>
    <style>
        /* ** --snipped-- ** */
    </style>
</head>
<body>
<div class="" id="logoDiv">
<img src="GigyaLogo_2016-05-04.png" />
</div>
<h2>CDC OIDC Demo OP Consent Page</h2>
<div class="standardDiv" id="errorsDiv">
    <?php
    // this is the partner 
    $secret="111";
    $errors="<br />There may be errors processing your request due to missing or incorrect values: <br /><br />";
    $errorsExist = 'false';
    if (isset($_GET['context']) && $_GET['context'] !== "") {
        $context = $_GET['context'];
    } else {
        $context = 'undefined';
        $errors .='context was undefined.<br />';
    }
    if (isset($_GET['clientID']) && $_GET['clientID'] !== "") {
        $clientID = $_GET['clientID'];
    } else {
        $clientID = 'undefined';
        $errors .='clientID was undefined.<br />';
    }
    if (isset($_GET['scope']) && $_GET['scope'] !== "") {
        $scope = $_GET['scope'];
        $scope = preg_replace('/[+]/', ' ', $scope);
    } else {
        $scope = 'undefined';
        $errors .= 'scope was undefined.<br />';
    }
    if (isset($_GET['prompt']) && $_GET['prompt'] !== "") {
        $prompt = $_GET['prompt'];
    } else {
        $prompt = 'undefined';
        $errors .= 'prompt was undefined.<br />';
    }
    if (isset($_GET['display']) && $_GET['display'] !== "") {
        $display = $_GET['display'];
    } else {
        $display = 'undefined';
        $errors .= 'display was undefined.<br />';
    }
    if (isset($_GET['UID']) && $_GET['UID'] !== "") {
        $UID = $_GET['UID'];
    } else {
        $UID = 'undefined';
        $errors .= 'UID was undefined.<br />';
    }
    if (isset($_GET['UIDSignature']) && $_GET['UIDSignature'] !== "") {
        $UIDSignature = $_GET['UIDSignature'];
    } else {
        $UIDSignature = 'undefined';
        $errors .= 'UIDSignature was undefined.<br />';
    }
    if (isset($_GET['signatureTimestamp']) && $_GET['signatureTimestamp'] !== "") {
        $signatureTimestamp = $_GET['signatureTimestamp'];
    } else {
        $signatureTimestamp = 'undefined';
        $errors .= 'signatureTimestamp was undefined.<br />';
    }
    if ($errors !== "<br />There may be errors processing your request due to missing or incorrect values: <br /><br />") {
        $errors .= "<br /><br />";
        echo $errors;
    }
    if (($scope ==="undefined") || ($clientID === "undefined") || ($context === "undefined") || ($UID === "undefined")) {
        echo "<br /><br /><span style='font-weight: bold; color: red;'>Too many errors occurred; please try again.</span>";
        $errorsExist = 'true';
    } else {

    //construct signature
    $consentObj2 = json_encode(array(
        "scope" => $scope,
        "clientID" => $clientID,
        "context" => $context,
        "UID" => $UID,
        "consent" => true
    ));
    $consentObj2Sig= SigUtils::calcSignature($consentObj2, $secret);
    $consentObj2Sig= preg_replace("/=$/", "", $consentObj2Sig);
    $consentObj2Sig= preg_replace("/=$/", "", $consentObj2Sig);
    $consentObj2Sig= preg_replace("/[+]/", "-", $consentObj2Sig); // -
    $consentObj2Sig= preg_replace("/\//", "_", $consentObj2Sig); // _
    }
    ?>
</div><!-- /errorsDiv -->

<div class="wrapper" id="main_wrapper">
    <!--div class="" id="errorsSwitch">
        <br /><br />There were errors detected. Check this box to view: <input type="checkbox" value='' id="errorsSwitchCheck" /><br /><br />
        <script>
            var rpBackLink=function() {
                window.history.back;
            };
        </script>
        <a href="http://jasonr.gigya-cs.com/oidc">Return to the Main page</a>.
    </div-->
    <script>
        var consentObj2Sig = '<?php echo $consentObj2Sig ?>';
        var b_js_consentOBJString = '<?php echo $consentObj2 ?>';
        console.log('sig: ' + consentObj2Sig);
        console.log('consentObj: ' + b_js_consentOBJString);

    </script>

    <div class="content" id="consent_content">



        By clicking the button below you agree to share your data from the Gigya <a href="https://demo.gigya.com" target="_blank">Demo Site</a> with the Gigya <a href="https://rp-demo-gigya.herokuapp.com" target="_blank">RP Site</a>.
        <!--<br />
        <input type="checkbox" id="consentYes" value="true" />&nbsp;&nbsp;&nbsp;<input type="checkbox" value="false" id="consentNo" /> -->
        <br />
        <br />
        In a production environment you would now give the user a chance to approve/disapprove the requested scopes and/or perform logic to determine if the user has previously consented and skip redundant consent.
        <br />
        <br />
        For the purposes of this demo, you are agreeing to share your email address and basic profile claims as defined in the <a href="http://developers.gigya.com/display/GD/fidm.oidc.op.createRP+REST#fidm.oidc.op.createRPREST-Parameters" target="_blank">allowedScopes</a> parameter.
        <br />
        <br />
        <button class="rpBtn" id="b_js_sigBtn">Grant Consent</button><br /><br />
    </div><!-- /consent_content -->
</div><!-- /main_wrapper -->
<script>
$(document).ready(function () {
    var errorsExist = '<?php echo "errors? ".$errorsExist ?>';
    if (errorsExist === 'true') {
        document.getElementById('errorsSwitch').style.display='block';
        document.getElementById('b_js_sigBtn').disabled=true;
        document.getElementById('b_js_sigBtn').className='rpBtn_disabled';
    }
    //errorsSwitchCheck
    $("#errorsSwitchCheck").click(function(){
        if (document.getElementById('errorsSwitchCheck').checked===true) {
            document.getElementById('errorsDiv').style.display='block';
        } else {
            document.getElementById('errorsDiv').style.display='none';
        }
    });
    $("#b_js_sigBtn").click(function(){
        var b_js_newUrl="proxy.html?mode=afterConsent&consent=" + b_js_consentOBJString + "&sig=" + consentObj2Sig;
        console.log('URL: ' + b_js_newUrl);
        window.location.href=b_js_newUrl;
    });
});
</script>
</body>
</html>
