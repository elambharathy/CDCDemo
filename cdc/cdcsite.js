/*
  SAP CDC CIAM Tester - Refactored JS (Embedded Forms)
*/

// ---------------------------------------------------------------------------
// 1. GLOBAL SETTINGS & STATE
// ---------------------------------------------------------------------------

let cdcSettings = {
    apiKey: '',
    dataCenter: 'us1', // NEW: Explicit Data Center setting, defaulting to 'us1'
    oidcClientId: 'YR03Nf-EABD3TuqbImtU1bPf', 
    oidcRedirectUri: 'https://elamdemo.fwh.is/sap/cdc/oidc/rp/RPIndexPage.html', 
    // Login/Register
    loginScreenSet: 'Default-RegistrationLogin',
    loginStartScreen: 'gigya-login-screen',
    sessionExpiration: 120, // NEW: Configurable session expiration (seconds)
    // Passwordless
    identifierScreenSet: 'Default-IdentifierFirst', // NEW: Identifier-First ScreenSet
    identifierStartScreen: 'gigya-identify-screen', // NEW: Identifier-First Start Screen
    // Registration
    regScreenSet: 'Default-OrganizationRegistration',
    regStartScreen: '',
    // Profile
    profileScreenSet: 'Default-ProfileUpdate',
    profileStartScreen: 'gigya-update-profile-screen' // MODIFIED: Changed to gigya-update-profile-screen
};

let gigyaSDKLoaded = false;
const SETTINGS_KEY = 'cdcTesterSettings';
const FORM_CONTAINER_ID = 'gigya-form-container'; // ID of our form div
let lastGigyaResponse = null; // Store the last response for JWT decoding

// ---------------------------------------------------------------------------
// 2. LOGGING UTILITY - FIX APPLIED HERE
// ---------------------------------------------------------------------------

/**
 * Custom logging function to include local machine timestamp and properly format objects.
 * @param {string} level - 'log' or 'error'.
 * @param {...any} messages - The messages to log.
 */
function log(level, ...messages) {
    const timestamp = new Date().toLocaleTimeString();
    const prefix = `${timestamp}: [${level.toUpperCase()}]`;
    
    // Process messages to handle objects correctly
    const formattedMessages = messages.map(msg => {
        if (typeof msg === 'object' && msg !== null) {
            // Use JSON.stringify for objects for clear console output
            return '\n' + JSON.stringify(msg, null, 2);
        }
        return msg;
    });

    const fullMessage = [prefix, ...formattedMessages].join(' ');

    if (level === 'error') {
        console.error(fullMessage);
    } else {
        // Use console.log's ability to handle multiple arguments if they aren't objects, 
        // but since we're formatting objects into strings, we just join and print.
        console.log(fullMessage);
    }
}

// ---------------------------------------------------------------------------
// 3. GIGYA SDK CALLBACK & EVENT HANDLERS
// ---------------------------------------------------------------------------

var onGigyaServiceReady = function () {
    log('log', 'Gigya Service is Ready.');
    gigyaSDKLoaded = true; 

    // Add global event handlers
    gigya.accounts.addEventHandlers({
        onLogin: onLoginCallback,
        onLogout: onLogoutCallback
    });

    // Check session using session.verify first, as requested.
    const dataCenter = cdcSettings.dataCenter;
    const requestUrl = `https://accounts.${dataCenter}.gigya.com/accounts.session.verify`;

    log('log', `Initial session check using accounts.session.verify... Request URL: ${requestUrl}`);

    gigya.accounts.session.verify({
        callback: function (response) {
            lastGigyaResponse = response; 
            
            if (response.errorCode == 0) {
                // Session is valid
                log('log', 'Valid session found. Getting account info to display data...');
                // Manually call getAccountInfo to fetch and display user data
                getAccountInfoManual(); 
                setLoginState(true);
            } else {
                // Session is not valid (or user not logged in)
                log('log', 'No valid session found or verification failed. Error message:', response.errorMessage);
                setLoginState(false);
            }
        }
    });
};

/**
 * Global onLogin event handler.
 */
function onLoginCallback(evt) {
    // FIX APPLIED: 'evt' object will now be stringified for console output
    log('log', 'onLogin event fired. Event Details:', evt); 
    lastGigyaResponse = evt; // Store response
    setLoginState(true);
    // Note: Since we are using popup, no need to explicitly call closeForm() here, 
    // but we can ensure the embedded container is hidden
    $("#" + FORM_CONTAINER_ID).hide(); 
    // After successful login, fetch the full account data and display it
    getAccountInfoManual();
}

/**
 * Global onLogout event handler.
 */
function onLogoutCallback(evt) {
    log('log', 'onLogout event fired. Event Details:', evt);
    lastGigyaResponse = evt; // Store response
    setLoginState(false);
    closeForm(); // Hide embedded form/show welcome
    displayResponse(evt);
}

// ---------------------------------------------------------------------------
// 4. PAGE LOAD & SDK INITIALIZATION
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", function() {
    loadSettings(); 

    if (cdcSettings.apiKey) {
        log('log', 'API key found. Loading Gigya SDK...');
        loadGigyaSDK(cdcSettings.apiKey);
    } else {
        log('log', 'No API key found. Opening settings modal.');
        openSettings();
    }

    // Set initial state
    setLoginState(false); // Assume logged out until session.verify confirms
    closeForm(); // Show welcome message by default
});

function loadGigyaSDK(apiKey) {
    if (document.querySelector('script[src*="gigya.js"]')) {
        return;
    }
    
    // --- USING EXPLICIT DATA CENTER SETTING ---
    const dataCenter = cdcSettings.dataCenter;
    
    // Set the global Data Center variable for Gigya API calls
    window.gigyaCmsFunctions = { dataCenter: dataCenter };
    
    const scriptSrc = `https://cdns.${dataCenter}.gigya.com/js/gigya.js?apikey=${apiKey}`;
    
    const script = document.createElement('script');
    script.type = 'text/javascript';
    script.lang = 'javascript';
    script.src = scriptSrc;
    
    log('log', `[SDK Loader] Using configured Data Center: ${dataCenter}`);
    log('log', `[SDK Loader] Attempting to load SDK from: ${scriptSrc}`); // Log the exact URL being used

    script.onerror = function() {
        log('error', '--- GIGYA SDK LOAD FAILED ---');
        log('error', `Attempted URL: ${scriptSrc}`);
        log('error', 'Possible Causes: 1. Incorrect API Key. 2. Incorrect Data Center (DC) configured. 3. The local URL is NOT a Trusted Site URL in your CDC console.');
    };
    document.body.appendChild(script);
}

// ---------------------------------------------------------------------------
// 5. SETTINGS MODAL FUNCTIONS
// ---------------------------------------------------------------------------

function openSettings() {
    document.getElementById('settingApiKey').value = cdcSettings.apiKey;
    document.getElementById('settingDataCenter').value = cdcSettings.dataCenter; 
    document.getElementById('settingOidcClientId').value = cdcSettings.oidcClientId;
    document.getElementById('settingOidcRedirectUri').value = cdcSettings.oidcRedirectUri;
    
    document.getElementById('settingLoginScreenSet').value = cdcSettings.loginScreenSet;
    document.getElementById('settingLoginStartScreen').value = cdcSettings.loginStartScreen;
    document.getElementById('settingSessionExpiration').value = cdcSettings.sessionExpiration;
    
    document.getElementById('settingIdentifierScreenSet').value = cdcSettings.identifierScreenSet;
    document.getElementById('settingIdentifierStartScreen').value = cdcSettings.identifierStartScreen;
    
    document.getElementById('settingRegScreenSet').value = cdcSettings.regScreenSet;
    document.getElementById('settingRegStartScreen').value = cdcSettings.regStartScreen;
    document.getElementById('settingProfileScreenSet').value = cdcSettings.profileScreenSet;
    document.getElementById('settingProfileStartScreen').value = cdcSettings.profileStartScreen;
    
    document.getElementById('settingsModal').style.display = 'block';
}

function closeSettings() {
    document.getElementById('settingsModal').style.display = 'none';
}

function saveSettings() {
    cdcSettings.apiKey = document.getElementById('settingApiKey').value.trim();
    cdcSettings.dataCenter = document.getElementById('settingDataCenter').value.trim().toLowerCase(); 
    cdcSettings.oidcClientId = document.getElementById('settingOidcClientId').value.trim();
    cdcSettings.oidcRedirectUri = document.getElementById('settingOidcRedirectUri').value.trim();
    
    cdcSettings.loginScreenSet = document.getElementById('settingLoginScreenSet').value.trim();
    cdcSettings.loginStartScreen = document.getElementById('settingLoginStartScreen').value.trim();
    // NEW: Session Expiration
    const expValue = document.getElementById('settingSessionExpiration').value.trim();
    cdcSettings.sessionExpiration = parseInt(expValue) > 0 ? parseInt(expValue) : 120; 

    cdcSettings.identifierScreenSet = document.getElementById('settingIdentifierScreenSet').value.trim();
    cdcSettings.identifierStartScreen = document.getElementById('settingIdentifierStartScreen').value.trim();
    
    cdcSettings.regScreenSet = document.getElementById('settingRegScreenSet').value.trim();
    cdcSettings.regStartScreen = document.getElementById('settingRegStartScreen').value.trim();
    cdcSettings.profileScreenSet = document.getElementById('settingProfileScreenSet').value.trim();
    cdcSettings.profileStartScreen = document.getElementById('settingProfileStartScreen').value.trim();

    localStorage.setItem(SETTINGS_KEY, JSON.stringify(cdcSettings));
    closeSettings();
    alert('Settings saved! Reloading page...');
    window.location.reload();
}

function resetSettings() {
    // Clear localStorage and reload, forcing default settings to load
    localStorage.removeItem(SETTINGS_KEY);
    alert('Settings reset to defaults! Reloading page...');
    window.location.reload();
}

function loadSettings() {
    const savedSettings = localStorage.getItem(SETTINGS_KEY);
    if (savedSettings) {
        log('log', 'Loaded settings from localStorage');
        // Ensure new settings fields exist if loaded from old config
        const parsedSettings = JSON.parse(savedSettings);
        Object.assign(cdcSettings, parsedSettings);
    }
}

// ---------------------------------------------------------------------------
// 6. UI & FORM HELPER FUNCTIONS
// ---------------------------------------------------------------------------

/**
 * A helper function to prevent calling 'gigya' before it's loaded.
 */
function checkGigyaLoaded() {
    if (typeof gigya === 'undefined' || !gigyaSDKLoaded) {
        alert('Gigya SDK is not loaded. Please configure your API Key in Settings.');
        openSettings();
        return false;
    }
    return true;
}

/**
 * Toggles the UI between "Logged In" and "Logged Out" states.
 * @param {boolean} isLoggedIn - True if the user is logged in.
 */
function setLoginState(isLoggedIn) {
    if (isLoggedIn) {
        $(".loggedin").show();
        $(".notloggedin").hide();
    } else {
        $(".loggedin").hide();
        $(".notloggedin").show();
    }
}

/**
 * Displays a JSON response in the text area.
 * @param {object} response - The Gigya response object.
 */
function displayResponse(response) {
    const prettyJson = JSON.stringify(response, null, 4);
    document.getElementById('apiResponse').value = prettyJson;
}

/**
 * Shows the screenset in a popup.
 * @param {object} params - The parameters for showScreenSet.
 */
function showForm(params) {
    if (!checkGigyaLoaded()) return;
    
    // MODIFIED: Use display: 'popup'
    const screenSetParams = {
        ...params,
        display: 'popup' 
    };

    // Keep the embedded form container hidden since we're using popup
    $("#" + FORM_CONTAINER_ID).hide();
    $("#welcome-section").show();

    log('log', 'Calling showScreenSet with params:', screenSetParams);
    gigya.accounts.showScreenSet(screenSetParams);
}

/**
 * Hides the form container and shows the welcome message.
 * NOTE: Primarily for clearing the embedded view if it was used, or on logout.
 */
function closeForm() {
    $("#" + FORM_CONTAINER_ID).hide().empty(); // Hide and clear the container
    $("#welcome-section").show();
}

// ---------------------------------------------------------------------------
// 7. ACTION FUNCTIONS (Bound to buttons)
// ---------------------------------------------------------------------------

function showLogin() {
    showForm({
        screenSet: cdcSettings.loginScreenSet,
        startScreen: cdcSettings.loginStartScreen || 'gigya-login-screen',
        sessionExpiration: cdcSettings.sessionExpiration
    });
};

function showIdentifierFirst() {
    showForm({
        screenSet: cdcSettings.identifierScreenSet,
        startScreen: cdcSettings.identifierStartScreen || 'gigya-identify-screen',
        sessionExpiration: cdcSettings.sessionExpiration
    });
}

function Orgregistration() {
    showForm({
        screenSet: cdcSettings.regScreenSet,
        startScreen: cdcSettings.regStartScreen || undefined // Use default if empty
    });
};

function profileupdate() {
    showForm({
        screenSet: cdcSettings.profileScreenSet,
        startScreen: cdcSettings.profileStartScreen || 'gigya-update-profile-screen'
    });
};

function SetOrganizationContext() {
    showForm({
		screenSet: cdcSettings.regScreenSet, // Assuming it's in this screenset
        startScreen: 'gigya-change-organization-context-screen'
    });
};

function logout() {
    if (!checkGigyaLoaded()) return;
    gigya.accounts.logout(); // This will trigger the global onLogoutCallback
};

// --- Manual API Calls (New) ---

/**
 * Calls accounts.getAccountInfo and prints response and request URL.
 */
function getAccountInfoManual() {
    if (!checkGigyaLoaded()) return;
    
    const dataCenter = cdcSettings.dataCenter;
    const requestUrl = `https://accounts.${dataCenter}.gigya.com/accounts.getAccountInfo`;
    
    displayResponse({
        message: "Calling accounts.getAccountInfo...", 
        RequestURL: requestUrl // API Key and query params are stripped for clarity
    });

    gigya.accounts.getAccountInfo({
        include: 'profile,data,groups',
        callback: function(response) {
            lastGigyaResponse = response;
            
            const fullResponse = {
                message: "Response from accounts.getAccountInfo",
                RequestURL: requestUrl,
                ...response
            }
            displayResponse(fullResponse);
            // FIX APPLIED: 'response' object will now be stringified for console output
            log('log', 'getAccountInfoManual response:', response); 
        }
    });
}

/**
 * Calls accounts.session.verify and prints response and request URL.
 */
function verifySessionManual() {
    if (!checkGigyaLoaded()) return;
    
    const dataCenter = cdcSettings.dataCenter;
    const requestUrl = `https://accounts.${dataCenter}.gigya.com/accounts.session.verify`;
    
    displayResponse({
        message: "Calling accounts.session.verify...", 
        RequestURL: requestUrl // API Key and query params are stripped for clarity
    });

    gigya.accounts.session.verify({
        callback: function(response) {
            lastGigyaResponse = response;
            
            const fullResponse = {
                message: "Response from accounts.session.verify",
                RequestURL: requestUrl,
                ...response
            }
            displayResponse(fullResponse);
            // FIX APPLIED: 'response' object will now be stringified for console output
            log('log', 'verifySessionManual response:', response);
        }
    });
}

// --- JWT and Decoding Functions ---

/**
 * Calls Gigya to get a new JWT token and displays the full response.
 */
function getJWT() {
    if (!checkGigyaLoaded()) return;
    gigya.accounts.getJWT({
        fields: "UID,firstName,lastName,email", // Requesting UID explicitly
        callback: function(response) {
            lastGigyaResponse = response; // Store for decoding
            displayResponse(response);
            if (response.id_token) {
                log('log', "JWT received. Click 'Decode JWT Payload' to see claims.");
            }
        },
        expiration: 3600 // 1 hour token validity for backend exchange
    });
}

/**
 * Helper function to decode URL-safe Base64 strings (JWT standard).
 * @param {string} str - The Base64 string from the JWT payload.
 */
function urlBase64Decode(str) {
    let output = str.replace(/-/g, '+').replace(/_/g, '/');
    switch (output.length % 4) {
        case 0: break;
        case 2: output += '=='; break;
        case 3: output += '='; break;
        default:
            throw new Error('Illegal base64url string!');
    }
    // Use window.atob and decodeURIComponent to handle special characters correctly
    return decodeURIComponent(window.atob(output).split('').map(function(c) {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
}

/**
 * Decodes the JWT payload from the last received response (if it contained a token).
 * NOTE: This is for TESTING/DISPLAY only. It does NOT validate the token's signature.
 */
function decodeAndDisplayJWT() {
    if (!lastGigyaResponse || !lastGigyaResponse.id_token) {
        alert("No JWT found. Please click '1. Get JWT' first.");
        return;
    }

    const jwt = lastGigyaResponse.id_token;
    const parts = jwt.split('.');

    if (parts.length !== 3) {
        alert("Invalid JWT format (expected 3 parts).");
        return;
    }

    try {
        const header = JSON.parse(urlBase64Decode(parts[0]));
        const payload = JSON.parse(urlBase64Decode(parts[1]));
        
        const decodedClaims = {
            message: "--- DECODED JWT PAYLOAD (FOR TESTING ONLY - SIGNATURE NOT VALIDATED) ---",
            TokenExpiration: new Date(payload.exp * 1000).toLocaleString(),
            UID: payload.UID, // The unique identifier you need
            ...payload
        };

        document.getElementById('apiResponse').value = JSON.stringify(decodedClaims, null, 4);
        log('log', 'JWT Payload Decoded:', decodedClaims);

    } catch (e) {
        log('error', "JWT Decoding Error:", e);
        alert("Failed to decode JWT payload. See console for error.");
    }
}

// --- Authorization Code Flow Initiation ---

function startOidcFlow() {
    if (!cdcSettings.apiKey || !cdcSettings.oidcClientId || !cdcSettings.oidcRedirectUri) {
        alert('Please configure API Key, OIDC Client ID, and Redirect URI in Settings first.');
        openSettings();
        return;
    }

    // 1. Extract necessary configuration variables
    const apiKey = cdcSettings.apiKey;
    const clientId = cdcSettings.oidcClientId;
    const redirectUri = encodeURIComponent(cdcSettings.oidcRedirectUri);
    
    // --- USING EXPLICIT DATA CENTER SETTING ---
    const dataCenter = cdcSettings.dataCenter;

    const baseUrl = `https://fidm.${dataCenter}.gigya.com/oidc/op/v1.0/${apiKey}/authorize`;

    // 2. Build the Authorization URL
    // Scope 'offline_access' is REQUIRED to obtain the Refresh Token.
    const authUrl = `${baseUrl}?` +
        `response_type=code&` +
        `client_id=${clientId}&` +
        `scope=openid%20profile%20email%20phone%20uid%20username%20locale%20offline_access&` +
        `redirect_uri=${redirectUri}&` +
        `state=${Math.random().toString(36).substring(2, 15)}`; // Simple CSRF state for test

    // 3. Redirect the browser to start the flow
    log('log', "Redirecting to CDC Authorization Endpoint:", authUrl);
    window.open(authUrl, "_blank");
}


// --- Other functions (B2B, SAML, etc.) ---

function openDelegatedAdmin() {
    if (!checkGigyaLoaded()) return;
    gigya.accounts.getAccountInfo({
        include: 'groups,profile',
        callback: function (event) {
            lastGigyaResponse = event; // Store response
            if (event.errorCode !== 0 || !event.groups || !event.groups.organizations) {
                alert('Could not get organization ID. Are you logged in as a B2B user?');
                return;
            }
            var params = {
                "orgId": event.groups.organizations[0].orgId
            }
            gigya.accounts.b2b.openDelegatedAdminLogin(params);
        }
    });
};

function showAuthorization() {
    if (!checkGigyaLoaded()) return;
    gigya.accounts.getAccountInfo({
        include: 'groups,profile',
        callback: function (event) {
            lastGigyaResponse = event; // Store response
            if (event.errorCode !== 0 || !event.groups || !event.groups.organizations) {
                alert('Could not get organization ID. Are you logged in as a B2B user?');
                return;
            }
            var params = {
                "orgId": event.groups.organizations[0].orgId,
                "appId": "PLGPF8LX8J2ZB0OUV8WE", // TODO: Parameterize this in settings?
                "callback": displayResponse
            }
            gigya.accounts.b2b.auth.getAssets(params); 
        }
    });
}

function showKASAuthorization() {
    if (!checkGigyaLoaded()) return;
    gigya.accounts.getAccountInfo({
        include: 'groups,profile',
        callback: function (event) {
            lastGigyaResponse = event; // Store response
            if (event.errorCode !== 0 || !event.groups || !event.groups.organizations) {
                alert('Could not get organization ID. Are you logged in as a B2B user?');
                return;
            }
            var params = {
                "orgId": event.groups.organizations[0].orgId, 
                "appId": "PX6FZX7ZCKWRUWOGIONH", // TODO: Parameterize this in settings?
                "callback": displayResponse
            }
            gigya.accounts.b2b.auth.getAssets(params);
        }
    });
}

function openKAS() {
    if (!checkGigyaLoaded()) return;
    gigya.fidm.saml.initSSO({ 
        'spName': 'saml-kas_stage1', // TODO: Parameterize this in settings?
        'redirectURL': 'https://Defaulteu--uat.sandbox.my.salesforce.com' 
    });
};