<?php

require_once 'AtizazAuth.php';

echo str_repeat("=", 40) . "\n";
echo "  Welcome to Atizaz Auth PHP Example  \n";
echo str_repeat("=", 40) . "\n";
echo "\n[+] Initializing with server...\n";

$api = new AtizazAuthAPI(
    "https://cmatizaz-cfire.atizazfayaz78.workers.dev",
    "ENTER SECRET",
    "ENTER NAME",
    "1.0"
);

$api->init();

echo "[+] Initialization Success! Session ID: {$api->sessionId}\n";
echo "[+] Hardware ID: {$api->getHWID()}\n";

while (true) {
    echo "\n------------------------------\n";
    echo "1. Login (Username/Password)\n";
    echo "2. Register\n";
    echo "3. License Only Login\n";
    echo "4. Exit\n";
    echo "------------------------------\n";
    
    $choice = readline("Enter your choice: ");

    if ($choice === "1") {
        $username = readline("Username: ");
        $password = readline("Password: ");
        
        $resp = $api->login($username, $password);
        if (isset($resp['success']) && $resp['success']) {
            echo "\n[SUCCESS] Login Authenticated!\n";
            echo " > User: {$resp['username']}\n";
            echo " > Subscription: {$resp['subscription']}\n";
            echo " > Expiry: {$resp['expiry']}\n";
        } else {
            $msg = $resp['message'] ?? "Unknown error";
            echo "\n[ERROR] Login Failed: {$msg}\n";
        }
    } 
    elseif ($choice === "2") {
        $username = readline("Username: ");
        $password = readline("Password: ");
        $licenseKey = readline("License Key: ");

        $resp = $api->register($username, $password, $licenseKey);
        if (isset($resp['success']) && $resp['success']) {
            echo "\n[SUCCESS] Account Registered! You can now login.\n";
        } else {
            $msg = $resp['message'] ?? "Unknown error";
            echo "\n[ERROR] Registration Failed: {$msg}\n";
        }
    } 
    elseif ($choice === "3") {
        $licenseKey = readline("License Key: ");

        $resp = $api->license($licenseKey);
        if (isset($resp['success']) && $resp['success']) {
            echo "\n[SUCCESS] License Authenticated!\n";
            echo " > Subscription: {$resp['subscription']}\n";
            echo " > Expiry: {$resp['expiry']}\n";
        } else {
            $msg = $resp['message'] ?? "Unknown error";
            echo "\n[ERROR] Login Failed: {$msg}\n";
        }
    } 
    elseif ($choice === "4") {
        echo "Exiting...\n";
        break;
    } 
    else {
        echo "Invalid choice, please select 1-4.\n";
    }
}
?>
