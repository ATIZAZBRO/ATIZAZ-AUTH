const readline = require('readline');
const AtizazAuthAPI = require('./AtizazAuth');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function askQuestion(query) {
    return new Promise(resolve => rl.question(query, resolve));
}

async function main() {
    console.log("=".repeat(40));
    console.log("  Welcome to Atizaz Auth JS Example  ");
    console.log("=".repeat(40));
    console.log("\n[+] Initializing with server...");

    const api = new AtizazAuthAPI(
        "https://cmatizaz-cfire.atizazfayaz78.workers.dev",
        "ENTER SECRET",
        "ENTER NAME",
        "1.0"
    );

    await api.init();
    
    console.log(`[+] Initialization Success! Session ID: ${api.sessionId}`);
    console.log(`[+] Hardware ID: ${api.getHWID()}`);

    while (true) {
        console.log("\n------------------------------");
        console.log("1. Login (Username/Password)");
        console.log("2. Register");
        console.log("3. License Only Login");
        console.log("4. Exit");
        console.log("------------------------------");
        
        const choice = await askQuestion("Enter your choice: ");

        if (choice === "1") {
            const username = await askQuestion("Username: ");
            const password = await askQuestion("Password: ");
            
            const resp = await api.login(username, password);
            if (resp.success) {
                console.log("\n[SUCCESS] Login Authenticated!");
                console.log(` > User: ${resp.username}`);
                console.log(` > Subscription: ${resp.subscription}`);
                console.log(` > Expiry: ${resp.expiry}`);
            } else {
                console.log(`\n[ERROR] Login Failed: ${resp.message}`);
            }
        } 
        else if (choice === "2") {
            const username = await askQuestion("Username: ");
            const password = await askQuestion("Password: ");
            const licenseKey = await askQuestion("License Key: ");

            const resp = await api.register(username, password, licenseKey);
            if (resp.success) {
                console.log("\n[SUCCESS] Account Registered! You can now login.");
            } else {
                console.log(`\n[ERROR] Registration Failed: ${resp.message}`);
            }
        } 
        else if (choice === "3") {
            const licenseKey = await askQuestion("License Key: ");

            const resp = await api.license(licenseKey);
            if (resp.success) {
                console.log("\n[SUCCESS] License Authenticated!");
                console.log(` > Subscription: ${resp.subscription}`);
                console.log(` > Expiry: ${resp.expiry}`);
            } else {
                console.log(`\n[ERROR] Login Failed: ${resp.message}`);
            }
        } 
        else if (choice === "4") {
            console.log("Exiting...");
            break;
        } 
        else {
            console.log("Invalid choice, please select 1-4.");
        }
    }
    rl.close();
}

main();
