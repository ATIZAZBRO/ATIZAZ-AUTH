const crypto = require('crypto');
const child_process = require('child_process');

class AtizazAuthAPI {
    constructor(apiUrl, secretKey, appName, version) {
        this.apiUrl = apiUrl.replace(/\/$/, "");
        this.secretKey = secretKey;
        this.appName = appName;
        this.version = version;
        this.sessionId = "";
        this.initialized = false;
        
        this.publicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnysSGsuoFA3YCx+FLvL1
jdAz4SN9nu2zIBp0yVjQgIazsymmFhDW6WEu16TzFVnNqcT2R5F8TR+5xnQFxgoG
WbuS1uSKhF0a0mXAQqhPijcw+qY+j3kxPbpu0YQrEeb0FIM5Oa0UjuhBXEA4aXNZ
tBAfKKxDxLAhY73DY1wPf4W3OgK2rRE6aZ/V7elAAlqjRMGvuPWVuTZVDf7GOSA7
mIiNdYvf0TdShpWJ4wF12xugHl4ezDHR+vOjOTVHScvFL5bRD0nEhH5fzCoDLlp9
Psz2/vAtCgLHyFj0WgUjsGbHC/6NhSBvPQYIHIV/z5m57JyuSI4S0kiIPcd4X8HR
XwIDAQAB
-----END PUBLIC KEY-----`;
    }

    getHWID() {
        try {
            if (process.platform === 'win32') {
                const output = child_process.execSync('wmic csproduct get uuid', { encoding: 'utf8' });
                const lines = output.split('\n').map(l => l.trim()).filter(l => l.length > 0);
                if (lines.length > 1) {
                    return lines[1];
                }
            } else if (process.platform === 'darwin') {
                const output = child_process.execSync('ioreg -rd1 -c IOPlatformExpertDevice', { encoding: 'utf8' });
                const match = output.match(/IOPlatformUUID"\s*=\s*"([^"]+)"/);
                if (match) return match[1];
            } else {
                return child_process.execSync('cat /etc/machine-id', { encoding: 'utf8' }).trim();
            }
        } catch (e) {
            return "UNKNOWN";
        }
        return "UNKNOWN";
    }

    sha256Hex(value) {
        return crypto.createHash('sha256').update(value, 'utf8').digest('hex').toUpperCase();
    }

    generateNonce() {
        return crypto.randomUUID().replace(/-/g, '');
    }

    getCurrentTimestamp() {
        return Math.floor(Date.now() / 1000).toString();
    }

    verifySignature(endpoint, signatureBase64, serverTimestamp, responseObj, requestNonce) {
        try {
            const currentTs = Math.floor(Date.now() / 1000);
            const srvTs = parseInt(serverTimestamp, 10);
            if (Math.abs(currentTs - srvTs) > 120) return false;

            const successStr = responseObj.success ? "1" : "0";
            let variableLines = "";

            if (responseObj.variables && typeof responseObj.variables === 'object') {
                const keys = Object.keys(responseObj.variables).sort();
                for (const k of keys) {
                    let val = responseObj.variables[k];
                    if (typeof val !== 'string') val = JSON.stringify(val);
                    variableLines += `${k}=${val}\n`;
                }
            }

            const payload = `endpoint=${this.sha256Hex(endpoint)}
requestNonce=${this.sha256Hex(requestNonce)}
serverTimestamp=${this.sha256Hex(serverTimestamp)}
success=${successStr}
message=${this.sha256Hex(responseObj.message || "")}
username=${this.sha256Hex(responseObj.username || "")}
subscription=${this.sha256Hex(responseObj.subscription || "")}
expiry=${this.sha256Hex(responseObj.expiry || "")}
serverVersion=${this.sha256Hex(responseObj.serverVersion || "")}
value=${this.sha256Hex(responseObj.value || "")}
variables=${this.sha256Hex(variableLines ? variableLines + "\n" : "")}
`;

            const verifier = crypto.createVerify('sha256');
            verifier.update(payload, 'utf8');
            return verifier.verify(this.publicKeyPem, signatureBase64, 'base64');
        } catch (e) {
            console.error("Verification error", e);
            return false;
        }
    }

    async req(endpoint, payloadDict, secure = true) {
        const requestNonce = this.generateNonce();
        const clientTimestamp = this.getCurrentTimestamp();

        if (secure) {
            payloadDict.clientNonce = requestNonce;
            payloadDict.clientTimestamp = clientTimestamp;
        }
        if (this.sessionId) {
            payloadDict.sessionid = this.sessionId;
        }

        try {
            const res = await fetch(`${this.apiUrl}/${endpoint}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(payloadDict)
            });

            const rsaSignature = res.headers.get('x-signature-rsa');
            const srvTimestamp = res.headers.get('x-signature-timestamp');
            
            const responseData = await res.text();
            let responseObj;
            try {
                responseObj = JSON.parse(responseData);
            } catch (e) {
                return { success: false, message: "Invalid JSON from server" };
            }

            if (secure) {
                if (!rsaSignature || !srvTimestamp || !this.verifySignature(endpoint, rsaSignature, srvTimestamp, responseObj, requestNonce)) {
                    console.error("SECURITY ERROR: Response signature validation failed!");
                    return { success: false, message: "Security Check Failed" };
                }
            }
            return responseObj;
        } catch (e) {
            return { success: false, message: "Network error: " + e.message };
        }
    }

    async init() {
        if (this.initialized) return;

        const payload = {
            secret: this.secretKey,
            appName: this.appName,
            appVersion: this.version,
            hash: "NOT_FOUND" // Skip exe hash for JS scripts
        };

        const response = await this.req("init", payload, false);
        if (response && response.success) {
            this.sessionId = response.sessionid;
            this.initialized = true;
        } else {
            console.error("Initialization Failed:", response ? response.message : "Unknown error");
            process.exit(1);
        }
    }

    async login(username, password, hwid = "") {
        if (!this.initialized) { console.error("Must call init() first!"); process.exit(1); }
        const payload = {
            secret: this.secretKey,
            appName: this.appName,
            appVersion: this.version,
            username,
            password,
            hwid: hwid || this.getHWID()
        };
        return await this.req("login", payload);
    }

    async register(username, password, licenseKey, hwid = "") {
        if (!this.initialized) { console.error("Must call init() first!"); process.exit(1); }
        const payload = {
            secret: this.secretKey,
            appName: this.appName,
            appVersion: this.version,
            username,
            password,
            licenseKey,
            hwid: hwid || this.getHWID()
        };
        return await this.req("register", payload);
    }

    async license(licenseKey, hwid = "") {
        if (!this.initialized) { console.error("Must call init() first!"); process.exit(1); }
        const payload = {
            secret: this.secretKey,
            appName: this.appName,
            appVersion: this.version,
            licenseKey,
            hwid: hwid || this.getHWID()
        };
        return await this.req("license", payload);
    }
}

module.exports = AtizazAuthAPI;
