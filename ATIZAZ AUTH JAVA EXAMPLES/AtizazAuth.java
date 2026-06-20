package com.example.atizazauth;

import android.content.Context;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;

public class AtizazAuthAPI {
    private static final String TAG = "AtizazAuth";
    
    private String apiUrl;
    private String secretKey;
    private String appName;
    private String version;
    private String sessionId = "";
    private boolean initialized = false;
    private Context context;

    private static final String PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnysSGsuoFA3YCx+FLvL1\n" +
            "jdAz4SN9nu2zIBp0yVjQgIazsymmFhDW6WEu16TzFVnNqcT2R5F8TR+5xnQFxgoG\n" +
            "WbuS1uSKhF0a0mXAQqhPijcw+qY+j3kxPbpu0YQrEeb0FIM5Oa0UjuhBXEA4aXNZ\n" +
            "tBAfKKxDxLAhY73DY1wPf4W3OgK2rRE6aZ/V7elAAlqjRMGvuPWVuTZVDf7GOSA7\n" +
            "mIiNdYvf0TdShpWJ4wF12xugHl4ezDHR+vOjOTVHScvFL5bRD0nEhH5fzCoDLlp9\n" +
            "Psz2/vAtCgLHyFj0WgUjsGbHC/6NhSBvPQYIHIV/z5m57JyuSI4S0kiIPcd4X8HR\n" +
            "XwIDAQAB\n" +
            "-----END PUBLIC KEY-----";

    public AtizazAuthAPI(Context context, String apiUrl, String secretKey, String appName, String version) {
        this.context = context;
        this.apiUrl = apiUrl;
        if (this.apiUrl.endsWith("/")) {
            this.apiUrl = this.apiUrl.substring(0, this.apiUrl.length() - 1);
        }
        this.secretKey = secretKey;
        this.appName = appName;
        this.version = version;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getHWID() {
        return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
    }

    private String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().toUpperCase();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    private String generateNonce() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    private String getCurrentTimestamp() {
        return String.valueOf(System.currentTimeMillis() / 1000);
    }

    private boolean verifySignature(String endpoint, String signatureBase64, String serverTimestamp, JSONObject responseObj, String requestNonce) {
        try {
            long currentTs = System.currentTimeMillis() / 1000;
            long srvTs = Long.parseLong(serverTimestamp);
            if (Math.abs(currentTs - srvTs) > 120) {
                Log.e(TAG, "Timestamp expired");
                return false;
            }

            String successStr = responseObj.optBoolean("success", false) ? "1" : "0";
            StringBuilder variableLines = new StringBuilder();

            if (responseObj.has("variables")) {
                JSONObject vars = responseObj.getJSONObject("variables");
                List<String> keys = new ArrayList<>();
                Iterator<String> it = vars.keys();
                while (it.hasNext()) {
                    keys.add(it.next());
                }
                Collections.sort(keys);
                for (String k : keys) {
                    variableLines.append(k).append("=").append(vars.getString(k)).append("\n");
                }
            }

            String payload = "endpoint=" + sha256Hex(endpoint) + "\n" +
                    "requestNonce=" + sha256Hex(requestNonce) + "\n" +
                    "serverTimestamp=" + sha256Hex(serverTimestamp) + "\n" +
                    "success=" + successStr + "\n" +
                    "message=" + sha256Hex(responseObj.optString("message", "")) + "\n" +
                    "username=" + sha256Hex(responseObj.optString("username", "")) + "\n" +
                    "subscription=" + sha256Hex(responseObj.optString("subscription", "")) + "\n" +
                    "expiry=" + sha256Hex(responseObj.optString("expiry", "")) + "\n" +
                    "serverVersion=" + sha256Hex(responseObj.optString("serverVersion", "")) + "\n" +
                    "value=" + sha256Hex(responseObj.optString("value", "")) + "\n" +
                    "variables=" + sha256Hex(variableLines.length() == 0 ? "" : variableLines.toString() + "\n") + "\n";

            String pubKeyPEM = PUBLIC_KEY_PEM
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] keyBytes = Base64.decode(pubKeyPEM, Base64.DEFAULT);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKey = kf.generatePublic(spec);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(payload.getBytes("UTF-8"));

            byte[] sigBytes = Base64.decode(signatureBase64, Base64.DEFAULT);
            return signature.verify(sigBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private JSONObject req(String endpoint, JSONObject payloadDict, boolean secure) {
        try {
            String requestNonce = generateNonce();
            String clientTimestamp = getCurrentTimestamp();

            if (secure) {
                payloadDict.put("clientNonce", requestNonce);
                payloadDict.put("clientTimestamp", clientTimestamp);
            }
            if (!sessionId.isEmpty()) {
                payloadDict.put("sessionid", sessionId);
            }

            String payloadStr = payloadDict.toString();

            URL url = new URL(apiUrl + "/" + endpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);

            OutputStream os = conn.getOutputStream();
            os.write(payloadStr.getBytes("UTF-8"));
            os.flush();
            os.close();

            int responseCode = conn.getResponseCode();
            
            String rsaSignature = conn.getHeaderField("x-signature-rsa");
            String srvTimestamp = conn.getHeaderField("x-signature-timestamp");

            BufferedReader br = new BufferedReader(new InputStreamReader(
                    (responseCode >= 200 && responseCode < 300) ? conn.getInputStream() : conn.getErrorStream(), "UTF-8"));
            
            StringBuilder responseData = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                responseData.append(line);
            }
            br.close();
            conn.disconnect();

            JSONObject responseObj = new JSONObject(responseData.toString());

            if (secure && responseObj.length() > 0) {
                if (rsaSignature == null || srvTimestamp == null || !verifySignature(endpoint, rsaSignature, srvTimestamp, responseObj, requestNonce)) {
                    Log.e(TAG, "SECURITY ERROR: Response signature validation failed!");
                    JSONObject err = new JSONObject();
                    err.put("success", false);
                    err.put("message", "Security Check Failed");
                    return err;
                }
            }

            return responseObj;

        } catch (Exception e) {
            e.printStackTrace();
            try {
                JSONObject err = new JSONObject();
                err.put("success", false);
                err.put("message", "Network Error: " + e.getMessage());
                return err;
            } catch (Exception ex) { return null; }
        }
    }

    public void init() {
        if (initialized) return;

        try {
            JSONObject payload = new JSONObject();
            payload.put("secret", secretKey);
            payload.put("appName", appName);
            payload.put("appVersion", version);
            payload.put("hash", "NOT_FOUND"); // Android apks don't have a simple exe hash, usually people skip this or hash the APK cert.

            JSONObject response = req("init", payload, false);
            if (response != null && response.optBoolean("success", false)) {
                sessionId = response.optString("sessionid", "");
                initialized = true;
                Log.i(TAG, "AtizazAuth Initialized!");
            } else {
                Log.e(TAG, "Initialization Failed: " + (response != null ? response.optString("message") : "Unknown Error"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public JSONObject login(String username, String password) {
        return login(username, password, "");
    }

    public JSONObject login(String username, String password, String hwid) {
        if (!initialized) {
            Log.e(TAG, "Must call init() first!");
            return null;
        }
        try {
            JSONObject payload = new JSONObject();
            payload.put("secret", secretKey);
            payload.put("appName", appName);
            payload.put("appVersion", version);
            payload.put("username", username);
            payload.put("password", password);
            payload.put("hwid", hwid.isEmpty() ? getHWID() : hwid);
            return req("login", payload, true);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public JSONObject register(String username, String password, String licenseKey) {
        return register(username, password, licenseKey, "");
    }

    public JSONObject register(String username, String password, String licenseKey, String hwid) {
        if (!initialized) {
            Log.e(TAG, "Must call init() first!");
            return null;
        }
        try {
            JSONObject payload = new JSONObject();
            payload.put("secret", secretKey);
            payload.put("appName", appName);
            payload.put("appVersion", version);
            payload.put("username", username);
            payload.put("password", password);
            payload.put("licenseKey", licenseKey);
            payload.put("hwid", hwid.isEmpty() ? getHWID() : hwid);
            return req("register", payload, true);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public JSONObject license(String licenseKey) {
        return license(licenseKey, "");
    }

    public JSONObject license(String licenseKey, String hwid) {
        if (!initialized) {
            Log.e(TAG, "Must call init() first!");
            return null;
        }
        try {
            JSONObject payload = new JSONObject();
            payload.put("secret", secretKey);
            payload.put("appName", appName);
            payload.put("appVersion", version);
            payload.put("licenseKey", licenseKey);
            payload.put("hwid", hwid.isEmpty() ? getHWID() : hwid);
            return req("license", payload, true);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
