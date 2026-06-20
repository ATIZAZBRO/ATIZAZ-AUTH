<?php

class AtizazAuthAPI {
    private $apiUrl;
    private $secretKey;
    private $appName;
    private $version;
    public $sessionId = "";
    private $initialized = false;
    
    private $publicKeyPem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnysSGsuoFA3YCx+FLvL1\njdAz4SN9nu2zIBp0yVjQgIazsymmFhDW6WEu16TzFVnNqcT2R5F8TR+5xnQFxgoG\nWbuS1uSKhF0a0mXAQqhPijcw+qY+j3kxPbpu0YQrEeb0FIM5Oa0UjuhBXEA4aXNZ\ntBAfKKxDxLAhY73DY1wPf4W3OgK2rRE6aZ/V7elAAlqjRMGvuPWVuTZVDf7GOSA7\nmIiNdYvf0TdShpWJ4wF12xugHl4ezDHR+vOjOTVHScvFL5bRD0nEhH5fzCoDLlp9\nPsz2/vAtCgLHyFj0WgUjsGbHC/6NhSBvPQYIHIV/z5m57JyuSI4S0kiIPcd4X8HR\nXwIDAQAB\n-----END PUBLIC KEY-----";

    public function __construct($apiUrl, $secretKey, $appName, $version) {
        $this->apiUrl = rtrim($apiUrl, '/');
        $this->secretKey = $secretKey;
        $this->appName = $appName;
        $this->version = $version;
    }

    public function getHWID() {
        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $output = shell_exec('wmic csproduct get uuid');
            $lines = explode("\n", trim($output));
            if (count($lines) > 1) {
                return trim($lines[1]);
            }
        } elseif (PHP_OS === 'Darwin') {
            $output = shell_exec('ioreg -rd1 -c IOPlatformExpertDevice');
            if (preg_match('/IOPlatformUUID"\s*=\s*"([^"]+)"/', $output, $matches)) {
                return $matches[1];
            }
        } else {
            if (file_exists('/etc/machine-id')) {
                return trim(file_get_contents('/etc/machine-id'));
            }
        }
        return "UNKNOWN";
    }

    private function sha256Hex($value) {
        return strtoupper(hash('sha256', $value));
    }

    private function generateNonce() {
        if (function_exists('random_bytes')) {
            return bin2hex(random_bytes(16));
        }
        return md5(uniqid(mt_rand(), true));
    }

    private function getCurrentTimestamp() {
        return (string)time();
    }

    private function verifySignature($endpoint, $signatureBase64, $serverTimestamp, $responseObj, $requestNonce) {
        try {
            $currentTs = time();
            $srvTs = (int)$serverTimestamp;
            if (abs($currentTs - $srvTs) > 120) {
                return false;
            }

            $successStr = isset($responseObj['success']) && $responseObj['success'] ? "1" : "0";
            $variableLines = "";

            if (isset($responseObj['variables']) && is_array($responseObj['variables'])) {
                $keys = array_keys($responseObj['variables']);
                sort($keys);
                foreach ($keys as $k) {
                    $val = $responseObj['variables'][$k];
                    if (!is_string($val)) $val = json_encode($val);
                    $variableLines .= "{$k}={$val}\n";
                }
            }

            $payload = "endpoint=" . $this->sha256Hex($endpoint) . "\n" .
                       "requestNonce=" . $this->sha256Hex($requestNonce) . "\n" .
                       "serverTimestamp=" . $this->sha256Hex($serverTimestamp) . "\n" .
                       "success=" . $successStr . "\n" .
                       "message=" . $this->sha256Hex($responseObj['message'] ?? "") . "\n" .
                       "username=" . $this->sha256Hex($responseObj['username'] ?? "") . "\n" .
                       "subscription=" . $this->sha256Hex($responseObj['subscription'] ?? "") . "\n" .
                       "expiry=" . $this->sha256Hex($responseObj['expiry'] ?? "") . "\n" .
                       "serverVersion=" . $this->sha256Hex($responseObj['serverVersion'] ?? "") . "\n" .
                       "value=" . $this->sha256Hex($responseObj['value'] ?? "") . "\n" .
                       "variables=" . $this->sha256Hex($variableLines ? $variableLines . "\n" : "") . "\n";

            $signature = base64_decode($signatureBase64);
            $pubKeyId = openssl_pkey_get_public($this->publicKeyPem);
            if (!$pubKeyId) return false;

            $result = openssl_verify($payload, $signature, $pubKeyId, OPENSSL_ALGO_SHA256);
            openssl_free_key($pubKeyId);
            
            return $result === 1;
        } catch (Exception $e) {
            return false;
        }
    }

    private function req($endpoint, $payloadDict, $secure = true) {
        $requestNonce = $this->generateNonce();
        $clientTimestamp = $this->getCurrentTimestamp();

        if ($secure) {
            $payloadDict['clientNonce'] = $requestNonce;
            $payloadDict['clientTimestamp'] = $clientTimestamp;
        }
        if (!empty($this->sessionId)) {
            $payloadDict['sessionid'] = $this->sessionId;
        }

        $payloadStr = json_encode($payloadDict);

        $ch = curl_init("{$this->apiUrl}/{$endpoint}");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payloadStr);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Accept: application/json'
        ]);
        curl_setopt($ch, CURLOPT_HEADER, true); // We need headers for signature
        
        $response = curl_exec($ch);
        if (curl_errno($ch)) {
            return ['success' => false, 'message' => 'Network error: ' . curl_error($ch)];
        }

        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $headerStr = substr($response, 0, $headerSize);
        $bodyStr = substr($response, $headerSize);
        curl_close($ch);

        $headers = [];
        foreach (explode("\r\n", $headerStr) as $line) {
            if (strpos($line, ':') !== false) {
                list($key, $value) = explode(':', $line, 2);
                $headers[strtolower(trim($key))] = trim($value);
            }
        }

        $responseObj = json_decode($bodyStr, true);
        if ($responseObj === null) {
            return ['success' => false, 'message' => 'Invalid JSON from server'];
        }

        if ($secure) {
            $rsaSignature = $headers['x-signature-rsa'] ?? null;
            $srvTimestamp = $headers['x-signature-timestamp'] ?? null;

            if (!$rsaSignature || !$srvTimestamp || !$this->verifySignature($endpoint, $rsaSignature, $srvTimestamp, $responseObj, $requestNonce)) {
                return ['success' => false, 'message' => 'Security Check Failed'];
            }
        }
        return $responseObj;
    }

    public function init() {
        if ($this->initialized) return;

        $payload = [
            'secret' => $this->secretKey,
            'appName' => $this->appName,
            'appVersion' => $this->version,
            'hash' => 'NOT_FOUND' // Exe hash not applicable for PHP
        ];

        $response = $this->req("init", $payload, false);
        if (isset($response['success']) && $response['success']) {
            $this->sessionId = $response['sessionid'];
            $this->initialized = true;
        } else {
            echo "Initialization Failed: " . ($response['message'] ?? "Unknown error") . "\n";
            exit(1);
        }
    }

    public function login($username, $password, $hwid = "") {
        if (!$this->initialized) { echo "Must call init() first!\n"; exit(1); }
        $payload = [
            'secret' => $this->secretKey,
            'appName' => $this->appName,
            'appVersion' => $this->version,
            'username' => $username,
            'password' => $password,
            'hwid' => empty($hwid) ? $this->getHWID() : $hwid
        ];
        return $this->req("login", $payload);
    }

    public function register($username, $password, $licenseKey, $hwid = "") {
        if (!$this->initialized) { echo "Must call init() first!\n"; exit(1); }
        $payload = [
            'secret' => $this->secretKey,
            'appName' => $this->appName,
            'appVersion' => $this->version,
            'username' => $username,
            'password' => $password,
            'licenseKey' => $licenseKey,
            'hwid' => empty($hwid) ? $this->getHWID() : $hwid
        ];
        return $this->req("register", $payload);
    }

    public function license($licenseKey, $hwid = "") {
        if (!$this->initialized) { echo "Must call init() first!\n"; exit(1); }
        $payload = [
            'secret' => $this->secretKey,
            'appName' => $this->appName,
            'appVersion' => $this->version,
            'licenseKey' => $licenseKey,
            'hwid' => empty($hwid) ? $this->getHWID() : $hwid
        ];
        return $this->req("license", $payload);
    }
}
?>
