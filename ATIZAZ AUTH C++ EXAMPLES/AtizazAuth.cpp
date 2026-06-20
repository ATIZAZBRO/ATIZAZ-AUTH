#include "AtizazAuth.h"
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <sddl.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

AtizazAuthAPI::AtizazAuthAPI(const std::string& apiUrl, const std::string& secretKey, const std::string& appName, const std::string& version)
    : api_url(apiUrl), secret_key(secretKey), application_name(appName), version(version), initialized(false) {
    
    // Remove trailing slash if present
    if (!api_url.empty() && api_url.back() == '/') {
        api_url.pop_back();
    }

    public_key_pem = "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnysSGsuoFA3YCx+FLvL1\n"
        "jdAz4SN9nu2zIBp0yVjQgIazsymmFhDW6WEu16TzFVnNqcT2R5F8TR+5xnQFxgoG\n"
        "WbuS1uSKhF0a0mXAQqhPijcw+qY+j3kxPbpu0YQrEeb0FIM5Oa0UjuhBXEA4aXNZ\n"
        "tBAfKKxDxLAhY73DY1wPf4W3OgK2rRE6aZ/V7elAAlqjRMGvuPWVuTZVDf7GOSA7\n"
        "mIiNdYvf0TdShpWJ4wF12xugHl4ezDHR+vOjOTVHScvFL5bRD0nEhH5fzCoDLlp9\n"
        "Psz2/vAtCgLHyFj0WgUjsGbHC/6NhSBvPQYIHIV/z5m57JyuSI4S0kiIPcd4X8HR\n"
        "XwIDAQAB\n"
        "-----END PUBLIC KEY-----\n";
}

AtizazAuthAPI::~AtizazAuthAPI() {}

std::string AtizazAuthAPI::GetHWID() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return "UNKNOWN";

    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);
    if (dwLength == 0) { CloseHandle(hToken); return "UNKNOWN"; }

    std::vector<BYTE> tokenInfo(dwLength);
    if (!GetTokenInformation(hToken, TokenUser, tokenInfo.data(), dwLength, &dwLength)) {
        CloseHandle(hToken); return "UNKNOWN";
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)tokenInfo.data();
    LPSTR sidString = NULL;
    if (!ConvertSidToStringSidA(pTokenUser->User.Sid, &sidString)) {
        CloseHandle(hToken); return "UNKNOWN";
    }

    std::string hwid(sidString);
    LocalFree(sidString);
    CloseHandle(hToken);
    return hwid;
}

std::string AtizazAuthAPI::GetExeHash() {
    char path[MAX_PATH];
    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) return "NOT_FOUND";

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "NOT_FOUND";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string md5Result = "NOT_FOUND";

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            BYTE buffer[4096];
            DWORD bytesRead = 0;
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                CryptHashData(hHash, buffer, bytesRead, 0);
            }
            
            BYTE hashVal[16];
            DWORD hashLen = 16;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hashVal, &hashLen, 0)) {
                std::stringstream ss;
                for (DWORD i = 0; i < hashLen; i++) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashVal[i];
                }
                md5Result = ss.str();
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
    return md5Result;
}

std::string AtizazAuthAPI::SHA256Hex(const std::string& value) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result = "";

    if (CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptHashData(hHash, (const BYTE*)value.c_str(), value.length(), 0);
            BYTE hashVal[32];
            DWORD hashLen = 32;
            if (CryptGetHashParam(hHash, HP_HASHVAL, hashVal, &hashLen, 0)) {
                std::stringstream ss;
                for (DWORD i = 0; i < hashLen; i++) {
                    ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)hashVal[i];
                }
                result = ss.str();
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

std::string AtizazAuthAPI::GenerateNonce() {
    GUID guid;
    CoCreateGuid(&guid);
    char guidStr[33];
    sprintf_s(guidStr, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return std::string(guidStr);
}

std::string AtizazAuthAPI::GetCurrentTimestamp() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    long long seconds = (uli.QuadPart - 116444736000000000LL) / 10000000LL;
    return std::to_string(seconds);
}

bool AtizazAuthAPI::VerifySignature(const std::string& endpoint, const std::string& signature_base64, const std::string& server_timestamp, const json& response_obj, const std::string& request_nonce) {
    try {
        long long current_ts = std::stoll(GetCurrentTimestamp());
        long long srv_ts = std::stoll(server_timestamp);
        if (std::abs(current_ts - srv_ts) > 120) return false;

        std::string success_str = response_obj.value("success", false) ? "1" : "0";
        std::string variable_lines = "";
        
        if (response_obj.contains("variables") && response_obj["variables"].is_object()) {
            std::vector<std::string> keys;
            for (auto& el : response_obj["variables"].items()) {
                keys.push_back(el.key());
            }
            std::sort(keys.begin(), keys.end());
            for (const auto& k : keys) {
                std::string val = response_obj["variables"][k].is_string() ? response_obj["variables"][k].get<std::string>() : response_obj["variables"][k].dump();
                variable_lines += k + "=" + val + "\n";
            }
        }

        std::string payload = 
            "endpoint=" + SHA256Hex(endpoint) + "\n" +
            "requestNonce=" + SHA256Hex(request_nonce) + "\n" +
            "serverTimestamp=" + SHA256Hex(server_timestamp) + "\n" +
            "success=" + success_str + "\n" +
            "message=" + SHA256Hex(response_obj.value("message", "")) + "\n" +
            "username=" + SHA256Hex(response_obj.value("username", "")) + "\n" +
            "subscription=" + SHA256Hex(response_obj.value("subscription", "")) + "\n" +
            "expiry=" + SHA256Hex(response_obj.value("expiry", "")) + "\n" +
            "serverVersion=" + SHA256Hex(response_obj.value("serverVersion", "")) + "\n" +
            "value=" + SHA256Hex(response_obj.value("value", "")) + "\n" +
            "variables=" + SHA256Hex(variable_lines.empty() ? "" : variable_lines + "\n") + "\n";

        DWORD derLen = 0;
        if (!CryptStringToBinaryA(public_key_pem.c_str(), 0, CRYPT_STRING_BASE64HEADER, NULL, &derLen, NULL, NULL)) return false;
        std::vector<BYTE> der(derLen);
        if (!CryptStringToBinaryA(public_key_pem.c_str(), 0, CRYPT_STRING_BASE64HEADER, der.data(), &derLen, NULL, NULL)) return false;

        DWORD keyInfoLen = 0;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, der.data(), derLen, 0, NULL, NULL, &keyInfoLen)) return false;
        std::vector<BYTE> keyInfoBuf(keyInfoLen);
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, der.data(), derLen, 0, NULL, keyInfoBuf.data(), &keyInfoLen)) return false;
        CERT_PUBLIC_KEY_INFO* pKeyInfo = (CERT_PUBLIC_KEY_INFO*)keyInfoBuf.data();

        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;

        HCRYPTKEY hKey = 0;
        if (!CryptImportPublicKeyInfo(hProv, X509_ASN_ENCODING, pKeyInfo, &hKey)) {
            CryptReleaseContext(hProv, 0); return false;
        }

        DWORD sigLen = 0;
        if (!CryptStringToBinaryA(signature_base64.c_str(), 0, CRYPT_STRING_BASE64, NULL, &sigLen, NULL, NULL)) return false;
        std::vector<BYTE> sig(sigLen);
        if (!CryptStringToBinaryA(signature_base64.c_str(), 0, CRYPT_STRING_BASE64, sig.data(), &sigLen, NULL, NULL)) return false;

        std::reverse(sig.begin(), sig.end());

        HCRYPTHASH hHash = 0;
        bool valid = false;
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (const BYTE*)payload.data(), payload.length(), 0)) {
                valid = CryptVerifySignatureA(hHash, sig.data(), sigLen, hKey, NULL, 0) != 0;
            }
            CryptDestroyHash(hHash);
        }

        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);

        return valid;
    } catch (...) {
        return false;
    }
}

json AtizazAuthAPI::Req(const std::string& endpoint, json payload_dict, bool secure) {
    std::string request_nonce = GenerateNonce();
    std::string client_timestamp = GetCurrentTimestamp();

    if (secure) {
        payload_dict["clientNonce"] = request_nonce;
        payload_dict["clientTimestamp"] = client_timestamp;
    }
    if (!sessionid.empty()) {
        payload_dict["sessionid"] = sessionid;
    }

    std::string payload_str = payload_dict.dump();

    URL_COMPONENTS urlComp;
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    
    std::wstring wApiUrl(api_url.begin(), api_url.end());
    std::wstring wEndpoint(endpoint.begin(), endpoint.end());
    std::wstring fullUrl = wApiUrl + L"/" + wEndpoint;

    wchar_t hostName[256];
    wchar_t urlPath[1024];
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = 256;
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = 1024;

    if (!WinHttpCrackUrl(fullUrl.c_str(), fullUrl.length(), 0, &urlComp)) {
        return json{{"success", false}, {"message", "Invalid API URL"}};
    }

    HINTERNET hSession = WinHttpOpen(L"Atizaz Auth C++ SDK/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return json{{"success", false}, {"message", "Failed to open WinHTTP session"}};

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return json{{"success", false}, {"message", "Connection failed"}}; }

    DWORD flags = (urlComp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return json{{"success", false}, {"message", "Failed to open request"}};
    }

    LPCWSTR headers = L"Content-Type: application/json\r\n";
    if (!WinHttpSendRequest(hRequest, headers, -1L, (LPVOID)payload_str.c_str(), payload_str.length(), payload_str.length(), 0)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return json{{"success", false}, {"message", "Failed to send request"}};
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return json{{"success", false}, {"message", "Failed to receive response"}};
    }

    // Read headers
    std::string rsa_signature = "";
    std::string srv_timestamp = "";

    DWORD headerSize = 0;
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, L"x-signature-rsa", WINHTTP_NO_OUTPUT_BUFFER, &headerSize, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::wstring wSig(headerSize / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, L"x-signature-rsa", &wSig[0], &headerSize, WINHTTP_NO_HEADER_INDEX)) {
            rsa_signature = std::string(wSig.begin(), wSig.end() - 1);
        }
    }

    headerSize = 0;
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, L"x-signature-timestamp", WINHTTP_NO_OUTPUT_BUFFER, &headerSize, WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::wstring wTs(headerSize / sizeof(wchar_t), L'\0');
        if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, L"x-signature-timestamp", &wTs[0], &headerSize, WINHTTP_NO_HEADER_INDEX)) {
            srv_timestamp = std::string(wTs.begin(), wTs.end() - 1);
        }
    }

    std::string responseData = "";
    DWORD dwSize = 0;
    do {
        if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
            std::vector<char> buffer(dwSize + 1);
            DWORD dwDownloaded = 0;
            if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                buffer[dwDownloaded] = '\0';
                responseData += buffer.data();
            }
        }
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    json response_obj;
    try {
        response_obj = json::parse(responseData);
    } catch (...) {
        return json{{"success", false}, {"message", "Invalid JSON Response from server"}};
    }

    if (secure && !response_obj.empty()) {
        if (!VerifySignature(endpoint, rsa_signature, srv_timestamp, response_obj, request_nonce)) {
            std::cerr << "SECURITY ERROR: Response signature validation failed!" << std::endl;
            exit(1);
        }
    }

    return response_obj;
}

void AtizazAuthAPI::Init() {
    if (initialized) return;

    std::string hash_val = GetExeHash();

    json payload = {
        {"secret", secret_key},
        {"appName", application_name},
        {"appVersion", version},
        {"hash", hash_val}
    };

    json response = Req("init", payload, false);
    if (response.value("success", false)) {
        sessionid = response.value("sessionid", "");
        initialized = true;
    } else {
        std::cerr << "Initialization Failed: " << response.value("message", "Unknown Error") << std::endl;
        exit(1);
    }
}

json AtizazAuthAPI::Login(const std::string& username, const std::string& password, const std::string& hwid) {
    if (!initialized) { std::cerr << "Must call Init() first!" << std::endl; exit(1); }
    json payload = {
        {"secret", secret_key},
        {"appName", application_name},
        {"appVersion", version},
        {"username", username},
        {"password", password},
        {"hwid", hwid.empty() ? GetHWID() : hwid}
    };
    return Req("login", payload);
}

json AtizazAuthAPI::Register(const std::string& username, const std::string& password, const std::string& licenseKey, const std::string& hwid) {
    if (!initialized) { std::cerr << "Must call Init() first!" << std::endl; exit(1); }
    json payload = {
        {"secret", secret_key},
        {"appName", application_name},
        {"appVersion", version},
        {"username", username},
        {"password", password},
        {"licenseKey", licenseKey},
        {"hwid", hwid.empty() ? GetHWID() : hwid}
    };
    return Req("register", payload);
}

json AtizazAuthAPI::License(const std::string& licenseKey, const std::string& hwid) {
    if (!initialized) { std::cerr << "Must call Init() first!" << std::endl; exit(1); }
    json payload = {
        {"secret", secret_key},
        {"appName", application_name},
        {"appVersion", version},
        {"licenseKey", licenseKey},
        {"hwid", hwid.empty() ? GetHWID() : hwid}
    };
    return Req("license", payload);
}
