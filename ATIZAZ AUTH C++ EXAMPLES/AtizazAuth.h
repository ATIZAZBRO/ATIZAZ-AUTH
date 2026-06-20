#pragma once
#include <string>
#include <vector>
#include "json.hpp"

using json = nlohmann::json;

class AtizazAuthAPI {
public:
    AtizazAuthAPI(const std::string& apiUrl, const std::string& secretKey, const std::string& appName, const std::string& version);
    ~AtizazAuthAPI();

    void Init();
    json Login(const std::string& username, const std::string& password, const std::string& hwid = "");
    json Register(const std::string& username, const std::string& password, const std::string& licenseKey, const std::string& hwid = "");
    json License(const std::string& licenseKey, const std::string& hwid = "");

    static std::string GetHWID();
    std::string GetSessionID() const { return sessionid; }

private:
    std::string api_url;
    std::string secret_key;
    std::string application_name;
    std::string version;
    std::string sessionid;
    bool initialized;

    std::string public_key_pem;

    std::string GetExeHash();
    std::string SHA256Hex(const std::string& value);
    std::string GenerateNonce();
    std::string GetCurrentTimestamp();

    bool VerifySignature(const std::string& endpoint, const std::string& signature_base64, const std::string& server_timestamp, const json& response_obj, const std::string& request_nonce);
    json Req(const std::string& endpoint, json payload_dict, bool secure = true);
};
