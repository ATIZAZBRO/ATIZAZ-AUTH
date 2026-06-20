using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace AtizazAuth
{
    public class AtizazAuthAPI
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern ushort GlobalAddAtom(string lpString);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern ushort GlobalFindAtom(string lpString);

        private readonly string apiUrl;
        private readonly string secretKey;
        private readonly string applicationName;
        private readonly string version;
        private readonly HttpClient client;
        
        private string sessionid = "";
        private string seed = "";
        private bool initialized = false;

        private const string publicKeyXml = "<RSAKeyValue><Modulus>nysSGsuoFA3YCx+FLvL1jdAz4SN9nu2zIBp0yVjQgIazsymmFhDW6WEu16TzFVnNqcT2R5F8TR+5xnQFxgoGWbuS1uSKhF0a0mXAQqhPijcw+qY+j3kxPbpu0YQrEeb0FIM5Oa0UjuhBXEA4aXNZtBAfKKxDxLAhY73DY1wPf4W3OgK2rRE6aZ/V7elAAlqjRMGvuPWVuTZVDf7GOSA7mIiNdYvf0TdShpWJ4wF12xugHl4ezDHR+vOjOTVHScvFL5bRD0nEhH5fzCoDLlp9Psz2/vAtCgLHyFj0WgUjsGbHC/6NhSBvPQYIHIV/z5m57JyuSI4S0kiIPcd4X8HRXw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

        public AtizazAuthAPI(string apiUrl, string secretKey, string applicationName, string version)
        {
            this.apiUrl = apiUrl.TrimEnd('/');
            this.secretKey = secretKey;
            this.applicationName = applicationName;
            this.version = version;
            this.client = new HttpClient();
        }

        private static string Checksum(string filename)
        {
            using (MD5 md = MD5.Create())
            {
                using (FileStream fileStream = File.OpenRead(filename))
                {
                    byte[] value = md.ComputeHash(fileStream);
                    return BitConverter.ToString(value).Replace("-", "").ToLowerInvariant();
                }
            }
        }

        public static string GetHWID()
        {
            try
            {
                return System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;
            }
            catch
            {
                return "UNKNOWN";
            }
        }

        private void CheckAtom()
        {
            Thread atomCheckThread = new Thread(() =>
            {
                while (true)
                {
                    Thread.Sleep(60000); 
                    ushort foundAtom = GlobalFindAtom(seed);
                    if (foundAtom == 0)
                    {
                        TerminateProcess(GetCurrentProcess(), 1);
                    }
                }
            });
            atomCheckThread.IsBackground = true;
            atomCheckThread.Start();
        }

        public void Init()
        {
            if (initialized) return; // Prevent multiple initializations

            Random random = new Random();
            int length = random.Next(15, 30);
            StringBuilder sb = new StringBuilder(length);
            for (int i = 0; i < length; i++) sb.Append((char)random.Next(32, 127));
            seed = sb.ToString();
            CheckAtom();

            string hash = Checksum(Process.GetCurrentProcess().MainModule.FileName);
            
            var payload = new Dictionary<string, string>
            {
                {"secret", this.secretKey},
                {"appName", this.applicationName},
                {"appVersion", this.version},
                {"hash", hash}
            };

            try 
            {
                // Task.Run prevents UI thread deadlock
                var response = Task.Run(() => Req("init", payload, false)).GetAwaiter().GetResult();
                if (response != null && response.success)
                {
                    this.sessionid = response.sessionid;
                    this.initialized = true;
                    GlobalAddAtom(seed);
                }
                else
                {
                    System.Windows.Forms.MessageBox.Show("Initialization Failed: " + (response != null ? response.message : "Unknown Error. Check secret key and app name."));
                    TerminateProcess(GetCurrentProcess(), 1);
                }
            }
            catch (Exception ex)
            {
                System.Windows.Forms.MessageBox.Show("Connection Error: " + ex.Message);
                TerminateProcess(GetCurrentProcess(), 1);
            }
        }

        private void CheckInit()
        {
            if (!initialized)
            {
                throw new Exception("You must run Init() first");
            }
        }

        private static string Sha256Hex(string value)
        {
            if (value == null) value = "";
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(value));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hash) sb.Append(b.ToString("X2"));
                return sb.ToString();
            }
        }

        private bool SigCheck(string endpoint, string signatureBase64, string serverTimestamp, APIResponse responseObj, string requestNonce)
        {
            try
            {
                long currentTs = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (!long.TryParse(serverTimestamp, out long srvTs) || Math.Abs(currentTs - srvTs) > 120)
                {
                    return false;
                }

                string successStr = responseObj.success ? "1" : "0";
                
                string variableLines = "";
                if (responseObj.variables != null)
                {
                    var keys = new List<string>(responseObj.variables.Keys);
                    keys.Sort();
                    StringBuilder varb = new StringBuilder();
                    foreach (var k in keys) varb.Append($"{k}={responseObj.variables[k]}\n");
                    variableLines = varb.ToString();
                }

                string payload = $"endpoint={Sha256Hex(endpoint)}\n" +
                                 $"requestNonce={Sha256Hex(requestNonce)}\n" +
                                 $"serverTimestamp={Sha256Hex(serverTimestamp)}\n" +
                                 $"success={successStr}\n" +
                                 $"message={Sha256Hex(responseObj.message)}\n" +
                                 $"username={Sha256Hex(responseObj.username)}\n" +
                                 $"subscription={Sha256Hex(responseObj.subscription)}\n" +
                                 $"expiry={Sha256Hex(responseObj.expiry)}\n" +
                                 $"serverVersion={Sha256Hex(responseObj.serverVersion)}\n" +
                                 $"value={Sha256Hex(responseObj.value)}\n" +
                                 $"variables={Sha256Hex(variableLines.Length > 0 ? variableLines + "\n" : "")}\n";

                byte[] signature = Convert.FromBase64String(signatureBase64);
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(publicKeyXml);
                    return rsa.VerifyData(Encoding.UTF8.GetBytes(payload), CryptoConfig.MapNameToOID("SHA256"), signature);
                }
            }
            catch
            {
                return false;
            }
        }

        private static string EscapeJsonString(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            return text.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");
        }

        private string SerializeDictionary(Dictionary<string, string> dict)
        {
            StringBuilder json = new StringBuilder("{");
            bool first = true;
            foreach (var kvp in dict)
            {
                if (!first) json.Append(",");
                json.Append($"\"{EscapeJsonString(kvp.Key)}\":\"{EscapeJsonString(kvp.Value)}\"");
                first = false;
            }
            json.Append("}");
            return json.ToString();
        }

        private APIResponse DeserializeResponse(string json)
        {
            var ms = new MemoryStream(Encoding.UTF8.GetBytes(json));
            var serializer = new DataContractJsonSerializer(typeof(APIResponse));
            return (APIResponse)serializer.ReadObject(ms);
        }

        private async Task<APIResponse> Req(string endpoint, Dictionary<string, string> payloadDict, bool secure = true)
        {
            string requestNonce = Guid.NewGuid().ToString("N");
            string clientTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            
            if (secure)
            {
                payloadDict["clientNonce"] = requestNonce;
                payloadDict["clientTimestamp"] = clientTimestamp;
            }
            if (sessionid != "")
            {
                payloadDict["sessionid"] = sessionid;
            }

            var content = new StringContent(SerializeDictionary(payloadDict), Encoding.UTF8, "application/json");
            var res = await client.PostAsync($"{apiUrl}/{endpoint}", content);

            string responseString = await res.Content.ReadAsStringAsync();
            var responseObj = DeserializeResponse(responseString);

            if (secure && responseObj != null)
            {
                string rsaSignature = "";
                string srvTimestamp = "";
                if (res.Headers.TryGetValues("x-signature-rsa", out var sigs)) rsaSignature = new List<string>(sigs)[0];
                if (res.Headers.TryGetValues("x-signature-timestamp", out var ts)) srvTimestamp = new List<string>(ts)[0];

                if (!SigCheck(endpoint, rsaSignature, srvTimestamp, responseObj, requestNonce))
                {
                    TerminateProcess(GetCurrentProcess(), 1);
                    return null;
                }
            }

            return responseObj;
        }

        public async Task<APIResponse> Login(string username, string password, string hwid = "")
        {
            CheckInit();
            if (string.IsNullOrEmpty(hwid)) hwid = GetHWID();
            var payload = new Dictionary<string, string>
            {
                {"secret", this.secretKey},
                {"appName", this.applicationName},
                {"appVersion", this.version},
                {"username", username},
                {"password", password},
                {"hwid", hwid}
            };
            return await Req("login", payload);
        }

        public async Task<APIResponse> Register(string username, string password, string licenseKey, string hwid = "")
        {
            CheckInit();
            if (string.IsNullOrEmpty(hwid)) hwid = GetHWID();
            var payload = new Dictionary<string, string>
            {
                {"secret", this.secretKey},
                {"appName", this.applicationName},
                {"appVersion", this.version},
                {"username", username},
                {"password", password},
                {"licenseKey", licenseKey},
                {"hwid", hwid}
            };
            return await Req("register", payload);
        }

        public async Task<APIResponse> License(string licenseKey, string hwid = "")
        {
            CheckInit();
            if (string.IsNullOrEmpty(hwid)) hwid = GetHWID();
            var payload = new Dictionary<string, string>
            {
                {"secret", this.secretKey},
                {"appName", this.applicationName},
                {"appVersion", this.version},
                {"licenseKey", licenseKey},
                {"hwid", hwid}
            };
            return await Req("license", payload);
        }
    }

    [DataContract]
    public class APIResponse
    {
        [DataMember(Name = "success")]
        public bool success { get; set; }
        
        [DataMember(Name = "message")]
        public string message { get; set; }
        
        [DataMember(Name = "username")]
        public string username { get; set; }
        
        [DataMember(Name = "subscription")]
        public string subscription { get; set; }
        
        [DataMember(Name = "expiry")]
        public string expiry { get; set; }
        
        [DataMember(Name = "serverVersion")]
        public string serverVersion { get; set; }
        
        [DataMember(Name = "value")]
        public string value { get; set; }
        
        [DataMember(Name = "variables")]
        public Dictionary<string, string> variables { get; set; }
        
        [DataMember(Name = "sessionid")]
        public string sessionid { get; set; }
    }
}
