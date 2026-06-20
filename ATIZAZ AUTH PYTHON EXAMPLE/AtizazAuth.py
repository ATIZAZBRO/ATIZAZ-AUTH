import os
import sys
import time
import uuid
import base64
import hashlib
import requests
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

class AtizazAuthAPI:
    def __init__(self, api_url, secret_key, application_name, version):
        self.api_url = api_url.rstrip('/')
        self.secret_key = secret_key
        self.application_name = application_name
        self.version = version
        self.sessionid = ""
        self.initialized = False
        self.session = requests.Session()

        self.public_key_pem = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnysSGsuoFA3YCx+FLvL1
jdAz4SN9nu2zIBp0yVjQgIazsymmFhDW6WEu16TzFVnNqcT2R5F8TR+5xnQFxgoG
WbuS1uSKhF0a0mXAQqhPijcw+qY+j3kxPbpu0YQrEeb0FIM5Oa0UjuhBXEA4aXNZ
tBAfKKxDxLAhY73DY1wPf4W3OgK2rRE6aZ/V7elAAlqjRMGvuPWVuTZVDf7GOSA7
mIiNdYvf0TdShpWJ4wF12xugHl4ezDHR+vOjOTVHScvFL5bRD0nEhH5fzCoDLlp9
Psz2/vAtCgLHyFj0WgUjsGbHC/6NhSBvPQYIHIV/z5m57JyuSI4S0kiIPcd4X8HR
XwIDAQAB
-----END PUBLIC KEY-----"""

        self.public_key = serialization.load_pem_public_key(self.public_key_pem)

    @staticmethod
    def get_hwid():
        try:
            # Gets Windows User SID similar to C# WindowsIdentity.GetCurrent().User.Value
            output = subprocess.check_output('whoami /user /fo csv /nh', shell=True).decode().strip()
            # output format: "DOMAIN\user","S-1-5-21-..."
            sid = output.split(',')[1].strip('"')
            return sid
        except Exception:
            try:
                return subprocess.check_output('wmic csproduct get uuid', shell=True).decode().split('\n')[1].strip()
            except Exception:
                return "UNKNOWN"

    @staticmethod
    def checksum(filename):
        md5 = hashlib.md5()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
        return md5.hexdigest().lower()

    @staticmethod
    def sha256_hex(value):
        if value is None:
            value = ""
        return hashlib.sha256(str(value).encode('utf-8')).hexdigest().upper()

    def check_init(self):
        if not self.initialized:
            raise Exception("You must run init() first")

    def sig_check(self, endpoint, signature_base64, server_timestamp, response_obj, request_nonce):
        try:
            current_ts = int(time.time())
            srv_ts = int(server_timestamp)
            if abs(current_ts - srv_ts) > 120:
                return False

            success_str = "1" if response_obj.get("success") else "0"
            
            variable_lines = ""
            variables = response_obj.get("variables", {})
            if variables:
                sorted_keys = sorted(variables.keys())
                for k in sorted_keys:
                    variable_lines += f"{k}={variables[k]}\n"

            payload = (
                f"endpoint={self.sha256_hex(endpoint)}\n"
                f"requestNonce={self.sha256_hex(request_nonce)}\n"
                f"serverTimestamp={self.sha256_hex(server_timestamp)}\n"
                f"success={success_str}\n"
                f"message={self.sha256_hex(response_obj.get('message', ''))}\n"
                f"username={self.sha256_hex(response_obj.get('username', ''))}\n"
                f"subscription={self.sha256_hex(response_obj.get('subscription', ''))}\n"
                f"expiry={self.sha256_hex(response_obj.get('expiry', ''))}\n"
                f"serverVersion={self.sha256_hex(response_obj.get('serverVersion', ''))}\n"
                f"value={self.sha256_hex(response_obj.get('value', ''))}\n"
                f"variables={self.sha256_hex(variable_lines + '\n' if variable_lines else '')}\n"
            )

            signature = base64.b64decode(signature_base64)
            self.public_key.verify(
                signature,
                payload.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False

    def req(self, endpoint, payload_dict, secure=True):
        request_nonce = uuid.uuid4().hex
        client_timestamp = str(int(time.time()))

        if secure:
            payload_dict["clientNonce"] = request_nonce
            payload_dict["clientTimestamp"] = client_timestamp
        
        if self.sessionid:
            payload_dict["sessionid"] = self.sessionid

        try:
            res = self.session.post(f"{self.api_url}/{endpoint}", json=payload_dict)
            response_obj = res.json()
        except Exception as e:
            return {"success": False, "message": f"Connection Error: {str(e)}"}

        if secure and response_obj:
            rsa_signature = res.headers.get("x-signature-rsa", "")
            srv_timestamp = res.headers.get("x-signature-timestamp", "")

            if not self.sig_check(endpoint, rsa_signature, srv_timestamp, response_obj, request_nonce):
                print("SECURITY ERROR: Response signature validation failed!")
                os._exit(1)
        
        return response_obj

    def init(self):
        if self.initialized:
            return
        
        try:
            exe_path = sys.argv[0]
            if not os.path.exists(exe_path):
                exe_path = sys.executable
            hash_val = self.checksum(exe_path)
        except Exception:
            hash_val = "NOT_FOUND"

        payload = {
            "secret": self.secret_key,
            "appName": self.application_name,
            "appVersion": self.version,
            "hash": hash_val
        }

        response = self.req("init", payload, secure=False)
        if response and response.get("success"):
            self.sessionid = response.get("sessionid", "")
            self.initialized = True
        else:
            print(f"Initialization Failed: {response.get('message', 'Unknown Error')}")
            os._exit(1)

    def login(self, username, password, hwid=""):
        self.check_init()
        if not hwid:
            hwid = self.get_hwid()
        payload = {
            "secret": self.secret_key,
            "appName": self.application_name,
            "appVersion": self.version,
            "username": username,
            "password": password,
            "hwid": hwid
        }
        return self.req("login", payload)

    def register(self, username, password, license_key, hwid=""):
        self.check_init()
        if not hwid:
            hwid = self.get_hwid()
        payload = {
            "secret": self.secret_key,
            "appName": self.application_name,
            "appVersion": self.version,
            "username": username,
            "password": password,
            "licenseKey": license_key,
            "hwid": hwid
        }
        return self.req("register", payload)

    def license(self, license_key, hwid=""):
        self.check_init()
        if not hwid:
            hwid = self.get_hwid()
        payload = {
            "secret": self.secret_key,
            "appName": self.application_name,
            "appVersion": self.version,
            "licenseKey": license_key,
            "hwid": hwid
        }
        return self.req("license", payload)
