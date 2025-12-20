import requests
import logging
from typing import Dict, Any
import time
from urllib.parse import unquote
from . import auth

_LOGGER = logging.getLogger(__name__)

class TPIPCApiError(Exception):
    """Custom TPIPC API exception."""
    def __init__(self, message, error_code=None):
        super().__init__(message)
        self.error_code = error_code

class TPLinkIPCApiClient:
    """A client to interact with TPIPC devices over non-secure HTTP."""
    
    PAYLOAD_GET_LENSMASK = {"method": "get", "lens_mask": {"name": ["lens_mask_info"]}}
    PAYLOAD_SET_LENSMASK_ON = {"method": "set", "lens_mask": {"lens_mask_info": {"enabled": "on"}}}
    PAYLOAD_SET_LENSMASK_OFF = {"method": "set", "lens_mask": {"lens_mask_info": {"enabled": "off"}}}
    

    def __init__(self, host: str, username: str, password: str):
        if "http" in host:
            raise ValueError("Hostname should not contain 'http://' or 'https://'")
        self.base_url = f"http://{host}"
        self.username = username
        self.password = password
        self.stok = None
        self.session = requests.Session()
        _LOGGER.info(f"TPIPC client initialized for host: {self.base_url}")

    def _get_auth_info(self) -> Dict[str, Any]:
        """Get authentication info (nonce, key, encrypt_type) from the device."""
        url = f"{self.base_url}/pc/Content.htm"
        try:
            response = requests.get(url, timeout=5)
            # response.raise_for_status()
            data = response.json()
            auth_data = data.get("data", {})
            nonce = auth_data.get("nonce")
            key = auth_data.get("key")
            encrypt_type = auth_data.get("encrypt_type")
            
            if not nonce:
                raise TPIPCApiError("Failed to get nonce from device.", data)
            if not key:
                raise TPIPCApiError("Failed to get public key from device.", data)
            
            return {
                "nonce": nonce,
                "key": unquote(key), # Decode key if it's URL encoded
                "encrypt_type": encrypt_type
            }
        except requests.RequestException as e:
            raise TPIPCApiError(f"Network error while getting auth info: {e}") from e

    def _login(self):
        """Login to the device to get a stok."""
        _LOGGER.info("Attempting to login...")
        auth_info = self._get_auth_info()
        nonce = auth_info["nonce"]
        key = auth_info["key"]
        encrypt_type = auth_info["encrypt_type"]
        
        encrypted_password, encrypt_type_to_use = auth.encrypt_password(
            self.password, nonce, key, encrypt_type
        )
        
        url = f"{self.base_url}/"
        payload = {
            "method": "do",
            "login": {
                "username": self.username,
                "password": encrypted_password,
                "encrypt_type": encrypt_type_to_use
            }
        }
        
        # Only add md5_encrypt_type for type 3
        if encrypt_type_to_use == "3":
            payload["login"]["md5_encrypt_type"] = "1"
        
        try:
            response = self.session.post(url, json=payload, timeout=5)
            response.raise_for_status()
            data = response.json()
            stok = data.get("stok")
            if not stok:
                raise TPIPCApiError("Login failed: 'stok' not found in response.", data)
            self.stok = stok
            _LOGGER.info("Login successful, STOK cached.")
        except requests.RequestException as e:
            raise TPIPCApiError(f"Network error during login: {e}") from e

    def request(self, payload: Dict[str, Any], retry: bool = True) -> Dict[str, Any]:
        """Send a request to the device."""
        if not self.stok:
            self._login()
        
        url = f"{self.base_url}/stok={self.stok}/ds"
        try:
            headers = {"Content-Type": "application/json; charset=utf-8", "User-Agent": "TP-LINK_APP"}
            response = self.session.post(url, json=payload, timeout=10, headers=headers)
            response.raise_for_status()
            data = response.json()
            error_code = data.get("error_code", 0)

            if error_code == -40401 and retry:
                _LOGGER.warning("STOK expired or invalid. Re-logging in and retrying request.")
                self.stok = None
                return self.request(payload, retry=False)
            
            if error_code != 0:
                 _LOGGER.warning(f"API returned error: {data}")

            return data
        except requests.RequestException as e:
            raise TPIPCApiError(f"Network error during request: {e}") from e

    def get_lens_mask_status(self) -> bool:
        """Get the current status of the lens mask."""
        result = self.request(self.PAYLOAD_GET_LENSMASK)
        status = result.get("lens_mask", {}).get("lens_mask_info", {}).get("enabled")
        if status is None:
            raise TPIPCApiError("Could not determine lens mask status from response.", result)
        return status == "on"

    def set_lens_mask_on(self) -> Dict[str, Any]:
        """Enable the lens mask (privacy on)."""
        return self.request(self.PAYLOAD_SET_LENSMASK_ON)

    def set_lens_mask_off(self) -> Dict[str, Any]:
        """Disable the lens mask (privacy off)."""
        return self.request(self.PAYLOAD_SET_LENSMASK_OFF)

    def sync_time(self) -> Dict[str, Any]:
        """Synchronize the camera time to the current system time (seconds from 1970)."""
        current_timestamp = int(time.time())
        payload = {
            "method": "do",
            "system": {
                "boot_set_date": {
                    "seconds_from_1970": current_timestamp
                }
            }
        }
        _LOGGER.info(f"Synchronizing camera time to timestamp: {current_timestamp}")
        return self.request(payload)