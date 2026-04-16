import requests
from typing import Dict, Any, Tuple
from api.constants import APIConstants, ValidatedDict

class UnityAPI():
    UNITY_URL = None
    UNITY_PSK = None
    UNITY_APP_ID = None
    UNITY_CALLBACK_URL = None

    @staticmethod
    def updateConfig(unityConfig: Dict[str, Any]) -> None:
        server = unityConfig.get('server', None)
        if server == None:
            raise Exception("Failed to initialize unity 'server'")
        
        psk = unityConfig.get('psk', None)
        if psk == None:
            raise Exception("Failed to initialize unity 'psk'")
        
        appId = unityConfig.get('app-id', None)
        if appId == None:
            raise Exception("Failed to initialize unity 'app-id'")
        
        callbackUrl = unityConfig.get('callback-url', None)
        if callbackUrl == None:
            raise Exception("Failed to initialize unity 'callback-url'")
        
        UnityAPI.UNITY_URL = server
        UnityAPI.UNITY_PSK = psk
        UnityAPI.UNITY_APP_ID = appId
        UnityAPI.UNITY_CALLBACK_URL = callbackUrl

    @staticmethod
    def build_headers(token: str = None) -> dict:
        headers = {
            "X-RS-Key": UnityAPI.UNITY_PSK,
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers
    
    @staticmethod
    def _send_request(url: str, method: str, headers: dict, **kwargs) -> Tuple[bool, Any]:
        try:
            response = requests.request(method, url, headers=headers, **kwargs)
        except requests.RequestException as e:
            return False, APIConstants.badEnd(str(e))
        
        if not response:
            return False, APIConstants.badEnd('No response from Unity')
        
        return True, ValidatedDict(response.json())
    
    @staticmethod
    def _process_response(data: ValidatedDict) -> Tuple[bool, Any]:
        if data.get_str('status') != "success":
            return False, APIConstants.badEnd(f'Unity Error: {data.get_str("error_code")}')
        
        return True, ValidatedDict(data.get_dict('data'))
    
    @classmethod
    def get_app_from_id(cls, appId: str) -> Tuple[bool, Any]:
        success, response = cls._send_request(f"{cls.UNITY_URL}/v1/oauth/app?oauthId={appId}", "GET", cls.build_headers())
        if not success:
            return success, response
        
        success, data = cls._process_response(response)
        return success, data
    
    @classmethod
    def check_app_auth(cls, appId: str, apiKey: str) -> Tuple[bool, Any]:
        requestData = {"apiKey": apiKey}
        success, response = cls._send_request(f"{cls.UNITY_URL}/v1/oauth/app/check/{appId}", "POST", cls.build_headers(), json=requestData)
        if not success:
            return success, response
        
        success, data = cls._process_response(response)
        return success, data