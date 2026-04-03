from typing import Dict, Any

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