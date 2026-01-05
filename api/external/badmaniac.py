import requests
from io import BytesIO
from typing import Dict, Any
from api.constants import APIConstants, ValidatedDict
from api.data.endpoints.arcade import ArcadeData
from api.data.endpoints.machine import MachineData
from api.external.pfsense import PFSense

class BadManiac:
    BM_URL = None
    BM_KEY = None

    @staticmethod
    def updateConfig(bmConfig: Dict[str, Any]) -> None:
        BadManiac.BM_URL = bmConfig.get('endpoint', '')
        BadManiac.BM_KEY = bmConfig.get('auth-key', '')

    @staticmethod
    def send_link_complete(discord_id: str):
        request_data = {
            "discordId": discord_id,
        }
        try:
            requests.post(f"{BadManiac.BM_URL}/successfulLink", json=request_data, headers={"X-API-Key": BadManiac.BM_KEY})
        except requests.RequestException as e:
            return APIConstants.badEnd(str(e))

    @staticmethod
    def send_upload_complete(discord_id: str, video_path: str, session_id: str):
        request_data = {
            "discordId": discord_id,
            "video": {
                "url": f"{video_path}/{session_id}.mp4",
            }
        }
        try:
            requests.post(f"{BadManiac.BM_URL}/uploadComplete", json=request_data, headers={"X-API-Key": BadManiac.BM_KEY})
        except requests.RequestException as e:
            return APIConstants.badEnd(str(e))
        
    @staticmethod
    def getDiscordMember(discordId: str) -> ValidatedDict | None:
        try:
            response = requests.get(f"{BadManiac.BM_URL}/member/{discordId}", headers={"X-API-Key": BadManiac.BM_KEY}, timeout=2)
            return ValidatedDict(response.json())
        except:
            return ValidatedDict({})
        
    @staticmethod
    def sendArcadeOnboarding(discordId: str, arcadeId: int):
        arcade = ArcadeData.getArcade(arcadeId)
        if not arcade:
            return APIConstants.badEnd('Unable to load the arcade!')
        
        arcadeData = arcade.get("data", {})
        requestData = {
            "discordId": discordId,
            "arcade": {
                "id": arcade.get("id"),
                "name": arcade.get("name"),
                "description": arcade.get("description"),
                "paseli": bool(arcadeData.get("paseli_enabled", False)),
                "infinitePaseli": bool(arcadeData.get("paseli_infinite", False)),
                "maintenance": bool(arcadeData.get("maint", False)),
                "betas": bool(arcadeData.get("is_beta", False)),
                "incognito": bool(arcadeData.get("hide_network", False)),
                "machineList": MachineData.getArcadeMachines(arcadeId)
            }
        }

        try:
            requests.post(f"{BadManiac.BM_URL}/onboardArcade", json=requestData, headers={"X-API-Key": BadManiac.BM_KEY})
            return None
        except requests.RequestException as e:
            return APIConstants.badEnd(str(e))
        
    @staticmethod
    def sendArcadeVPN(discordId: str, arcadeId: int):
        arcade = ArcadeData.getArcade(arcadeId)
        if not arcade:
            return APIConstants.badEnd('Unable to load the arcade!')

        arcadeConfig = PFSense.export_vpn_profile(arcade)
        if not arcadeConfig:
            return APIConstants.badEnd("Failed to generate VPN profile!")

        fileContent = ''.join(list(arcadeConfig[0])).encode('utf-8')
        fileName = f"gradius-{arcadeConfig[1]}-phaseii-config.ovpn"
        files = {
            'vpnFile': (fileName, BytesIO(fileContent), 'text/plain')
        }

        try:
            requests.post(f"{BadManiac.BM_URL}/sendVPNProfile/{discordId}", files=files, headers={"X-API-Key": BadManiac.BM_KEY})
            return None
        except requests.RequestException as e:
            return APIConstants.badEnd(str(e))