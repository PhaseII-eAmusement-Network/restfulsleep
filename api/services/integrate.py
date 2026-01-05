import requests
from flask_restful import Resource
from api.constants import APIConstants
from api.precheck import RequestPreCheck
from api.data.endpoints.user import UserData
from api.external.badmaniac import BadManiac

class Integrations:
    DISCORD_CONFIG = {}
    TACHI_CONFIG = {}

    @classmethod
    def updateConfig(self, discord_config: dict, tachi_config: dict) -> None:
        Integrations.DISCORD_CONFIG = discord_config
        Integrations.TACHI_CONFIG = tachi_config

class IntegrateDiscord(Resource):
    def post(self):
        '''
        Callback for discord integration. Redirects to URL set in config.
        '''
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        config = Integrations.DISCORD_CONFIG
        if not config:
            return APIConstants.badEnd('Config isn\'t loaded!')
        
        dataState, data = RequestPreCheck.checkData()
        if not dataState:
            return data
        
        userId = session.get('id', 0)
        user = UserData.getUser(int(userId))
        if not user:
            return APIConstants.badEnd('No user found.')
        
        code = data.get('code', None)
        if not code:
            return APIConstants.badEnd('No `code`!')
        
        try:
            auth_token_response = requests.post(config.get('token-url', ''),
                data={
                    "client_id": config.get('client-id', ''),
                    "client_secret": config.get('client-secret', ''),
                    "grant_type": "authorization_code",
                    "redirect_uri": config.get('callback-url', ''),
                    "code": code,
                    "scope": "identify",
                },
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            )
            auth_token_response.raise_for_status()
            auth_token_json = auth_token_response.json()

            if 'error' in auth_token_json:
                return APIConstants.badEnd(f"{auth_token_json.get('error')}, Description: {auth_token_json.get('error_description')}")
            else:
                access_token = auth_token_json.get('access_token', None)
                token_type = auth_token_json.get('token_type', None)

                if access_token:
                    discord_data = requests.get(
                        config.get('data-url', ''),
                        headers={'Authorization': f'{token_type} {access_token}'}
                    )
                    discord_data.raise_for_status()
                    discord_json = discord_data.json()

                    discord_dict = {
                        'linked': True,
                        'id': discord_json.get('id', ''),
                        'username': discord_json.get('username', ''),
                        'avatar': discord_json.get('avatar', '')
                    }
                    update_state = UserData.updateUserData(userId, {'discord': discord_dict})
                    if update_state:
                        BadManiac.send_link_complete(discord_dict.get('id'))

                        return 200
                    else:
                        return APIConstants.badEnd('Failed to save discord!')

        except requests.RequestException as e:
            return APIConstants.badEnd(f"Request failed: {e}")

        return APIConstants.badEnd('Failed to integrate with discord!')
    
    def delete(self):
        '''
        Remove discord.
        '''
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        userId = session.get('id', 0)
        user = UserData.getUser(int(userId))
        if not user:
            return APIConstants.badEnd('No user found.')
        
        update_state = UserData.updateUserData(userId, {'discord': None})
        if update_state:
            return 200
        else:
            return APIConstants.badEnd('Failed to unlink discord!')
        
class IntegrateTachi(Resource):
    def post(self):
        '''
        Callback for tachi integration. Redirects to URL set in config.
        '''
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        config = Integrations.TACHI_CONFIG
        if not config:
            return APIConstants.badEnd('Config isn\'t loaded!')
        
        dataState, data = RequestPreCheck.checkData()
        if not dataState:
            return data
        
        userId = session.get('id', 0)
        user = UserData.getUser(int(userId))
        if not user:
            return APIConstants.badEnd('No user found.')
        
        code = data.get('code', None)
        if not code:
            return APIConstants.badEnd('No `code`!')
        
        try:
            auth_token_response = requests.post(config.get('token-url'), json={
                "client_id": config.get('client-id'),
                "client_secret": config.get('client-secret'),
                "redirect_uri": config.get('callback-url'),
                "grant_type": "authorization_code",
                "code": code
            })
            auth_token_response.raise_for_status()
            auth_token_json = auth_token_response.json()
            auth_token_body = auth_token_json.get('body', None)
            if not auth_token_body: 
                return APIConstants.badEnd('Failed to integrate with tachi!')

            access_token = auth_token_body.get('token', None)
            if access_token:
                tachi_data = requests.get(
                    config.get('user-url'),
                    headers={
                        'authorization': f'Bearer {access_token}'
                    }
                )
                tachi_data.raise_for_status()
                tachi_json = tachi_data.json()
                tachi_body = tachi_json.get('body', {})

                tachi_dict = {
                    'linked': True,
                    'token': access_token,
                    'username': tachi_body.get('username'),
                    'bio': tachi_body.get('about')
                }
                update_state = UserData.updateUserData(userId, {'tachi': tachi_dict})
                if update_state:
                    return 200
                else:
                    return APIConstants.badEnd('Failed to save tachi!')

        except requests.RequestException as e:
            return APIConstants.badEnd(f"Request failed: {e}")

        return APIConstants.badEnd('Failed to integrate with tachi!')
    
    def delete(self):
        '''
        Remove tachi.
        '''
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        userId = session.get('id', 0)
        user = UserData.getUser(int(userId))
        if not user:
            return APIConstants.badEnd('No user found.')
        
        update_state = UserData.updateUserData(userId, {'tachi': None})
        if update_state:
            return 200
        else:
            return APIConstants.badEnd('Failed to unlink tachi!')