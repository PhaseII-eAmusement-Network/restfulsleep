from flask import make_response, request
from flask_restful import Resource
from typing import Dict, Any

from api.constants import APIConstants, AppIntents
from api.precheck import RequestPreCheck
from api.data.endpoints.session import SessionData, KeyData, TokenData
from api.data.endpoints.user import UserData

from api.external.mailjet import MailjetSMTP
from api.external.unity import UnityAPI
from api.external.badmaniac import BadManiac

class OAuthClient(Resource):
    def get(self, clientId: str):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        if clientId == UnityAPI.UNITY_APP_ID:
            return {'status': 'success', 'data': {
                'internal': True,
                'callbackUrl': UnityAPI.UNITY_CALLBACK_URL,
            }}
        
        appState, app = UnityAPI.get_app_from_id(clientId)
        if not appState:
            return app
        
        appData = app.get_dict('data')
        app['callbackUrl'] = appData.get_str('callbackUri')
        return APIConstants.goodEnd(app)
    
    def post(self, clientId: str):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        if clientId == UnityAPI.UNITY_APP_ID:
            code = KeyData.createKey(session.get_int('id'), 'oauth_unity_code', length=15)
            return APIConstants.goodEnd({'code': code})

        appState, app = UnityAPI.get_app_from_id(clientId)
        if not appState:
            return app
        code = KeyData.createKey(session.get_int('id'), f'oauth_{app.get_str('oauthId')}_code', length=15)
        if code == None:
            return APIConstants.badEnd("Failed to create code")

        return APIConstants.goodEnd({'code': code})

class OAuthToken(Resource):
    DEVELOPER_ROLE = 798959859143147531 # Eventually, I'll replace this with proper developer support in the backend.
    def post(self, clientId: str):        
        dataState, data = RequestPreCheck.checkData({
            'code': str,
        })
        if not dataState:
            return data
        
        auth, authData = RequestPreCheck.getAuthorization(noBearer=True)
        if not auth:
            return authData
        intentBits = authData.get('intents', 0)
        
        if clientId == UnityAPI.UNITY_APP_ID:
            appName = "Unity"
            intentBits = AppIntents.maxIntents()
        else:
            appState, app = UnityAPI.get_app_from_id(clientId)
            if not appState:
                return app
            appName = app.get_str('name')

        if not AppIntents.hasIntents(intentBits, read_user=True, update_user=True):
            return APIConstants.badEnd('unauthorized! Please enable `read_user` and `update_user`')
        
        code = data.get_str('code')
        if len(code) != 15:
            return APIConstants.badEnd('Bad code format.')
        try:
            code = int(code)
        except:
            return APIConstants.badEnd('code is not int compatible!')
        
        code_status = KeyData.checkKey(code, f'oauth_{clientId}_code')
        if not code_status.get_bool('active'):
            return APIConstants.badEnd('No matching code found.')
        
        user = UserData.getUser(code_status.get_int('id'))
        if not user:
            return APIConstants.badEnd('No user found.')
        
        if user.get_bool('banned'):
            return APIConstants.badEnd('User is banned.')
        
        if clientId == UnityAPI.UNITY_APP_ID and not user.get_bool('admin'):
            userData = user.get_dict('data')
            discordLink = userData.get_dict('discord')
            if discordLink.get_bool('linked'):
                member = BadManiac.getDiscordMember(discordLink.get_str('id'))
                roles = member.get('roles', None)
                if not roles:
                    return APIConstants.badEnd('User isn\'t verified')
                
                if not str(self.DEVELOPER_ROLE) in roles:
                    return APIConstants.badEnd('You must have the developer role to proceed')
            else:
                return APIConstants.badEnd("Authorization for Unity requires that you're an admin or a developer. Currently, you must link Discord to proceed with Unity")
        
        KeyData.deleteKey(code, f'oauth_{clientId}_code')
        token = TokenData.createToken(user.get_int('id'), f'{clientId}_token', 15724800) # 6 month token life
        encryptedToken = SessionData.AES.encrypt(token)

        error_state = MailjetSMTP().oAuthUsed(user.get_str('email'), appName)
        if error_state:
            return APIConstants.badEnd(error_state)
        return APIConstants.goodEnd({'userId': user.get_int('id'), 'token': encryptedToken})
    
    def delete(self, clientId: str):
        sessionState, session = RequestPreCheck.getSession(allowApi=True)
        if not sessionState:
            return session

        if clientId != UnityAPI.UNITY_APP_ID:
            appState, app = UnityAPI.get_app_from_id(clientId)
            if not appState:
                return app
        
        tokenState, tokenData = RequestPreCheck.getAuthorization()
        if not tokenState:
            return tokenData

        TokenData.deleteToken(tokenData['authorization_token'], f'{clientId}_token')
        return APIConstants.goodEnd({})
