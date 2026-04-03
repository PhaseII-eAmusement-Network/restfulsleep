from flask import make_response, request
from flask_restful import Resource
from typing import Dict, Any

from api.constants import APIConstants
from api.precheck import RequestPreCheck
from api.data.endpoints.session import SessionData, KeyData, TokenData
from api.data.endpoints.user import UserData

from api.external.mailjet import MailjetSMTP
from api.external.unity import UnityAPI

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
        
        return APIConstants.badEnd('Failed to find application')
    
    def post(self, clientId: str):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        if clientId == UnityAPI.UNITY_APP_ID:
            code = KeyData.createKey(session.get_int('id'), 'oauth_code', length=15)
            return {'status': 'success', 'data': {'code': code}}
        
        return APIConstants.badEnd('Failed to find application and generate key')

class OAuthToken(Resource):
    def post(self, clientId: str):        
        dataState, data = RequestPreCheck.checkData({
            'code': str,
        })
        if not dataState:
            return data
        
        if clientId != UnityAPI.UNITY_APP_ID:
            return APIConstants.badEnd('Failed to find application')
        
        code = data.get_str('code')
        if len(code) != 15:
            return APIConstants.badEnd('Bad code format.')
        try:
            code = int(code)
        except:
            return APIConstants.badEnd('code is not int compatible!')
        
        code_status = KeyData.checkKey(code, 'oauth_code')
        if not code_status.get_bool('active'):
            return APIConstants.badEnd('No matching code found.')
        
        user = UserData.getUser(code_status.get_int('id'))
        if not user:
            return APIConstants.badEnd('No user found.')
        
        if user.get_bool('banned'):
            return APIConstants.badEnd('User is banned.')
        
        KeyData.deleteKey(code, 'oauth_code')
        token = TokenData.createToken(user.get_int('id'), f'{clientId}_token', 15724800) # 6 month token life
        encryptedToken = SessionData.AES.encrypt(token)
        
        return APIConstants.goodEnd({'userId': user.get_int('id'), 'token': encryptedToken})
    
    def delete(self, clientId: str):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session

        if clientId != UnityAPI.UNITY_APP_ID:
            return APIConstants.badEnd('Failed to find application')
        
        tokenState, tokenData = RequestPreCheck.getAuthorization()
        if not tokenState:
            return tokenData

        TokenData.deleteToken(tokenData['authorization_token'], f'{clientId}_token')
        return APIConstants.goodEnd({})
