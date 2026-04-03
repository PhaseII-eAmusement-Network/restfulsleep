from flask import request
from typing import Tuple
from api.constants import APIConstants, ValidatedDict
from api.data.endpoints.session import SessionData, TokenData
from api.data.endpoints.user import UserData
from api.external.unity import UnityAPI

class RequestPreCheck:
    def getSession() -> Tuple[bool, ValidatedDict]:
        sessionId = request.cookies.get('User-Auth-Key')
        appId = None
        if not sessionId:
            # Attempt to check for a bearer token and app ID
            auth = RequestPreCheck.getAuthorization()
            if auth:
                return auth
            return (False, APIConstants.softEnd('No User-Auth-Key provided!'))
        
        decryptedSession = SessionData.AES.decrypt(sessionId)
        if not decryptedSession:
            return (False, APIConstants.badEnd('Unable to decrypt User-Auth-Key!'))

        session = SessionData.checkSession(decryptedSession)
        if not session or session.get('active') != True:
            return (False, APIConstants.badEnd('No session found!'))

        return (True, session)
    
    def getAuthorization() -> Tuple[bool, ValidatedDict]:
        unityKey = request.headers['X-Unity-Key']
        if unityKey:
            appId = 'unity'
            if unityKey != UnityAPI.UNITY_PSK:
                return (False, APIConstants.softEnd('X-Unity-Key provided is incorrect'))
            
            authorization = request.headers['Authorization']
            if not authorization:
                return (False, APIConstants.softEnd('No Authorization provided!'))
            try:
                bearer, token = authorization.split(' ')
                if bearer != 'Bearer':
                    return (False, APIConstants.softEnd('No Bearer provided!'))
            except Exception as e:
                return (False, APIConstants.badEnd(e))

            try:
                token = SessionData.AES.decrypt(token)
            except Exception as e:
                return (False, APIConstants.badEnd(e))

            tokenData = TokenData.checkToken(token, f"{appId}_token")
            if not tokenData or tokenData.get('active') != True:
                return (False, APIConstants.badEnd('No token found!'))
            tokenData['authorization_token'] = token
            return (True, tokenData)
    
    def checkAdmin(session: ValidatedDict) -> Tuple[bool, ValidatedDict]:
        '''
        Check if a user is an admin. Returns a bool and a response dict.
        '''
        userId = session.get('id', 0)
        user = UserData.getUser(userId)

        if not user.get("admin", False):
            return (False, APIConstants.badEnd('You must have administrative rights.'))
        
        return (True, None)
    
    def checkData(keys: dict[str, type] = {}) -> Tuple[bool, ValidatedDict]:
        '''
        Check if JSON data was sent. If found, return it as a ValidatedDict.

        Optionally can be given a dict of {key: type} to check for specific elements.
        Returns an error for the missing/incorrect keys.
        '''
        data = request.get_json(silent=True)
        if data is None:
            return False, APIConstants.badEnd("No JSON data was sent!")

        data = ValidatedDict(data)

        type_getters = {
            str: data.get_str,
            int: data.get_int,
            bool: data.get_bool,
            bytes: data.get_bytes,
        }

        for key, key_type in keys.items():
            getter = type_getters.get(key_type)
            if getter and getter(key, None) is None:
                try:
                    changed_val = key_type(data.get(key, None))
                    data[key] = changed_val
                except:
                    return False, APIConstants.badEnd(f"`{key}` type {key_type.__name__} not found!\nFailed to find and convert type.")

        return True, data
    
    def checkArgs(keys: dict[str, type] = {}) -> Tuple[bool, ValidatedDict]:
        '''
        Check if args were sent. If found, return them as a ValidatedDict.

        Optionally can be given a dict of {key: type} to check for specific elements.
        Returns an error for the missing/incorrect keys.
        '''
        data = request.args
        if data is None:
            return False, APIConstants.badEnd("No args sent!")

        data = ValidatedDict(data)

        type_getters = {
            str: data.get_str,
            int: data.get_int,
            bool: data.get_bool,
            bytes: data.get_bytes,
        }

        for key, key_type in keys.items():
            getter = type_getters.get(key_type)
            if getter and getter(key, None) is None:
                try:
                    changed_val = key_type(data.get(key, None))
                    data[key] = changed_val
                except:
                    return False, APIConstants.badEnd(f"`{key}` type {key_type.__name__} not found!\nFailed to find and convert type.")

        return True, data
    