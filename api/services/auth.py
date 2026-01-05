from flask import make_response, request
from flask_restful import Resource
from typing import Dict, Any

from api.constants import APIConstants
from api.precheck import RequestPreCheck
from api.data.endpoints.session import SessionData, KeyData
from api.data.endpoints.user import UserData

from api.external.mailjet import MailjetSMTP

class UserSession(Resource):
    SECURE_COOKIE = True

    @staticmethod
    def updateConfig(flaskConfig: Dict[str, Any]) -> None:
        secure_cookie = flaskConfig.get('secure_cookie', None)
        if secure_cookie == None:
            raise Exception("Failed to initialize auth config.")
        
        UserSession.SECURE_COOKIE = secure_cookie

    def get(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        return {'status': 'success', 'activeSession': session.get_bool('active'), 'userId': session.get_int('id')}
    
    def post(self):
        '''
        Given a user's username and password, validates them, makes a session.
        '''
        dataState, data = RequestPreCheck.checkData({
            'username': str,
            'password': str,
            'remember': bool
        })
        if not dataState:
            return data
        
        username = data.get_str('username')
        password = data.get_str('password')
        remember = data.get_bool('remember')
        if username == '' or password == '':
            return APIConstants.softEnd('No credentials provided.')
        
        user = UserData.getUserByName(username)
        if not user:
            return APIConstants.softEnd('Password incorrect or no user found.')
        userId = user.get_int('id')

        if not UserData.validatePassword(password, userId):
            return APIConstants.softEnd('Password incorrect or no user found.')
        
        sessionAuth = SessionData.createSession(userId, 'userid', (90 * 86400) if remember else 86400)
        encryptedAuth = SessionData.AES.encrypt(sessionAuth)
        
        payload = {'status': 'success', 'userId': userId}
        resp = make_response(payload)
        resp.set_cookie(
            "User-Auth-Key",
            encryptedAuth,
            (90 * 86400) if remember else 86400,
            httponly=True,
            samesite="Strict",
            secure=self.SECURE_COOKIE
        )

        return resp
    
    def delete(self):
        '''
        Given a user's session id, delete it from the db.
        '''        
        session_id = request.cookies.get('User-Auth-Key')
        if session_id:
            decryptedSession = SessionData.AES.decrypt(session_id)
            if not decryptedSession:
                return APIConstants.badEnd('Unable to decrypt User-Auth-Key!')

            SessionData.deleteSession(decryptedSession)
        
        resp = make_response({'status': 'success'})
        resp.set_cookie(
            'User-Auth-Key',
            '',
            expires=0, # immediately expire
            httponly=True,
            samesite="Strict",
            secure=self.SECURE_COOKIE
        )
        return resp
    
class emailAuth(Resource):
    def post(self):
        '''
        Given a user's email, validates it, makes a key.
        '''
        dataState, data = RequestPreCheck.checkData({
            'email': str
        })
        if not dataState:
            return data
        
        email = data.get_str('email')
        if email == '':
            return APIConstants.softEnd('No email provided.')
        
        user = UserData.getUserByEmail(email)
        if not user:
            return APIConstants.softEnd('No user found.')
        
        if user.get_bool('banned'):
            return APIConstants.badEnd('You\'re banned.')
        
        authKey = KeyData.createKey(user.get_int('id'), 'auth_key')
        errorState = MailjetSMTP().sendAuthKey(user.get_str('email'), authKey)
        if errorState:
            return APIConstants.badEnd(errorState)

        return {'status': 'success'}
    
class check2FAKey(Resource):
    def post(self):
        '''
        Given a user's key, validates it, lets user reset password.
        '''
        dataState, data = RequestPreCheck.checkData({
            'key': str
        })
        if not dataState:
            return data
        
        key = data.get_str('key')

        if len(key) != 6:
            return APIConstants.badEnd('Incorrect key length.')
        
        key_status = KeyData.checkKey(key, 'auth_key')
        if not key_status.get_bool('active'):
            return APIConstants.badEnd('No key found.')
        
        user = UserData.getUser(key_status.get_int('id'))
        if not user:
            return APIConstants.badEnd('No user found.')
        
        if user.get_bool('banned'):
            return APIConstants.badEnd('You\'re still banned.')
    
        return {'status': 'success', 'username': user.get('username')}
    
class resetPassword(Resource):
    def post(self):
        '''
        Given a user's key, validates it, changes password.
        '''
        dataState, data = RequestPreCheck.checkData({
            'key': str, 
            'newPassword': str,
            'confirmPassword': str,
        })
        if not dataState:
            return data
        
        key = data.get_str('key')
        
        newPassword = data.get_str('newPassword')
        if newPassword == '':
            return APIConstants.badEnd('No password provided.')
        
        confirmPassword = data.get_str('confirmPassword')
        if confirmPassword == '':
            return APIConstants.badEnd('No password confirmation provided.')
        
        if len(newPassword) < 8:
            return APIConstants.softEnd('Password must be at least 8 characters!')
        
        if newPassword != confirmPassword:
            return APIConstants.softEnd('The passwords don\'t match!')

        if len(key) != 6:
            return APIConstants.badEnd('Bad key format.')
        
        key_status = KeyData.checkKey(key, 'auth_key')
        if not key_status.get_bool('active'):
            return APIConstants.badEnd('No key found.')
        
        user = UserData.getUser(key_status.get_int('id'))
        if not user:
            return APIConstants.badEnd('No user found.')
        
        if user.get_bool('banned'):
            return APIConstants.badEnd('You\'re still banned.')
        
        KeyData.deleteKey(key, 'auth_key')
        if UserData.updatePassword(user.get_int('id'), newPassword) == True:
            errorState = MailjetSMTP().passwordChanged(user.get_str('email'))
            if errorState:
                return APIConstants.badEnd(errorState)

            return {'status': 'success'}
        else:
            return APIConstants.badEnd('Failed to reset!')