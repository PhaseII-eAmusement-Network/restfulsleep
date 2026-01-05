from flask_restful import Resource
from flask import request

from api.constants import APIConstants, ValidatedDict
from api.precheck import RequestPreCheck
from api.data.endpoints.user import UserData
from api.data.endpoints.profiles import ProfileData
from api.data.endpoints.achievements import AchievementData
from api.data.endpoints.game import GameData
from api.data.endpoints.music import MusicData
from api.data.endpoints.links import LinkData

class Profile(Resource):
    def get(self, game: str):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        version = request.args.get('version')
        userId = request.args.get('userId')

        if not userId:
            return APIConstants.badEnd('No userId!')
        
        versions = ProfileData.getVersions(game, userId)
        if not version or version == 'null' and versions:
            version = versions[-1] if len(versions) > 1 else versions[0]

        payload = ValidatedDict()

        profile = ProfileData.getProfile(game, version, userId)
        if not profile:
            return APIConstants.softEnd('No profile found!')


        profile['extid'] = GameData.getUserExtid(game, userId)
        payload['profile'] = profile
        payload['versions'] = versions
        payload['stats'] = GameData.getUserGameStats(game, userId)
        payload['hitChart'] = MusicData.getHitChart(game, version, 10, None, None, userId)

        sessionUserId = session.get_int('id', -1)

        userPublic: ValidatedDict = UserData.public(userId)
        if not userPublic and sessionUserId != userId:
            if not UserData.admin(sessionUserId):
                payload['stats']['arcade_history'] = []

        return {
            'status': 'success',
            'data': payload
        }, 200
    
    def post(self, game: str):
        session: ValidatedDict
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        version = request.args.get('version')
        userId = request.args.get('userId')

        if not userId:
            return APIConstants.badEnd('No userId!')

        sessionUserId = session.get_int('id', -1)
        sessionUser: ValidatedDict = UserData.getUser(sessionUserId)
        if not sessionUser:
            return APIConstants.badEnd('No user found.')
        
        if sessionUserId != int(userId):
            if not sessionUser.get_bool('admin'):
                return APIConstants.badEnd('This isn\'t your profile!')
        
        data = request.json
        if not data:
            return APIConstants.badEnd('No JSON data sent!')
        
        profile = ProfileData.getProfile(game, version, userId)
        if not profile:
            return APIConstants.softEnd('No profile found!')

        error_code = ProfileData.updateProfile(game, version, userId, data)
        if error_code:
            return APIConstants.badEnd(error_code)
        
        return {
            'status': 'success'
        }, 200
    
class Achievements(Resource):
    def get(self, game: str):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        args = ValidatedDict(request.args)

        version = int(args.get_str('version'))
        userId = int(args.get_str('userId'))
        header_value = request.headers.get('achievements', None)

        try:
            if header_value:
                achievements = [
                    (name, int(score)) for name, score in 
                    (item.split(':') for item in header_value.split(','))
                ]
            else:
                achievements = []
        except Exception as e:
            return APIConstants.badEnd(f'`achievements`: {e}')

        if not userId:
            return APIConstants.badEnd('No userId!')
        
        if not achievements:
            return APIConstants.badEnd('`achievements: list[str: int]` needs to be supplied in headers. The format is `achievementType:achievementId,`')
        
        versions = ProfileData.getVersions(game, userId)
        if not version or version == 'null' and versions:
            version = versions[-1] if len(versions) > 1 else versions[0]

        loadedAchievements = []
        try:
            for achievementType, achievementId in achievements:
                achievement = AchievementData.getAchievement(game, version, userId, achievementType, achievementId)
                loadedAchievements.append({
                    'achievementType': achievementType,
                    'achievementId': achievementId,
                    'data': achievement,
                })
        except:
            return APIConstants.badEnd('Failed to parse `achievements: list[str: int]` from headers')
        
        return {
            'status': 'success',
            'data': loadedAchievements
        }, 200

class Links(Resource):
    def get(self, game: str):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        argsState, args = RequestPreCheck.checkArgs({
            'version': str,
            'userId': str,
        })
        if not argsState:
            return args
        
        version = int(args.get_str('version'))
        userId = int(args.get_str('userId'))

        if not userId:
            return APIConstants.badEnd('No userId!')
        
        sessionUserId = session.get_int('id', -1)
        if sessionUserId != int(userId):
            return APIConstants.badEnd('This isn\'t your profile!')
        
        versions = ProfileData.getVersions(game, userId)
        if not version or version == 'null' and versions:
            version = versions[-1] if len(versions) > 1 else versions[0]

        linkData = LinkData.getAllLinks(game, version, userId)
        if linkData:
            for link in linkData:
                otherUserId = link.get_int('otherUserId')
                otherProfile = ProfileData.getProfile(game, version, otherUserId, True)
                link.replace_dict('otherProfileData', {"username": otherProfile.get_str('username')})
        
        return {
            'status': 'success',
            'data': linkData
        }, 200
    
class Link(Resource):
    def put(self, game: str):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        dataState, data = RequestPreCheck.checkData({
            'version': int,
            'userId': int,
            'otherUserId': int,
            'type': str
        })
        if not dataState:
            return data

        version = data.get_int('version')
        userId = data.get_int('userId')
        otherUserId = data.get_int('otherUserId')
        linkType = data.get_str('type')

        if not userId:
            return APIConstants.badEnd('No userId!')
        
        if not otherUserId:
            return APIConstants.badEnd('No otherUserId!')
        
        if not version:
            return APIConstants.badEnd('No version!')
        
        sessionUserId = session.get_int('id', -1)
        if sessionUserId != int(userId):
            return APIConstants.badEnd('This isn\'t your profile!')

        linkState = LinkData.putLink(game, version, userId, otherUserId, linkType)
        if not linkState:
            return APIConstants.badEnd('Failed to put link!')
        
        return {
            'status': 'success',
        }, 200
    
    def delete(self, game: str):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        dataState, data = RequestPreCheck.checkData({
            'version': int,
            'userId': int,
            'otherUserId': int,
            'type': str
        })
        if not dataState:
            return data

        version = data.get_int('version')
        userId = data.get_int('userId')
        otherUserId = data.get_int('otherUserId')
        linkType = data.get_str('type')

        if not userId:
            return APIConstants.badEnd('No userId!')
        
        if not otherUserId:
            return APIConstants.badEnd('No otherUserId!')
        
        if not version:
            return APIConstants.badEnd('No version!')
        
        sessionUserId = session.get_int('id', -1)
        if sessionUserId != int(userId):
            return APIConstants.badEnd('This isn\'t your profile!')

        linkState = LinkData.deleteLink(game, version, userId, otherUserId, linkType)
        if not linkState:
            return APIConstants.badEnd('Failed to delete link!')
        
        return {
            'status': 'success',
        }, 200
    