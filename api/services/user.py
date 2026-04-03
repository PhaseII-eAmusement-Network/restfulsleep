from flask import request
from flask_restful import Resource

from api.constants import APIConstants, ValidatedDict
from api.precheck import RequestPreCheck
from api.data.card import CardCipher
from api.data.endpoints.session import SessionData 
from api.data.endpoints.arcade import ArcadeData
from api.data.endpoints.user import UserData
from api.data.endpoints.profiles import ProfileData
from api.data.endpoints.game import GameData
from api.data.endpoints.score import ScoreData
from api.external.badmaniac import BadManiac

class UserAccount(Resource):
    def get(self):
        '''
        Loads a user's account based on ID or a User Auth Key.
        If given a user ID, only return a user's public info. Otherwise, return everything.
        '''
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        sessionUserId = session.get_int('id')
        sessionUser = UserData.getUser(sessionUserId)

        argsState, args = RequestPreCheck.checkArgs()
        if not argsState:
            return args
        reqUserId = args.get_str('userId', None)
        if not reqUserId:
            reqUserId = sessionUserId
        else:
            try:
                reqUserId = int(reqUserId)
            except:
                return APIConstants.badEnd('Failed to load a userId.')
            
        reqUser = UserData.getUser(reqUserId)
        if not reqUser:
            return APIConstants.badEnd('No user found.')
        
        authUser = True if sessionUserId == reqUserId else False
        if sessionUser.get_bool('admin'):
            authUser = True

        if reqUser.get_bool('banned') and not sessionUser.get_bool('admin'):
            return APIConstants.badEnd('You\'re banned.' if authUser else 'This user is banned.')
        
        if not authUser:
            if not reqUser.get_bool('public'):
                return APIConstants.badEnd('This is a private profile.')

        reqUserData = reqUser.get_dict('data')
        discordLink = reqUserData.get_dict('discord')
        backup_avatar = None
        member = None
        if discordLink.get_bool('linked'):
            member = BadManiac.getDiscordMember(discordLink.get_str('id'))
            backup_avatar = f"https://cdn.discordapp.com/avatars/{discordLink.get('id')}/{discordLink.get('avatar')}"

            # Use this chance to update the user's avatar
            if member and member.get_str('avatar'):
                try:
                    avatar_spit = member.get_str('avatar').split('/')
                    avatar_hash = avatar_spit[-1].split('.')[0]
                    if (avatar_hash):
                        UserData.updateUserData(reqUserId, ValidatedDict({'discord': {'avatar': avatar_hash}}))
                except:
                    pass

        profiles = GameData.getUserGameSettings(reqUserId)
        for gameProfile in profiles:
            profile = ProfileData.getProfile(gameProfile.get('game'), None, reqUserId, noData=True)
            if not profile:
                continue

            username = profile.get('username')
            gameProfile.replace_str('username', username)

        arcades = []
        if authUser:
            for arcade in ArcadeData.getUserArcades(reqUserId):
                arcades.append({
                    'id': arcade,
                    'name': ArcadeData.getArcadeName(arcade)
                })
        
        noScores = args.get_str('noScores', None)
        if noScores:
            scoreStats = None
        else:
            scoreStats = ScoreData.getUserStats(reqUserId)

        return {
            'status': 'success',
            'data': {
                'id': reqUser.get_int('id'),
                'name': reqUser.get_str('username'),
                'email': reqUser.get_str('email') if authUser else None,
                'admin': reqUser.get_bool('admin'),
                'banned': reqUser.get_bool('banned'),
                'public': reqUser.get_bool('public'),
                'avatar': member.get_str('avatar') if member else backup_avatar,
                'discordRoles': member.get('roles') if member else None,
                'data': reqUser.get_dict('data') if authUser else None,
                'profiles': profiles,
                'arcades': arcades,
                'scoreStats': scoreStats
            }
        }
    
    def post(self):
        '''
        Given new user params, save them.
        '''
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        dataState, data = RequestPreCheck.checkData()
        if not dataState:
            return data
        
        userId = session.get('id', 0)
        username = None
        email = None
        pin = None
        public = None

        if data.get('username', None):
            try:
                username = str(data.get('username', None))
            except:
                return APIConstants.badEnd('Invalid username!')
            
            existingUser = UserData.getUserByName(username)
            if existingUser and existingUser.get('id') != userId:
                return APIConstants.badEnd('Username already taken.')

        if data.get('email', None):
            try:
                email = str(data.get('email', None))
            except:
                return APIConstants.badEnd('Invalid email!')

            splitEmail = email.split('@')
            if len(splitEmail) != 2:
                return APIConstants.badEnd('Invalid email!')
            
            if len(splitEmail[1].split('.')) != 2:
                return APIConstants.badEnd('Invalid email!')

        if data.get('pin', None):
            try:
                pin = str(data.get('pin', None))
            except:
                return APIConstants.badEnd('Invalid pin!')
            
            if len(pin) != 4 and len(pin) != 0:
                return APIConstants.badEnd('PIN must be 4 characters!')
            
            if len(pin) == 0:
                pin = None # If it's an empty string, we'll just forget it.

        if data.get('public', None) != None:
            try:
                public = bool(data.get('public', False))
            except:
                return APIConstants.badEnd('Invalid public!')
            
        if UserData.updateUser(userId, username, email, pin, public):
            return {'status': 'success'}

        return APIConstants.badEnd('Failed to save!')
    
    def put(self):
        '''
        Register a new user
        '''
        dataState, data = RequestPreCheck.checkData()
        if not dataState:
            return data

        username = None
        email = None
        newPassword = None
        confirmPassword = None
        pin = None
        cardId = None

        if data.get('username', None):
            try:
                username = str(data.get('username', None))
            except:
                return APIConstants.badEnd('Invalid username!')
            
            existingUser = UserData.getUserByName(username)
            if existingUser:
                return APIConstants.softEnd('Username already taken.')
        else:
            return APIConstants.badEnd('No username provided!')

        if data.get('email', None):
            try:
                email = str(data.get('email', None))
            except:
                return APIConstants.badEnd('Invalid email!')

            splitEmail = email.split('@')
            if len(splitEmail) != 2:
                return APIConstants.badEnd('Invalid email!')
            
            if len(splitEmail[1].split('.')) != 2:
                return APIConstants.badEnd('Invalid email!')
        else:
            return APIConstants.badEnd('No email provided!')
            
        if data.get('newPassword', None):
            try:
                newPassword = str(data.get('newPassword', None))
            except:
                return APIConstants.badEnd('Invalid newPassword.')
        else:
            return APIConstants.badEnd('No newPassword provided!')
            
        if data.get('confirmPassword', None):
            try:
                confirmPassword = str(data.get('confirmPassword', None))
            except:
                return APIConstants.badEnd('Invalid confirmPassword.')
        else:
            return APIConstants.badEnd('No confirmPassword provided!')
        
        if len(str(newPassword)) < 8:
            return APIConstants.softEnd('Password must be at least 8 characters!')
        
        if newPassword != confirmPassword:
            return APIConstants.softEnd('The passwords don\'t match!')

        if data.get('pin', None):
            try:
                pin = str(data.get('pin', None))
            except:
                return APIConstants.badEnd('Invalid pin!')
            
            try:
                int(data.get('pin', None))
            except:
                return APIConstants.badEnd('Invalid pin!')
            
            if len(pin) != 4:
                return APIConstants.badEnd('PIN must be 4 characters!')
        else:
            return APIConstants.badEnd('No pin provided!')
        
        if data.get('cardId', None):
            try:
                cardId = str(data.get('cardId', None))
            except:
                return APIConstants.badEnd('Invalid cardId.')
        else:
            return APIConstants.badEnd('No cardId provided!')
        
        try:
            cardId = CardCipher.decode(cardId)
        except:
            return APIConstants.softEnd('Bad cardId encoding!')
        
        userId = UserData.cardExist(cardId)
        if not userId:
            return APIConstants.softEnd('Card is unused!\nPlease play a game to begin registration.')
        
        user = UserData.getUser(userId)
        if not user:
            return APIConstants.badEnd('No user found.')
        
        if user.get('username', None):
            return APIConstants.softEnd('User account is already claimed.')
        
        if not UserData.checkUserPin(userId, pin):
            return APIConstants.softEnd('PIN mismatch!')

        if not UserData.updateUser(userId, username, email, pin):
            return APIConstants.badEnd('Failed to update user.')
        
        if not UserData.updatePassword(userId, newPassword):
            return APIConstants.badEnd('Failed to update password!')

        return {'status': 'success'}

class UserUpdatePassword(Resource):
    def post(self):
        '''
        Validate user, changes password.
        '''
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        dataState, data = RequestPreCheck.checkData()
        if not dataState:
            return data
        
        userId = session.get('id', 0)

        currentPassword = data.get('currentPassword', None)
        if currentPassword == None:
            return APIConstants.badEnd('No currentPassword provided.')
        
        if not UserData.validatePassword(currentPassword, userId):
            return APIConstants.softEnd('Password incorrect.')
        
        newPassword = data.get('newPassword', None)
        if newPassword == None:
            return APIConstants.badEnd('No newPassword provided.')
        
        confirmPassword = data.get('confirmPassword', None)
        if confirmPassword == None:
            return APIConstants.badEnd('No confirmPassword confirmation provided.')
        
        if len(str(newPassword)) < 8:
            return APIConstants.softEnd('Password must be at least 8 characters!')
        
        if newPassword != confirmPassword:
            return APIConstants.softEnd('The passwords don\'t match!')
        
        user = UserData.getUser(userId)
        if not user:
            return APIConstants.badEnd('No user found.')
        
        if user.get('banned', False):
            return APIConstants.badEnd('You\'re banned.')

        if UserData.updatePassword(user.get('id', 0), newPassword) == True:
            return {'status': 'success'}
        else:
            return APIConstants.badEnd('Failed to update password!')
    
class UserCard(Resource):
    '''
    Handle loading, creation, and deletion of a user's cards. Requires the auth header for a user.
    '''
    def get(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        userId = session.get('id', 0)

        cards = UserData.getCards(int(userId))
        if not cards:
            return APIConstants.badEnd('No cards found.')
        
        returnCards = []
        for card in cards:
            returnCards.append({
                'id': card,
                'encoded': CardCipher.encode(card)
            })

        return {
            'status': 'success',
            'cards': returnCards
        }
    
    def post(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        dataState, data = RequestPreCheck.checkData()
        if not dataState:
            return data
        
        cardId = data.get('cardId', None)
        if cardId == None:
            return APIConstants.badEnd('No cardId provided.')
        
        try:
            cardId = CardCipher.decode(cardId)
        except:
            return APIConstants.softEnd('Bad encoding!')
        
        if UserData.cardExist(cardId):
            return APIConstants.softEnd('Card in use!')
        
        userId = session.get('id', 0)
        if not UserData.putCard(userId, cardId):
            return APIConstants.badEnd('Failed to add!')
        
        return {'status': 'success'}
    
    def delete(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        dataState, data = RequestPreCheck.checkData()
        if not dataState:
            return data
        
        cardId = data.get('cardId', None)
        if cardId == None:
            return APIConstants.badEnd('No cardId provided.')
        
        try:
            cardId = CardCipher.decode(cardId)
        except:
            return APIConstants.softEnd('Bad encoding!')
        
        userId = session.get('id', 0)
        if not UserData.deleteCard(userId, cardId):
            return APIConstants.badEnd('Failed to delete!')
        
        return {'status': 'success'}
    
class UserTakeover(Resource):
    '''
    Claim an already used card. Transfers user data into account
    '''
    
    def get(self):
        '''
        Get account information, check if new card is actually unregistered.
        '''
        userId = None
        sessionState, session = RequestPreCheck.getSession()
        if sessionState:
            userId = session.get('id', None)

        if not userId:
            return APIConstants.badEnd('Bad session!')

        pin = None
        cardId = None

        if request.args.get('pin', None):
            try:
                pin = str(request.args.get('pin', None))
            except:
                return APIConstants.badEnd('Invalid pin!')
            
            try:
                int(request.args.get('pin', None))
            except:
                return APIConstants.badEnd('Invalid pin!')
            
            if len(pin) != 4:
                return APIConstants.badEnd('PIN must be 4 characters!')
        else:
            return APIConstants.badEnd('No pin provided!')
        
        if request.args.get('cardId', None):
            try:
                cardId = str(request.args.get('cardId', None))
            except:
                return APIConstants.badEnd('Invalid cardId.')
        else:
            return APIConstants.badEnd('No cardId provided!')
        
        try:
            cardId = CardCipher.decode(cardId)
        except:
            return APIConstants.softEnd('Bad cardId encoding!')

        user = UserData.getUser(userId)
        if not user:
            return APIConstants.badEnd('No user found.')
        
        claimUserId = UserData.cardExist(cardId)
        if not claimUserId:
            return APIConstants.softEnd('Card is unused!')
        
        claimUser = UserData.getUser(claimUserId)
        if not claimUser:
            return APIConstants.badEnd('No user found.')
        
        if claimUser.get('username', None):
            return APIConstants.softEnd('User account is already claimed.')
        
        if not UserData.checkUserPin(claimUserId, pin):
            return APIConstants.softEnd('PIN mismatch!')
        
        profiles = GameData.getUserGameSettings(claimUserId)

        return {'status': 'success', 'data': {'userId': claimUserId, 'profiles': profiles}}
    
    def post(self):
        '''
        Claim an already used card. Transfers user data into account
        '''
        dataState, data = RequestPreCheck.checkData()
        if not dataState:
            return data
        
        userId = None
        sessionState, session = RequestPreCheck.getSession()
        if sessionState:
            userId = session.get('id', None)

        pin = None
        cardId = None

        if data.get('pin', None):
            try:
                pin = str(data.get('pin', None))
            except:
                return APIConstants.badEnd('Invalid pin!')
            
            try:
                int(data.get('pin', None))
            except:
                return APIConstants.badEnd('Invalid pin!')
            
            if len(pin) != 4:
                return APIConstants.badEnd('PIN must be 4 characters!')
        else:
            return APIConstants.badEnd('No pin provided!')
        
        if data.get('cardId', None):
            try:
                cardId = str(data.get('cardId', None))
            except:
                return APIConstants.badEnd('Invalid cardId.')
        else:
            return APIConstants.badEnd('No cardId provided!')
        
        try:
            cardId = CardCipher.decode(cardId)
        except:
            return APIConstants.softEnd('Bad cardId encoding!')
        
        if data.get('mergeSettings', None):
            try:
                mergeSettings = dict(data.get('mergeSettings'))
            except:
                return APIConstants.badEnd('Invalid merge data!')
        else:
            return APIConstants.badEnd('No mergeSettings provided!')
        
        claimUserId = UserData.cardExist(cardId)
        if not claimUserId:
            return APIConstants.softEnd('Card is unused!\nPlease play a game to begin registration.')
        
        user = UserData.getUser(claimUserId)
        if not user:
            return APIConstants.badEnd('No user found.')
        
        if user.get('username', None):
            return APIConstants.softEnd('User account is already claimed.')
        
        if not UserData.checkUserPin(claimUserId, pin):
            return APIConstants.softEnd('PIN mismatch!')
        
        recordsCount = 0
        for game in mergeSettings:
            if game == 'card':
               UserData.transferCard(claimUserId, userId, cardId)

            else:
                gameSettings = mergeSettings[game]
                if gameSettings.get('scores'):
                    try:
                        recordsCount += ScoreData.transferUserRecords(game, claimUserId, userId)
                    except Exception as e:
                        return APIConstants.badEnd("Failed to transfer scores")

        return {'status': 'success', 'count': recordsCount}

class UserPlayVideos(Resource):
    '''
    Handle loading, and deletion of a user's play videos. Requires the auth header for a user.
    '''
    def get(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        userId = session.get('id', 0)

        playVideos = UserData.getUserPlayVideos(int(userId))

        return {
            'status': 'success',
            'data': playVideos
        }
    
class UserContent(Resource):
    '''
    Handle loading, and deletion of a user's content. Requires the auth header for a user.
    '''
    def get(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        if request.args.get('type', None):
            try:
                contentType = str(request.args.get('type', None))
            except:
                return APIConstants.badEnd('Invalid type!')
        
        userId = session.get('id', 0)

        userContent = UserData.getAllUserContent(int(userId), contentType)

        return {
            'status': 'success',
            'data': userContent
        }

class UserCustomize(Resource):
    '''
    Handle updating user preferences for customization.
    '''
    def post(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        session = ValidatedDict(session)
        
        dataState, data = RequestPreCheck.checkData({'customize': dict})
        if not dataState:
            return data
        data = ValidatedDict(data)
        
        userId = session.get_int('id')
        user = UserData.getUser(userId)
        if not user:
            return APIConstants.badEnd('No user found.')
        
        customize = data.get_dict('customize')
        update_state = UserData.updateUserData(userId, {'customize': customize})
        if update_state:
            return {'status': 'success'}

        return APIConstants.badEnd('Failed to update customization!')
    
class UserAppVersion(Resource):
    '''
    Handle updating user preferences for update popups.
    '''
    def post(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        session = ValidatedDict(session)
        
        dataState, data = RequestPreCheck.checkData({'version': str, 'disable': bool})
        if not dataState:
            return data
        data = ValidatedDict(data)
        
        userId = session.get_int('id')
        user = UserData.getUser(userId)
        if not user:
            return APIConstants.badEnd('No user found.')
        
        version = data.get_str('version')
        disable = data.get_bool('disable')

        webVersions = user.get_dict('data').get('webVersions', [])
        webVersions.append(version)

        update_state = UserData.updateUserData(userId, {'webVersions': webVersions, 'disableUpdateModal': disable})
        if update_state:
            return {'status': 'success'}

        return APIConstants.badEnd('Failed to update!')

class UserOnboard(Resource):
    '''
    Handle updating onboarding data
    '''
    def post(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        session = ValidatedDict(session)

        dataState, data = RequestPreCheck.checkData({'version': str, 'disable': bool})
        if not dataState:
            return data
        data = ValidatedDict(data)
        
        userId = session.get_int('id')
        user = UserData.getUser(userId)
        if not user:
            return APIConstants.badEnd('No user found.')
        
        # Any web version data before this is from beta, we shall move it to a new dict.
        # We will also add the current version into the new data.
        webVersionsBeta = user.get_dict('data').get('webVersions', [])
        version = data.get_str('version')
        webVersions = [version]

        update_state = UserData.updateUserData(userId, {'webVersions': webVersions, 'webVersionsBeta': webVersionsBeta, 'onboardingComplete': True})
        if update_state:
            return {'status': 'success'}

        return APIConstants.badEnd('Failed to update!')
    
class UserReadNews(Resource):
    '''
    Handle updating user news states.
    '''
    def post(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        session = ValidatedDict(session)
        
        dataState, data = RequestPreCheck.checkData({'newsId': int})
        if not dataState:
            return data
        data = ValidatedDict(data)
        
        userId = session.get_int('id')
        user = UserData.getUser(userId)
        if not user:
            return APIConstants.badEnd('No user found.')
        
        newsId = data.get_int('newsId')

        seenNews = user.get_dict('data').get_dict('seen_news')
        seenNews[str(newsId)] = True

        update_state = UserData.updateUserData(userId, {'seen_news': seenNews})
        if update_state:
            return {'status': 'success'}

        return APIConstants.badEnd('Failed to update!')

class UserSessions(Resource):
    '''
    Handle user sessions.
    '''
    def get(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        session = ValidatedDict(session)
        
        userId = session.get_int('id')

        try:
            sessions = SessionData.getAllSessions(userId)
            return {'status': 'success', 'data': sessions}
        except:
            return APIConstants.badEnd('Failed to load sessions')
        
    def delete(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        session = ValidatedDict(session)
        
        userId = session.get_int('id')

        try:
            SessionData.deleteAllSessions(userId)
            return {'status': 'success'}
        except:
            return APIConstants.badEnd('Failed to delete sessions')
