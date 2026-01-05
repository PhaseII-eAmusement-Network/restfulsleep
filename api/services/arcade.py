from flask_restful import Resource
from flask import Response, request

from api.constants import APIConstants
from api.precheck import RequestPreCheck
from api.data.card import CardCipher
from api.data.endpoints.arcade import ArcadeData
from api.data.endpoints.machine import MachineData
from api.data.endpoints.paseli import PaseliData
from api.data.endpoints.user import UserData
from api.external.pfsense import PFSense

class Arcade(Resource):
    '''
    Handle loading, creation, and updating of an arcade.
    Requires a valid user session and that a user owns an arcade (or if user is admin).
    '''
    def get(self, arcadeId: int):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        userId = session.get_int('id')
        authUser = True
        if not ArcadeData.checkOwnership(userId, arcadeId):
            authUser = False
        
        arcade = ArcadeData.getArcade(arcadeId)
        if not arcade:
            return APIConstants.badEnd('Unable to load the arcade!')
        
        if authUser:
            filteredOwners = []
            owners = ArcadeData.getArcadeOwners(arcadeId)
            for owner in owners:
                ownerData = UserData.getUser(owner)
                if ownerData is not None:
                    data = ownerData.get_dict('data')
                    discordLink = data.get_dict('discord')
                    avatar = None
                    if discordLink.get_bool('linked'):
                        avatar = f"https://cdn.discordapp.com/avatars/{discordLink.get_str('id')}/{discordLink.get_str('avatar')}"
                    ownerData['email'] = None
                    ownerData['data'] = None
                    ownerData['avatar'] = avatar
                    filteredOwners.append(ownerData)

            arcade['owners'] = filteredOwners
            arcade['machines'] = MachineData.getArcadeMachines(arcadeId)
        
        return {'status': 'success', 'arcade': arcade if authUser else {'name': arcade.get_str('name'), 'description': arcade.get_str('description')}}
    
    def post(self, arcadeId: int):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        userId = session.get_int('id')
        if not ArcadeData.checkOwnership(userId, arcadeId):
            return APIConstants.badEnd('You don\'t have access to this arcade!')
        
        arcade = ArcadeData.getArcade(arcadeId)
        if not arcade:
            return APIConstants.badEnd('Unable to load the arcade!')
        
        dataState, data = RequestPreCheck.checkData()
        if not dataState:
            return data

        error_code = ArcadeData.updateArcadeData(arcadeId, data)
        if error_code:
            return APIConstants.badEnd(error_code)
        
        return {
            'status': 'success'
        }, 200
    
class ArcadeSettings(Resource):
    '''
    Handle loading, creation, and updating of game event settings for an arcade.
    Requires a valid user session and that a user owns an arcade (or if user is admin) for updating.
    '''
    def get(self, arcadeId: int):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        argsState, args = RequestPreCheck.checkArgs({
            'game': str,
            'version': int,
        })
        if not argsState:
            return args
        
        userId = session.get_int('id')
        authUser = True
        if not ArcadeData.checkOwnership(userId, arcadeId):
            authUser = False
        
        arcade = ArcadeData.getArcade(arcadeId)
        if not arcade:
            return APIConstants.badEnd('Unable to load the arcade!')
        
        game = args.get_str('game')
        version = args.get_int('version')
        if authUser:
            arcade_settings = ArcadeData.getArcadeSettings(arcadeId, game, version, 'game_config')
            return {'status': 'success', 'data': arcade_settings if arcade_settings else {}}
        
        return APIConstants.badEnd('Unauthorized.')
    
    def post(self, arcadeId: int):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        argsState, args = RequestPreCheck.checkArgs({
            'game': str,
            'version': int,
        })
        if not argsState:
            return args

        dataState, data = RequestPreCheck.checkData()
        if not dataState:
            return data
        
        userId = session.get_int('id')
        if not ArcadeData.checkOwnership(userId, arcadeId):
            return APIConstants.badEnd('Unauthorized.')
        
        arcade = ArcadeData.getArcade(arcadeId)
        if not arcade:
            return APIConstants.badEnd('Unable to load the arcade!')
        
        game = args.get_str('game')
        version = args.get_int('version')
        update_state = ArcadeData.updateArcadeSettings(arcadeId, game, version, 'game_config', data)
        if update_state:
            return APIConstants.badEnd(update_state)

        return {'status': 'success'}
    
class VPN(Resource):
    '''
    Handle exporting of an arcade's VPN profile.
    Requires a valid user session and that a user owns an arcade (or if user is admin).
    '''
    def get(self, arcadeId: int):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        userId = session.get_int('id')
        if not ArcadeData.checkOwnership(userId, arcadeId):
            return APIConstants.badEnd('You don\'t own this arcade or it doesn\'t exist!')
        
        arcade = ArcadeData.getArcade(arcadeId)
        if not arcade:
            return APIConstants.badEnd('Unable to load the arcade!')

        arcade_config = PFSense.export_vpn_profile(arcade)
        
        if arcade_config:
            return Response(
                arcade_config[0],
                mimetype="text/plain",
                headers={"Content-Disposition": f"attachment;filename=gradius-{arcade_config[1]}-phaseii-config.ovpn"}
            )
        else:
            return APIConstants.badEnd('Failed to export!')
    
class Paseli(Resource):
    '''
    Handle loading and updating of PASELI information.
    '''
    def get(self, arcadeId: int):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        userId = session.get_int('id')
        if not ArcadeData.checkOwnership(userId, arcadeId):
            return APIConstants.badEnd('You don\'t own this arcade or it doesn\'t exist!')
        
        returnData = {}
        balances = PaseliData.getArcadeBalances(arcadeId)
        filteredBalances = []
        if balances:
            for balance in balances:
                user = UserData.getUser(balance.get('userId', 0))
                filteredBalances.append({
                    'userId': user.get_int('id'),
                    'username': user.get_str('username'),
                    'balance': balance.get_int('balance')
                })

        returnData['balances'] = filteredBalances

        returnData['transactions'] = []
        transactions = PaseliData.getTransactions(arcadeId)
        if transactions:
            returnData['transactions'] = transactions
        
        return {'status': 'success', 'data': returnData}
    
    def post(self, arcadeId: int):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        userId = session.get_int('id')
        if not ArcadeData.checkOwnership(userId, arcadeId):
            return APIConstants.badEnd('You don\'t own this arcade or it doesn\'t exist!')
        
        dataState, data = RequestPreCheck.checkData({'cardId': str, 'credit': int})
        if not dataState:
            return data
        
        reqUserId = data.get_int('userId', None)
        if not reqUserId:     
            if data.get_str('cardId', None):
                try:
                    cardId = str(data.get('cardId', None))
                except:
                    return APIConstants.badEnd('Invalid cardId.')
            else:
                return APIConstants.badEnd('No cardId provided!')
            
            try:
                cardId = CardCipher.decode(cardId)
            except:
                try:
                    CardCipher.encode(cardId)
                except:
                    return APIConstants.badEnd('Bad cardId encoding!')

            reqUserId = UserData.cardExist(cardId)

        print(reqUserId)

        reqUser = UserData.getUser(reqUserId)
        if not reqUser:
            return APIConstants.badEnd('No user found.')
        
        PaseliData.putArcadeBalance(arcadeId, reqUserId, data.get_int('credit'))
        PaseliData.putTransaction(arcadeId, reqUserId, data.get_int('credit'))
        
        return {'status': 'success'}
    
class CheckArcadeName(Resource):
    '''
    Check if an arcade name has been taken
    '''
    def get(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        adminState, errorCode = RequestPreCheck.checkAdmin(session)
        if not adminState:
            return errorCode
        
        argsState, args = RequestPreCheck.checkArgs({
            'name': str,
        })
        if not argsState:
            return args
        
        name = args.get_str('name')
        validArcade = True
        if ArcadeData.fromName(name):
            validArcade = False
        
        return {'status': 'success', 'unused': validArcade}

class CheckPCBID(Resource):
    '''
    Check if PCBID has been taken
    '''
    def get(self):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        adminState, errorCode = RequestPreCheck.checkAdmin(session)
        if not adminState:
            return errorCode
        
        argsState, args = RequestPreCheck.checkArgs({
            'PCBID': str,
        })
        if not argsState:
            return args
        
        if len(args.get_str('PCBID')) != 20:
            return APIConstants.badEnd('PCBID must be 20 characters!')
        
        validArcade = True
        if MachineData.fromPCBID(args.get_str('PCBID')):
            validArcade = False
        
        return {'status': 'success', 'unused': validArcade}
    
class ArcadeTakeover(Resource):
    '''
    Claim an already used card. Transfers arcade perms into account
    '''
    
    def get(self):
        '''
        Get arcade information, check if arcade is actually unregistered.
        '''
        userId = None
        sessionState, session = RequestPreCheck.getSession()
        if sessionState:
            userId = session.get_int('id')

        if not userId:
            return APIConstants.badEnd('Bad session!')
        
        argsState, args = RequestPreCheck.checkArgs({
            'PCBID': str,
        })
        if not argsState:
            return args
        
        machine = MachineData.fromPCBID(args.get_str('PCBID'))
        if not machine:
            return APIConstants.badEnd('No machine found!')

        owners = ArcadeData.getArcadeOwners(machine.get_int('arcadeId'))
        if owners:
            return APIConstants.badEnd('Arcade already claimed!')
        
        if len(owners) != 0:
            return APIConstants.badEnd('Arcade already claimed!')

        arcade = ArcadeData.getArcade(machine.get_int('arcadeId'))
        machines = MachineData.getArcadeMachines(machine.get_int('arcadeId'))

        return {'status': 'success', 'data': {'arcade': arcade, 'count': len(machines)}}
    
    def post(self):
        '''
        Claim an already used card. Transfers user data into account
        '''
        dataState, data = RequestPreCheck.checkData({
            'PCBID': str
        })
        if not dataState:
            return data
        
        userId = None
        sessionState, session = RequestPreCheck.getSession()
        if sessionState:
            userId = session.get_int('id')

        if not userId:
            return APIConstants.badEnd('Bad session!')

        PCBID = data.get_str('PCBID')
        
        machine = MachineData.fromPCBID(PCBID)
        if not machine:
            return APIConstants.badEnd('No machine found!')

        owners = ArcadeData.getArcadeOwners(machine.get_int('arcadeId'))
        if owners:
            return APIConstants.badEnd('Arcade already claimed!')
        
        if len(owners) != 0:
            return APIConstants.badEnd('Arcade already claimed!')

        saveState = ArcadeData.putArcadeOwner(machine.get_int('arcadeId'), userId)
        if not saveState:
            return APIConstants.badEnd('Failed to transfer arcade.')

        return {'status': 'success'}