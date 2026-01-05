from flask_restful import Resource
from flask import request

from api.constants import APIConstants
from api.precheck import RequestPreCheck
from api.data.endpoints.arcade import ArcadeData
from api.external.badmaniac import BadManiac

class OnboardingVPN(Resource):
    '''
    Handle exporting of an arcade's VPN profile and send it to a Discord User.
    Requires a valid user session and that a user is an admin.
    '''
    def get(self, arcadeId: int):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        adminState, errorCode = RequestPreCheck.checkAdmin(session)
        if not adminState:
            return errorCode
        
        arcade = ArcadeData.getArcade(arcadeId)
        if not arcade:
            return APIConstants.badEnd('Unable to load the arcade!')
        
        discordId = request.args.get('discordId')
        if not discordId:
            return APIConstants.badEnd('No Discord ID!')
        
        failedResponse = BadManiac.sendArcadeVPN(discordId, arcadeId)
        if failedResponse == None:
            return {'status': 'success'}
        else:
            return failedResponse
        
class OnboardingArcade(Resource):
    '''
    Handle onboarding messages sent to a Discord User.
    Requires a valid user session and that a user is an admin.
    '''
    def get(self, arcadeId: int):
        sessionState, session = RequestPreCheck.getSession()
        if not sessionState:
            return session
        
        adminState, errorCode = RequestPreCheck.checkAdmin(session)
        if not adminState:
            return errorCode

        discordId = request.args.get('discordId')
        if not discordId:
            return APIConstants.badEnd('No Discord ID!')
        
        failedResponse = BadManiac.sendArcadeOnboarding(discordId, arcadeId)
        if failedResponse == None:
            return {'status': 'success'}
        else:
            return failedResponse
        