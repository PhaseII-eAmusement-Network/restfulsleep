from flask_restful import Resource
from flask import request

from api.constants import APIConstants
from api.precheck import RequestPreCheck
from api.data.endpoints.arcade import ArcadeData
from api.external.badmaniac import BadManiac

class PCBIDRequest(Resource):
    '''
    Handle Discord interaction between BadManiac (bot) and user.
    Requires a valid API key for BadManiac.
    This does not generate an arcade, but does fill out a request.
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
        