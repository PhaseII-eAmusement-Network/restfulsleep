from flask_restful import Resource
from flask import request
from api.data.endpoints.music import MusicData
from api.precheck import RequestPreCheck

from api.constants import APIConstants

class Music(Resource):
    def get(self):
        sessionState, session = RequestPreCheck.getSession(allowApi=True)
        if not sessionState:
            return session
        
        game = request.args.get('game')
        version = request.args.get('version')
        songIds = request.headers.get('songIds')
        oneChart = request.args.get('oneChart')

        if not version:
            return APIConstants.badEnd('No version provided!')
        
        if not game:
            return APIConstants.badEnd('No game provided!')
        
        filteredSongIds = None
        if songIds:
            filteredSongIds = []
            for songId in songIds.split(','):
                filteredSongIds.append(int(songId))
            
        filteredVersion = int(version)
        data = MusicData.getAllMusic(game = game, version = filteredVersion, song_ids = filteredSongIds, chart = 0 if oneChart else None)
        return {
            'status': 'success',
            'data': data
        }, 200
