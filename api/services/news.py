from flask_restful import Resource
from api.precheck import RequestPreCheck
from api.constants import APIConstants

from api.data.endpoints.news import NewsData

class getAllNews(Resource):
    def get(self):
        sessionState, session = RequestPreCheck.getSession(allowApi=True)
        if not sessionState:
            return session
        
        argsState, args = RequestPreCheck.checkArgs()
        if not argsState:
            return args
        
        limit = None
        if args.get_str('limit'):
            try:
                limit = int(args.get_str('limit'))
            except Exception as e:
                return APIConstants.badEnd(str(e))
        
        data = NewsData.getAllNews(limit)
        return data, 200

class getNews(Resource):
    def get(self, newsId):
        sessionState, session = RequestPreCheck.getSession(allowApi=True)
        if not sessionState:
            return session
        
        data = NewsData.getNews(newsId)
        return {
            'status': 'success',
            'news': data
        }, 200 