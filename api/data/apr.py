from flask import request
from typing import Dict

class APRConstants:
    def badEnd(error: int) -> dict:
        return {'ErrorCode': error}

class RequestData:
    '''
    Deals with all request data, returns it how we want it.
    '''
    @staticmethod
    def get_request_data() -> Dict:
        data_dict = {}
        data = request.get_data()
        if data != None:
            data = data.decode('utf-8').split('&')
            for i in data:
                i_split = i.split('=')
                if len(i_split) == 2:
                    data_dict[f'{i_split[0]}'] = f'{i_split[1]}'
                    
        return data_dict