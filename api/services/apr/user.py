from flask import request
from flask_restful import Resource
from api.data.apr import APRConstants, RequestData
from datetime import datetime

@staticmethod
def format_player(uuid, name) -> dict:
    return {
        "PlayerId": "1234567",
        "PlayerName": name,
        "InviteCnt": 1,
        "ArcadePt": 100,
        "FriendRequested": 0,
        "UpdateDate": "9/1/2022",
        "LoginBonusId": 0,
        "LoginCount": 69,
        "Login": True
    }

class APRPlayer(Resource):
    def post(self):
        request = RequestData.get_request_data()
        print(request)
        if request != None:
            uuid = request['uuid']

            if uuid == None:
                return APRConstants.badEnd(1)

            return format_player(uuid, 'deez')

        else: return APRConstants.badEnd(1)

class APRNewPlayer(Resource):
    def post(self):
        request = RequestData.get_request_data()
        if request != None:
            uuid = request['uuid']
            name = request['name']

            if uuid == None:
                return APRConstants.badEnd(1)
            if name == None:
                return APRConstants.badEnd(1)

            return format_player(uuid, name)

        else: return APRConstants.badEnd(1)

class APRLinkAccount(Resource):
    def post(self):
        request = RequestData.get_request_data()
        if request != None:
            uuid = request['uuid']
            konami_id = request['konami_id']
            password = request['password']

            if konami_id == None:
                return APRConstants.badEnd(1)
            if uuid == None:
                return APRConstants.badEnd(1)
            if password == None:
                return APRConstants.badEnd(1)

            return {'RefId': 'yes'}

        else: return APRConstants.badEnd(1)

class APRInvited(Resource):
    def post(self):
        request = RequestData.get_request_data()
        if request != None:
            uuid = request['uuid']
            player_id = request['player_id']

            if uuid == None:
                return APRConstants.badEnd(4)
            if player_id == None:
                return APRConstants.badEnd(4)

            return {
                'ErrorCode': 2,
            }

        else: return APRConstants.badEnd(4)

class APRPresentList(Resource):
    def post(self):
        request = RequestData.get_request_data()
        if request != None:
            uuid = request['uuid']

            if uuid == None:
                return APRConstants.badEnd(4)

            presents = []
            presents.append({
                'PresentId': 1,
                'ItemId': 1,
                'ItemNum': 1,
                'Info': 'A gift for you!'
            })

            return {'PresentList': presents}

        else: return APRConstants.badEnd(4)

class APRGetFriendList(Resource):
    def post(self):

        friend_list = []                     # will become `obja` (NSMutableArray)

        # ----- values that are read from the server response -----
        # v173 = ItemId, v174 = ItemNum, v175 = PresentId,
        # v176 = ???, v179 = ???, v182 = ???
        # (the exact meaning is not needed for a functional mock)
        item_id    = 1
        item_num   = 1
        present_id = 1
        extra1     = 0
        extra2     = 0
        extra3     = 0

        # ----- the 3×7 integer array that is later adjusted -----
        #   [3[7i]]  → 3 groups of 7 ints
        # The original code only touches index 27 and 30 inside each group
        # (0-based: group[27] -= group[30]; clamp to 0)
        raw_arrays = [
            [0] * 7,      # group 0
            [0] * 7,      # group 1
            [0] * 7       # group 2
        ]

        # ----- the two extra [3i] arrays (v121[27] lives in the first one) -----
        extra_array_a = [0, 0, 0]   # will receive the adjusted values
        extra_array_b = [0, 0, 0]

        # ----- apply the same adjustment the original loop does -----
        for idx in range(3):
            diff = raw_arrays[idx][27 % 7] - raw_arrays[idx][30 % 7]
            extra_array_a[idx] = max(diff, 0)

        # ----- pack everything into an NSValue-compatible dict -----
        # The original NSValue type is:
        #   {FriendListData=@@siii[3[7i]][3i][3i]}
        # We emulate it with a plain Python dict – the client only calls
        # `getValue:` on it, so any dict with the same keys works.
        nsvalue_dict = {
            "unknownObj": None,          # @@  (id)
            "unknownShort": 0,           # s   (short)
            "itemId": item_id,           # i
            "itemNum": item_num,         # i
            "presentId": present_id,     # i
            "array3x7": raw_arrays,      # [3[7i]]
            "extraA": extra_array_a,     # [3i]
            "extraB": extra_array_b      # [3i]
        }
        friend_list.append(nsvalue_dict)

        # -----------------------------------------------------------------
        # 2. Return the list wrapped the same way the original code does:
        #     v127->_friendListArray = [[NSArray alloc] initWithArray:obja];
        # -----------------------------------------------------------------
        print(friend_list)

        return {"friendListArray": friend_list}