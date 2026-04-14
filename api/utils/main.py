from flask import Flask, make_response
from flask_cors import CORS # type: ignore
from flask_restful import Api, Resource
from typing import Any, Dict
import argparse
import yaml
import hashlib

# External APIs
from api.data.mysql import MySQLBase
from api.data.cache import LocalCache
from api.data.endpoints.session import SessionData
from api.external.pfsense import PFSense
from api.external.backblaze import BackBlazeCDN
from api.external.mailjet import MailjetSMTP
from api.external.unity import UnityAPI

# Bad Maniac Discord Bot
from api.external.badmaniac import BadManiac

# Services
from api.services.discord import OnboardingVPN, OnboardingArcade
from api.services.admin import AdminDashboard, AdminAudit, AdminArcade, AdminArcadeOwner, AdminArcadeMachine, AdminArcades, OnboardArcade, AdminMachinePCBID, Maintenance, Client, AdminUsers, AdminUser, AdminUserUpdatePassword, AdminUserCardId, AdminNews, AdminNewsPost
from api.services.arcade import Arcade, ArcadeSettings, Paseli, VPN, CheckArcadeName, CheckPCBID, ArcadeTakeover
from api.services.news import getAllNews, getNews
from api.services.auth import UserSession, emailAuth, check2FAKey, resetPassword
from api.services.oauth import OAuthClient, OAuthToken
from api.services.user import UserAccount, UserUpdatePassword, UserCard, UserTakeover, UserPlayVideos, UserContent, UserCustomize, UserAppVersion, UserOnboard, UserReadNews, UserSessions, UserMinified
from api.services.profiles import Profile, Achievements, Links, Link
from api.services.game import Game
from api.services.music import Music
from api.services.score import Attempts, Records, TopScore

# Share server
from api.services.share import ShareServer, shareServerStatus, shareNewSession, shareBeginUpload, shareVideoUpload, shareEndUpload, shareLPACUpload

# Integrations
from api.services.integrate import Integrations, IntegrateDiscord, IntegrateTachi

# pop'n rhythmin API server
from api.services.apr.events import APREventInfo, APRFileList
from api.services.apr.session import APRNewSession, APRSaveSession
from api.services.apr.music import APRRecommendList, APRPackList
from api.services.apr.network import APRSearchMaster
from api.services.apr.user import APRPlayer, APRNewPlayer, APRLinkAccount, APRInvited, APRPresentList, APRGetFriendList

# jubeat PLUS server
from api.services.agx.cgi import AGXServer, AGXStartup, AGXCheckMarker, AGXNew, AGXPolicyStore
from api.services.aqq.lab import AQQGetLabURL
from api.services.aqq.ios import AQQLabiOS

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.config.update(
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = 'None',
)

api = Api(app)
config: Dict[str, Any] = {}

class restfulTop(Resource):
    def get(self):
        return "RestfulSleep is alive! PhaseII's powerful API used for bots, apps, and more."

# Base keep-alive
api.add_resource(restfulTop, '/')

# Admin
api.add_resource(AdminDashboard, '/v1/admin')
api.add_resource(AdminAudit, '/v1/admin/audit')
api.add_resource(AdminArcade, '/v1/admin/arcade/<arcadeId>')
api.add_resource(AdminArcadeOwner, '/v1/admin/arcade/<arcadeId>/owner')
api.add_resource(AdminArcadeMachine, '/v1/admin/arcade/<arcadeId>/machine')
api.add_resource(AdminArcades, '/v1/admin/arcades')
api.add_resource(OnboardArcade, '/v1/admin/onboardArcade')
api.add_resource(AdminMachinePCBID, '/v1/admin/machine/<PCBID>')
api.add_resource(Maintenance, '/v1/admin/maint')
api.add_resource(Client, '/v1/admin/client')
api.add_resource(AdminUsers, '/v1/admin/users')
api.add_resource(AdminUser, '/v1/admin/user/<userId>')
api.add_resource(AdminUserUpdatePassword, '/v1/admin/user/<userId>/updatePassword')
api.add_resource(AdminUserCardId, '/v1/admin/user/card/<cardId>')
api.add_resource(AdminNews, '/v1/admin/news')
api.add_resource(AdminNewsPost, '/v1/admin/news/<newsId>')

# Arcades
api.add_resource(Arcade, '/v1/arcade/<arcadeId>')
api.add_resource(ArcadeSettings, '/v1/arcade/<arcadeId>/settings')
api.add_resource(Paseli, '/v1/arcade/<arcadeId>/paseli')
api.add_resource(VPN, '/v1/arcade/<arcadeId>/exportVPN')
api.add_resource(CheckArcadeName, '/v1/arcade/checkName')
api.add_resource(CheckPCBID, '/v1/arcade/checkPCBID')
api.add_resource(ArcadeTakeover, '/v1/arcade/takeover')

# BadManiac Calls
api.add_resource(OnboardingVPN, '/v1/discord/exportVPN/<arcadeId>')
api.add_resource(OnboardingArcade, '/v1/discord/onboardArcade/<arcadeId>')

# News
api.add_resource(getAllNews, '/v1/news')
api.add_resource(getNews, '/v1/news/<newsId>')

# Authentication
api.add_resource(UserSession, '/v1/auth/session')
api.add_resource(emailAuth, '/v1/auth/emailAuth')
api.add_resource(check2FAKey, '/v1/auth/check2FAKey')
api.add_resource(resetPassword, '/v1/auth/changePassword')

# OAuth
api.add_resource(OAuthClient, '/v1/oauth/client/<clientId>')
api.add_resource(OAuthToken, '/v1/oauth/token/<clientId>')

# User Data
api.add_resource(UserAccount, '/v1/user')
api.add_resource(UserUpdatePassword, '/v1/user/updatePassword')
api.add_resource(UserCard, '/v1/user/card')
api.add_resource(UserTakeover, '/v1/user/takeover')
api.add_resource(UserPlayVideos, '/v1/user/playVideos')
api.add_resource(UserContent, '/v1/user/content')
api.add_resource(UserCustomize, '/v1/user/customize')
api.add_resource(UserAppVersion, '/v1/user/appVersion')
api.add_resource(UserOnboard, '/v1/user/onboard')
api.add_resource(UserReadNews, '/v1/user/readNews')
api.add_resource(UserSessions, '/v1/user/sessions')
api.add_resource(UserMinified, '/v1/user/minified')

# Integration callbacks
api.add_resource(IntegrateDiscord, '/v1/user/integrate/discord')
api.add_resource(IntegrateTachi, '/v1/user/integrate/tachi')

# Game Data
api.add_resource(Game, '/v1/game/<game>')
api.add_resource(Profile, '/v1/profile/<game>')
api.add_resource(Achievements, '/v1/profile/<game>/achievements')
api.add_resource(Links, '/v1/profile/<game>/links')
api.add_resource(Link, '/v1/profile/<game>/link')

# Music DB Data
api.add_resource(Music, '/v1/music')

# Scores
api.add_resource(Attempts, '/v1/attempts/<game>')
api.add_resource(Records, '/v1/records/<game>')
api.add_resource(TopScore, '/v1/topscore/<game>/<songId>')

# Game Upload API
api.add_resource(shareServerStatus, '/share/server/status')
api.add_resource(shareNewSession, '/share/sessions/new')
api.add_resource(shareBeginUpload, '/share/sessions/<session_id>/videos/<video_id>/begin-upload')
api.add_resource(shareVideoUpload, '/share/videoUpload/<session_id>/<video_id>')
api.add_resource(shareEndUpload, '/share/sessions/<session_id>/videos/<video_id>/end-upload')
api.add_resource(shareLPACUpload, '/share/lpac/<session_id>')

# pop'n Rhythmin API
app.route('/apr/main/cgi/new/index.jsp')
def new():
    return {'status': 200}

api.add_resource(APRFileList, f'/apr/main/cgi/get_dl_file_list/index.jsp')
api.add_resource(APREventInfo, f'/apr/main/cgi/get_event_info/index.jsp')
api.add_resource(APRNewSession, f'/apr/main/cgi/new/index.jsp')
api.add_resource(APRSaveSession, f'/apr/main/cgi/save_apns_token/index.jsp')
api.add_resource(APRPlayer, f'/apr/main/cgi/get_player/index.jsp')
api.add_resource(APRNewPlayer, f'/apr/main/cgi/new_player/index.jsp')
api.add_resource(APRLinkAccount, f'/apr/main/cgi/link_kid/index.jsp')
api.add_resource(APRInvited, f'/apr/main/cgi/invited/index.jsp')
api.add_resource(APRPresentList, f'/apr/main/cgi/get_present_list/index.jsp')
api.add_resource(APRGetFriendList, f'/apr/main/cgi/get_friend_list/index.jsp')
api.add_resource(APRRecommendList, f'/apr/main/cgi/get_recommend_list/index.jsp')
api.add_resource(APRPackList, f'/apr/main/cgi/packlist/index.jsp')
api.add_resource(APRSearchMaster, f'/apr/main/cgi/search_master/index.jsp')

api.add_resource(AGXStartup, '/agx/main/cgi/startup/')
api.add_resource(AGXCheckMarker, '/agx/main/cgi/check_marker/')
api.add_resource(AGXNew, '/agx/main/cgi/new/')
api.add_resource(AGXPolicyStore, '/agx/main/cgi/policy/store/')
api.add_resource(AQQGetLabURL, '/aqq/api/JP/v1/utils/getLabURL')
api.add_resource(AQQLabiOS, '/aqq/api/ios')

def loadConfigs(filename: str) -> None:
    global config

    with open(filename, 'r') as file:
        config.update(yaml.safe_load(file))

    flaskConfig = config.get('flask', {})
    secretKey = flaskConfig.get('secret_key')
    if not secretKey:
        raise ValueError("Missing 'flask.secret_key' in config file. Required for secure HTTP-only cookies.")
    app.secret_key = secretKey
    app.config.update(
        SESSION_COOKIE_SECURE = flaskConfig.get('secure_cookie', True),
    )

    configMap = {
        'database': MySQLBase.updateConfig,
        'cache': LocalCache.updateConfig,
        'crypto': SessionData.updateConfig,
        'pfsense': PFSense.updateConfig,
        'email': MailjetSMTP.updateConfig,
        'backblaze': BackBlazeCDN.updateConfig,
        'share': ShareServer.updateConfig,
        'bad-maniac': BadManiac.updateConfig,
        'agx-server': AGXServer.updateConfig,
        'flask': UserSession.updateConfig,
        'unity': UnityAPI.updateConfig,
    }

    for key, updater in configMap.items():
        section = config.get(key, {})
        if section:
            updater(section)

    # Special handling for integrations
    discordConfig = config.get('discord', {})
    tachiConfig = config.get('tachi', {})
    if config.get('share', {}):
        Integrations.updateConfig(discordConfig, tachiConfig)

def main() -> None:
    parser = argparse.ArgumentParser(description="PhaseII's powerful API, RestfulSleep. Built with Flask and restful.")
    parser.add_argument("-p", "--port", help="Port to listen on. Defaults to 8000", type=int, default=8000)
    parser.add_argument("-c", "--config", help="Path to configuration file. Defaults to 'config.yaml'", type=str, default='config.yaml')
    args = parser.parse_args()
    loadConfigs(args.config)

    app.run(host='0.0.0.0', port=args.port, debug=True)

if __name__ == '__main__':
    main()