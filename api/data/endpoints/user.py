from passlib.hash import pbkdf2_sha512

from api.data.json import JsonEncoded
from api.data.mysql import MySQLBase
from api.data.types import User, UserContent, Card
from api.data.data import BaseData
from api.constants import ValidatedDict

class UserData:
    def validatePassword(plain_password: str, userID: int) -> bool:
        with MySQLBase.SessionLocal() as session:
            pw_hash = session.query(User.password).filter(User.id == userID).first()
            if not pw_hash:
                return False
            try:
                return pbkdf2_sha512.verify(plain_password, pw_hash[0])
            except (ValueError, TypeError):
                return False
            
    def banned(userId: int) -> ValidatedDict:
        with MySQLBase.SessionLocal() as session:
            userBanned = session.query(User.banned).filter(User.id == userId).first()

            if userBanned is not None and userBanned[0]:
                return True
            else:
                return False
            
    def public(userId: int) -> ValidatedDict:
        with MySQLBase.SessionLocal() as session:
            userPublic = session.query(User.public).filter(User.id == userId).first()

            if userPublic is not None and userPublic[0]:
                return True
            else:
                return False
            
    def admin(userId: int) -> ValidatedDict:
        with MySQLBase.SessionLocal() as session:
            userAdmin = session.query(User.admin).filter(User.id == userId).first()

            if userAdmin is not None and userAdmin[0]:
                return True
            else:
                return False

    def getUser(userId: int) -> ValidatedDict:
        with MySQLBase.SessionLocal() as session:
            user = session.query(User).filter(User.id == userId).first()
            if user is None:
                return None
            else:
                return ValidatedDict({
                    'id': int(user.id),
                    'username': user.username,
                    'email': user.email,
                    'admin': bool(user.admin),
                    'banned': bool(user.banned),
                    'public': bool(user.public),
                    'data': JsonEncoded.deserialize(user.data)
                })
            
    def getUsername(userId: int) -> str:
        with MySQLBase.SessionLocal() as session:
            user = session.query(User.username).filter(User.id == userId).first()
            if user is None:
                return None
            else:
                return user.username
            
    def getUserPlayVideos(userId: int) -> dict:
        with MySQLBase.SessionLocal() as session:
            play_videos = session.query(UserContent).filter(UserContent.userid == userId, UserContent.type == "play_video").all()
            
            sorted_videos = []
            for play_video in play_videos:
                sorted_videos.append(
                    ValidatedDict({
                        'id': int(play_video.id),
                        'timestamp': int(play_video.timestamp),
                        'game': play_video.game,
                        'version': play_video.version,
                        'musicid': int(play_video.musicid),
                        'sessionId': play_video.sessionid,
                        'data': JsonEncoded.deserialize(play_video.data)
                    })
                )
            
            return sorted_videos
        
    def getUserPlayVideo(sessionId: str) -> dict:
        with MySQLBase.SessionLocal() as session:
            play_video = session.query(UserContent).filter(UserContent.sessionid == sessionId, UserContent.type == "play_video").first()
            
            if play_video:
                return ValidatedDict({
                    'id': int(play_video.id),
                    'userid': int(play_video.userid),
                    'timestamp': int(play_video.timestamp),
                    'game': play_video.game,
                    'version': play_video.version,
                    'musicid': int(play_video.musicid),
                    'sessionId': play_video.sessionid,
                    'data': JsonEncoded.deserialize(play_video.data)
                })
            
            return None

    def updateUserPlayVideoData(sessionId: str, new_data: dict) -> dict:
        with MySQLBase.SessionLocal() as session:
            play_video = session.query(UserContent).filter(UserContent.type == "play_video", UserContent.sessionid == sessionId).first()
            if play_video:
                rawData = JsonEncoded.deserialize(play_video.data, True)
                error_code = BaseData.update_data(rawData, new_data)
                if error_code:
                    return error_code
            
                play_video.data = JsonEncoded.serialize(rawData)
                session.commit()
            
            return None

    def getAllUserContent(userId: int, session_type: str) -> dict:
        with MySQLBase.SessionLocal() as session:
            user_contents = session.query(UserContent).filter(UserContent.userid == userId, UserContent.type == session_type).all()
            
            sorted_videos = []
            for user_content in user_contents:
                sorted_videos.append(
                    ValidatedDict({
                        'id': int(user_content.id),
                        'timestamp': int(user_content.timestamp),
                        'game': user_content.game,
                        'version': user_content.version,
                        'musicid': user_content.musicid,
                        'sessionId': user_content.sessionid,
                        'data': JsonEncoded.deserialize(user_content.data)
                    })
                )
            
            return sorted_videos
            
    def getUserContent(sessionId: str, session_type: str) -> dict:
        with MySQLBase.SessionLocal() as session:
            user_content = session.query(UserContent).filter(UserContent.sessionid == sessionId, UserContent.type == session_type).first()
            
            if user_content:
                return ValidatedDict({
                    'id': int(user_content.id),
                    'userid': int(user_content.userid),
                    'timestamp': int(user_content.timestamp),
                    'game': user_content.game,
                    'version': user_content.version,
                    'musicid': user_content.musicid,
                    'sessionId': user_content.sessionid,
                    'data': JsonEncoded.deserialize(user_content.data)
                })
            
            return None

    def updateUserContentData(sessionId: str, session_type: str, new_data: dict) -> dict:
        with MySQLBase.SessionLocal() as session:
            user_content = session.query(UserContent).filter(UserContent.type == session_type, UserContent.sessionid == sessionId).first()
            if user_content:
                rawData = JsonEncoded.deserialize(user_content.data, True)
                error_code = BaseData.update_data(rawData, new_data)
                if error_code:
                    return error_code
            
                user_content.data = JsonEncoded.serialize(rawData)
                session.commit()
            
            return None
    
    def checkUserPin(userId: int, pin: int) -> str:
        with MySQLBase.SessionLocal() as session:
            userPin = session.query(User.pin).filter(User.id == userId, User.pin == pin).first()
            if userPin is None:
                return False
            else:
                return True
            
    def updateUser(userId: int, newUsername: str = None, newEmail: str = None, newPin: str = None, public: bool = None, banned: bool = None) -> bool:
        with MySQLBase.SessionLocal() as session:
            user = session.query(User).filter(User.id == userId).first()
            if user is None:
                return False
            else:
                didAnything = False
                if newUsername:
                    user.username = newUsername
                    didAnything = True

                if newEmail:
                    user.email = newEmail
                    didAnything = True

                if newPin:
                    user.pin = newPin
                    didAnything = True

                if public != None:
                    user.public = int(public)
                    didAnything = True

                if banned != None:
                    user.banned = int(banned)
                    didAnything = True

                if didAnything:
                    session.commit()
                    return True

                return False
            
    def updateUserData(userId: int, new_data: ValidatedDict) -> bool:
        with MySQLBase.SessionLocal() as session:
            user = session.query(User).filter(User.id == userId).first()
            if user is None:
                return False
            else:
                didAnything = False
                if new_data:
                    rawData = JsonEncoded.deserialize(user.data, True)
                    error_code = BaseData.update_data(rawData, new_data)
                    if error_code:
                        return error_code
                    user.data = JsonEncoded.serialize(rawData)
                    didAnything = True

                if didAnything:
                    session.commit()
                    return True

                return False
       
    def updatePassword(userId: int, newPassword: str) -> bool:
        with MySQLBase.SessionLocal() as session:
            user = session.query(User).filter(User.id == userId).first()
            if user is None:
                return False
            else:
                hashed = pbkdf2_sha512.hash(newPassword)
                user.password = hashed
                session.commit()
                return True

    def getUserByName(username: str) -> dict:
        with MySQLBase.SessionLocal() as session:
            user = session.query(User).filter(User.username == username).first()
            if user is None:
                return None
            else:
                return ValidatedDict({
                    'id': int(user.id),
                    'username': user.username,
                    'admin': bool(user.admin),
                    'banned': bool(user.banned),
                    'data': JsonEncoded.deserialize(user.data)
                })
    
    def getUserByEmail(email: str) -> dict:
        with MySQLBase.SessionLocal() as session:
            user = session.query(User).filter(User.email == email).first()
            if user is None:
                return None
            else:
                return ValidatedDict({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'banned': bool(user.banned),
                })

    def getCards(userId: int) -> dict:
        with MySQLBase.SessionLocal() as session:
            cards = session.query(Card).filter(Card.userid == userId).all()
            if cards is None:
                return None
            else:
                return [card.id for card in cards]
            
    def cardExist(cardId: str) -> bool:
        with MySQLBase.SessionLocal() as session:
            card = session.query(Card).filter(Card.id == cardId).first()
            if card is None:
                return False
            else:
                return card.userid

    def putCard(userId: int, cardId: str) -> bool:
        with MySQLBase.SessionLocal() as session:
            if session.query(Card).filter(Card.id == cardId).first() is not None:
                return False

            new_card = Card(id=cardId, userid=userId)
            session.add(new_card)
            session.commit()
            return True

    def deleteCard(userId: str, cardId: str) -> bool:
        with MySQLBase.SessionLocal() as session:
            card = session.query(Card).filter(Card.id == cardId, Card.userid == userId).first()
            if card is None:
                return True

            session.delete(card)
            session.commit()
            return True
        
    def transferCard(fromUserId: int, toUserId: int, cardId: str) -> bool:
        with MySQLBase.SessionLocal() as session:
            card = session.query(Card).filter(Card.id == cardId, Card.userid == fromUserId).first()
            if not card:
                return False

            card.userid = toUserId
            session.commit()
            return True