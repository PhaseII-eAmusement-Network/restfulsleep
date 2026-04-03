import random
import time
from typing import Dict, Any
from api.data.aes import AESCipher
from api.data.types import Session
from api.data.mysql import MySQLBase
from api.constants import ValidatedDict

class SessionData:
    AES = None

    @staticmethod
    def updateConfig(cryptoConfig: Dict[str, Any]) -> None:
        key = cryptoConfig.get('cookie_key', None)
        if not key:
            raise Exception("Failed to initialize cookie encryption.")
        
        SessionData.AES = AESCipher(key)

    @staticmethod
    def createSession(opId: int, opType: str, expiration: int=(30 * 86400)) -> str:
        sessionToken = ''.join(random.choice('0123456789ABCDEF') for _ in range(32))
        expirationTime = int(time.time() + expiration)

        with MySQLBase.SessionLocal() as session:
            while session.query(Session).filter(Session.session == sessionToken).first():
                sessionToken = ''.join(random.choice('0123456789ABCDEF') for _ in range(32))
            
            newSession = Session(id=opId, session=sessionToken, type=opType, expiration=expirationTime)
            session.add(newSession)
            session.commit()

            return sessionToken
    
    @staticmethod
    def checkSession(sessionID: str) -> ValidatedDict:
        with MySQLBase.SessionLocal() as session:
            userSession = session.query(Session).filter(Session.session == sessionID, Session.type == 'userid').first()
            if userSession != None:
                return ValidatedDict({
                    'active': True,
                    'id': int(userSession.id)
                })
            else:
                return ValidatedDict({
                    'active': False,
                    'id': None 
                })
        
    @staticmethod
    def getAllSessions(userId: int) -> list[ValidatedDict]:
        with MySQLBase.SessionLocal() as session:
            userSessions = session.query(Session).filter(Session.id == userId, Session.type == 'userid').all()
            if userSessions != None:
                return [ValidatedDict({
                    'expiration': int(session.expiration),
                    'id': int(session.id)
                }) for session in userSessions]
        
    @staticmethod
    def deleteSession(sessionID: str) -> None:
        with MySQLBase.SessionLocal() as session:
            session.query(Session).filter(Session.session == sessionID, Session.type == 'userid').delete()
            session.commit()

    @staticmethod
    def deleteAllSessions(userId: int) -> None:
        with MySQLBase.SessionLocal() as session:
            userSessions = session.query(Session).filter(Session.id == userId, Session.type == 'userid').all()
            for userSession in userSessions:
                session.delete(userSession)
            session.commit()

class KeyData:
    @staticmethod
    def createKey(opId: int, opType: str, expiration: int=(300), length: int=6) -> str:
        keyToken = ''.join(random.choice('123456789') for _ in range(length))
        expirationTime = int(time.time() + expiration)

        with MySQLBase.SessionLocal() as session:
            while session.query(Session).filter(Session.session == keyToken).first():
                keyToken = ''.join(random.choice('123456789') for _ in range(length))
            
            newSession = Session(id=opId, session=keyToken, type=opType, expiration=expirationTime)
            session.add(newSession)
            session.commit()

            return keyToken
    
    @staticmethod
    def checkKey(key: int, opType: str) -> ValidatedDict:
        with MySQLBase.SessionLocal() as session:
            userSession = session.query(Session).filter(Session.session == key, Session.type == opType).first()
            
            if userSession is not None:
                current_time = int(time.time())
                
                if userSession.expiration > current_time:
                    return ValidatedDict({
                        'active': True,
                        'id': int(userSession.id)
                    })
                else:
                    return ValidatedDict({
                        'active': False,
                        'id': None 
                    })
            else:
                return ValidatedDict({
                    'active': False,
                    'id': None 
                })
    
    @staticmethod
    def deleteKey(key: str, opType: str) -> None:
        with MySQLBase.SessionLocal() as session:
            session.query(Session).filter(Session.session == key, Session.type == opType).delete()
            session.commit()

class TokenData:
    @staticmethod
    def createToken(opId: int, opType: str, expiration: int=(300)) -> str:
        newToken = ''.join(random.choice('0123456789ABCDEF') for _ in range(32))
        expirationTime = int(time.time() + expiration)

        with MySQLBase.SessionLocal() as session:
            while session.query(Session).filter(Session.session == newToken).first():
                newToken = ''.join(random.choice('0123456789ABCDEF') for _ in range(32))
            
            newSession = Session(id=opId, session=newToken, type=opType, expiration=expirationTime)
            session.add(newSession)
            session.commit()

            return newToken
    
    @staticmethod
    def checkToken(token: str, opType: str) -> ValidatedDict:
        with MySQLBase.SessionLocal() as session:
            userSession = session.query(Session).filter(Session.session == token, Session.type == opType).first()
            if userSession != None:
                return ValidatedDict({
                    'active': True,
                    'id': int(userSession.id)
                })
            else:
                return ValidatedDict({
                    'active': False,
                    'id': None 
                })
    
    @staticmethod
    def deleteToken(token: str, opType: str) -> None:
        with MySQLBase.SessionLocal() as session:
            session.query(Session).filter(Session.session == token, Session.type == opType).delete()
            session.commit()