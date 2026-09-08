from sqlalchemy import func, and_
from api.data.mysql import MySQLBase
from api.data.types import Profile, Refid, User
from api.data.json import JsonEncoded
from typing import Dict, Any, List
from api.data.data import BaseData
from api.constants import ValidatedDict

class ProfileData:
    @staticmethod
    def getAllProfiles(game: str, version: int = None) -> List[Dict[str, Any]]:
        profiles = []
        with MySQLBase.SessionLocal() as session:
            if version is not None:
                query_results = (
                    session.query(
                        Refid.userId,
                        Refid.version,
                        Profile.data
                    )
                    .outerjoin(User, and_(
                      Refid.userId == User.id, 
                      User.banned.is_(True)
                    ))
                    .join(Profile, Refid.refid == Profile.refid)
                    .filter(
                        Refid.game == game,
                        Refid.version == version,
                        User.id.is_(None),
                    )
                    .yield_per(1000)
                )

            else:
                latest_version_subquery = (
                    session.query(
                        Refid.userId,
                        func.max(Refid.version).label("max_version"),
                    )
                    .outerjoin(User, and_(
                      Refid.userId == User.id, 
                      User.banned.is_(True)
                    ))
                    .filter(
                        Refid.game == game,
                        Refid.version < 10000,
                        User.id.is_(None),
                    )
                    .group_by(Refid.userId)
                ).subquery()

                query_results = (
                    session.query(
                        Refid.userId,
                        Refid.version,
                        Profile.data
                    )
                    .join(
                        latest_version_subquery,
                        and_(
                            Refid.userId == latest_version_subquery.c.userId,
                            Refid.version == latest_version_subquery.c.max_version,
                        ),
                    )
                    .join(Profile, Refid.refid == Profile.refid)
                    .filter(Refid.game == game)
                    .yield_per(1000)
                )

            for userId, maxVersion, profile_data in query_results:
                rawData = JsonEncoded.deserialize(profile_data)
                profiles.append({
                    'userId': userId,
                    'maxVersion': maxVersion,
                    'username': rawData.get('username', rawData.get('name', '')),
                    'chara': rawData.get('chara', None),
                    'sgrade': rawData.get('sgrade', None),
                    'dgrade': rawData.get('dgrade', None),
                    'block': rawData.get('block', None),
                    'packet': rawData.get('packet', None),
                    'skill_level': rawData.get('skill_level', None),
                    'flare_single': rawData.get('flare_single', None),
                    'flare_double': rawData.get('flare_double', None),
                    'jubility': (rawData.get('jubility', 0)) / 10,
                    'profile_skill': (rawData.get('profile_skill', 0)) / 100,
                    'skill': (rawData.get('skill', 0)) / 100,
                })

        return profiles
        
    def getProfile(game: str, version: int, userId: int, noData: bool = False) -> ValidatedDict:
        with MySQLBase.SessionLocal() as session:
            profile = None
            if version:
                # Combine Refid and Profile queries into a single JOIN query
                profile = session.query(Profile).join(Refid, Refid.refid == Profile.refid).filter(
                    Refid.userId == userId,
                    Refid.game == game,
                    Refid.version == version
                ).first()
            else:
                # Fetch the latest Refid and Profile in one query, ordering by version descending
                profile = session.query(Profile).join(Refid, Refid.refid == Profile.refid).filter(
                    Refid.userId == userId,
                    Refid.game == game,
                    Refid.version < 10000
                ).order_by(Refid.version.desc()).first()

            if profile:
                rawData = JsonEncoded.deserialize(profile.data)
                rawData['machine_judge_adjust'] = None # Block exposing PCBIDs
                return ValidatedDict({
                    'userId': userId,
                    'username': rawData.get('username', rawData.get('name', '')),
                    **(rawData if not noData else {})
                })
            
            return None
                
    def getVersions(game: str, userId: int) -> dict:
        with MySQLBase.SessionLocal() as session:
            refid_query = session.query(Refid.version).filter(
                Refid.userId == userId,
                Refid.game == game,
                (Refid.version < 10000)
            ).order_by(Refid.version.asc()).all()

            if refid_query:
                return [refid.version for refid in refid_query]

    def getProfileName(game: str, version: int, userId: int) -> str | None:
        with MySQLBase.SessionLocal() as session:
            if version:
                refid = session.query(Refid.refid).filter_by(
                    userId=userId,
                    game=game,
                    version=version
                ).scalar()
            else:
                refid = session.query(Refid.refid).filter(
                    Refid.userId == userId,
                    Refid.game == game,
                    Refid.version < 10000
                ).order_by(Refid.version.desc()).limit(1).scalar()

            if refid:
                data = session.query(Profile.data).filter_by(refid=refid).scalar()
                if data:
                    deserialized = JsonEncoded.deserialize(data)
                    return deserialized.get("username") or deserialized.get("name")
            return None
            
    def updateProfile(game: str, version: int, userId: int, new_profile: dict) -> str | None:
        profile = ProfileData.getProfile(game, version, userId)
        if not profile:
            return 'No profile found!'
        
        if new_profile.get('username') != None:
            new_profile['name'] = new_profile.get('name', new_profile.get('username'))

        with MySQLBase.SessionLocal() as session:
            profile = None
            refid_query = session.query(Refid).filter(
                Refid.userId == userId,
                Refid.game == game,
                Refid.version == version
            ).first()

            if refid_query:
                profile = session.query(Profile).filter(Profile.refid == refid_query.refid).first()

            if profile:
                rawData = JsonEncoded.deserialize(profile.data, True)
                error_code = BaseData.update_data(rawData, new_profile)
                if error_code:
                    return error_code
            
                profile.data = JsonEncoded.serialize(rawData)
                session.commit()
                
            return None