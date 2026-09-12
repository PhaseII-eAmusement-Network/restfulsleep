from typing import List, Tuple, Optional
from sqlalchemy import func, and_
from api.data.mysql import MySQLBase
from api.data.types import Music, Attempt
from api.data.json import JsonEncoded
from api.data.cache import LocalCache
from api.data.time import Time

def _latest_version_subquery(session, game, song_ids=None):
    q = (
        session.query(
            Music.songid,
            func.max(Music.version).label("max_version")
        )
        .filter(Music.game == game)
        .group_by(Music.songid)
    )

    if song_ids:
        q = q.filter(Music.songid.in_(song_ids))

    return q.subquery()

class MusicData:
    @staticmethod
    def getAllMusic(
        game: str = None,
        version: int = None,
        limit: int = None,
        chart: int = None,
        song_ids: list[int] = None
    ) -> list[dict]:

        cacheName = f'music_{game}_{version}'
        musicData = None
        if not song_ids:
            musicData = LocalCache().getCachedData(cacheName)

        if not musicData:
            with MySQLBase.SessionLocal() as session:
                musicQuery = session.query(Music).filter(Music.game == game)
                if song_ids:
                    musicQuery = musicQuery.filter(Music.songid.in_(song_ids))

                if chart:
                    musicQuery = musicQuery.filter(Music.chart == chart)

                if version is not None:
                    musicQuery = musicQuery.filter(Music.version == version)

                musicQuery = musicQuery.order_by(Music.songid.desc())
                if limit:
                    musicQuery = musicQuery.limit(limit)
                result = musicQuery.all()

            seen = set()
            musicData = []
            for song in result:
                songKey = (song.id, song.chart)
                if songKey not in seen:
                    seen.add(songKey)
                    musicData.append({
                        'db_id': song.id,
                        'id': song.songid,
                        'chart': song.chart,
                        'name': song.name,
                        'artist': song.artist,
                        'genre': song.genre,
                        'data': JsonEncoded.deserialize(song.data)
                    })

            if not song_ids:
                LocalCache().putCachedData(cacheName, musicData)

        return musicData
    
    @staticmethod
    def getAllSongs(game: str = None, version: int = None, song_ids: list[int] = None) -> list[dict]:
        cacheName = f'songs_{game}_{version}'
        resultData = None
        if not song_ids:
            resultData = LocalCache().getCachedData(cacheName)

        if not resultData:
            with MySQLBase.SessionLocal() as session:
                musicQuery = (
                    session.query(Music)
                    .filter(Music.game == game, Music.songid.in_(song_ids) if song_ids else True)
                    .order_by(Music.songid.desc(), Music.version.desc())
                )

                if version is not None:
                    musicQuery = musicQuery.filter(Music.version == version)

                result = musicQuery.all()

            seen = set()
            groupedSongs = {}

            for song in result:
                key = (song.id, song.chart)
                if key in seen:
                    continue
                seen.add(key)

                chartData = {
                    'db_id': song.id,
                    'chart': song.chart,
                    'data': JsonEncoded.deserialize(song.data)
                }

                if song.songid not in groupedSongs:
                    category = chartData.get('data', {}).get('category', None)
                    groupedSongs[song.songid] = {
                        'id': song.songid,
                        'name': song.name,
                        'artist': song.artist,
                        'genre': song.genre,
                        'version': category if category else song.version,
                        'charts': []
                    }

                groupedSongs[song.songid]['charts'].append(chartData)

            resultData = list(groupedSongs.values())

            if not song_ids:
                LocalCache().putCachedData(cacheName, resultData)

        return resultData
    
    @staticmethod
    def getSongByGameId(game: str, songId: int, version: int = None, chart: int = None) -> list[dict]:
        with MySQLBase.SessionLocal() as session:
            with MySQLBase.SessionLocal() as session:
                musicQuery = (
                    session.query(Music)
                    .filter(Music.game == game, Music.songid == songId)
                )

                if chart is not None:
                    musicQuery = musicQuery.filter(Music.chart == chart)

                if version is not None:
                    musicQuery = musicQuery.filter(Music.version == version)
                else:
                    latest = (
                        session.query(
                            func.max(Music.version).label("max_version")
                        )
                        .filter(Music.game == game, Music.songid == songId)
                        .scalar_subquery()
                    )

                    musicQuery = musicQuery.filter(Music.version == latest)

                result = musicQuery.order_by(Music.chart.asc()).all()

        seen = set()
        groupedSongs = {}

        for song in result:
            key = (song.id, song.chart)
            if key in seen:
                continue
            seen.add(key)

            chartData = {
                'db_id': song.id,
                'chart': song.chart,
                'data': JsonEncoded.deserialize(song.data)
            }

            if song.songid not in groupedSongs:
                groupedSongs[song.songid] = {
                    'id': song.songid,
                    'name': song.name,
                    'artist': song.artist,
                    'genre': song.genre,
                    'charts': []
                }

            groupedSongs[song.songid]['charts'].append(chartData)

        return list(groupedSongs.values())[0] if len(groupedSongs) == 1 else list(groupedSongs.values())
    
    @staticmethod
    def getHitChart(
        game: str,
        version: int,
        count: int,
        days: Optional[int] = None,
        lid: Optional[int] = None,
        userId: Optional[int] = None,
    ) -> List[Tuple[int, int]]:
        """
        Look up a game's most played songs.
        Returns: [(songid, plays), ...]
        """
        with MySQLBase.SessionLocal() as session:
            plays = func.count().label("plays")

            query = (
                session.query(
                    Music.songid.label("songid"),
                    plays,
                )
                .join(Attempt, Attempt.musicid == Music.id)
                .filter(
                    Music.game == game,
                    Music.version == version,
                )
            )

            if days is not None:
                timestamp = Time.now() - (Time.SECONDS_IN_DAY * days)
                query = query.filter(Attempt.timestamp > timestamp)

            if lid is not None:
                query = query.filter(Attempt.lid == lid)

            if userId is not None:
                query = query.filter(Attempt.userid == userId)

            results = (
                query
                .group_by(Music.songid)
                .order_by(plays.desc())
                .limit(count)
                .all()
            )

        return [(row.songid, row.plays) for row in results]