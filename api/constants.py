from typing import Optional, List, Dict, Any

def intish(val: Any, base: int=10) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val, base)
    except ValueError:
        return None

class APIConstants:
    def goodEnd(data: dict) -> dict:
        return {'status': 'success', 'error_code': None, 'data': data}

    def badEnd(error: str) -> dict:
        return {'status': 'error', 'error_code': error}
    
    def softEnd(error: str) -> dict:
        return {'status': 'warn', 'error_code': error}
    
class GameConstants:
    BEATSTREAM = 'bst'
    BISHI_BASHI = 'bishi'
    BISHI_BASHI_NEW = 'newbishi'
    DANCE_EVOLUTION = 'danevo'
    DANCE_RUSH = 'dancerush'
    DDR = 'ddr'
    DDRCLASS = 'ddrclass'
    DDROMNI = 'ddromni'
    DRUMMANIA = 'dm'
    EEMALL = 'eemall'
    FUTURETOMTOM = 'ftt'
    GITADORA_DM = 'gitadora_dm'
    GITADORA_GF = 'gitadora_gf'
    GUITARFREAKS = 'gf'
    IIDX = 'iidx'
    IIDXCLASS = 'iidxclass'
    JUBEAT = 'jubeat'
    LOVEPLUS = 'loveplus'
    MGA = 'metalgear'
    MUSECA = 'museca'
    NOSTALGIA = 'nost'
    OTOMEDIUS = 'oto'
    OTOCA = 'otoca'
    POPN_HELLO = 'hpm'
    POPN_MUSIC = 'pnm'
    QMA = 'qma'
    REFLEC_BEAT = 'reflec'
    ROAD_FIGHTERS = 'roadfighters'
    SDVX = 'sdvx'
    SILENT_HILL = 'sha'
    SILENT_SCOPE = 'scope'
    TSUMTSUM = 'tsum'
    WINNING_ELEVEN = 'weac'
    SCOTTO = 'scotto'
    PASELI = 'paseli'
    MFC = 'mahjong'

class VersionConstants:
    BISHI_BASHI_TSBB = 1
    BISHI_BASHI_CN = 1

    ROAD_FIGHTERS_DDD = 1

    DANCE_EVOLUTION_GAME = 1

    OTOCA_DOLL = 1

    BEATSTREAM = 1
    BEATSTREAM_2 = 2

    NOSTALGIA = 1
    NOSTALGIA_FORTE = 2
    NOSTALGIA_OP_2 = 3
    NOSTALGIA_OP_3 = 4

    OTOMEDIUS = 1

    EEMALL_1ST = 1
    EEMALL_2ND = 2

    FUTURETOMTOM = 1
    FUTURETOMTOM_VER2 = 2

    DDR_1STMIX = 1
    DDR_2NDMIX = 2
    DDR_3RDMIX = 3
    DDR_4THMIX = 4
    DDR_5THMIX = 5
    DDR_6THMIX = 6
    DDR_7THMIX = 7
    DDR_EXTREME = 8
    DDR_SUPERNOVA = 9
    DDR_SUPERNOVA_2 = 10
    DDR_X = 11
    DDR_X2 = 12
    DDR_X3_VS_2NDMIX = 13
    DDR_2013 = 14
    DDR_2014 = 15
    DDR_ACE = 16
    DDR_A20 = 17
    DDR_A20_PLUS = 18
    DDR_A3 = 19
    DDR_WORLD = 20

    DDR_OMNI_1STMIX = 1
    DDR_OMNI_2NDMIX = 2
    DDR_OMNI_3RDMIX = 3
    DDR_OMNI_4THMIX = 4
    DDR_OMNI_5THMIX = 5
    DDR_OMNI_6THMIX = 6
    DDR_OMNI_7THMIX = 7
    DDR_OMNI_EXTREME = 8
    DDR_OMNI_SUPERNOVA = 9
    DDR_OMNI_SUPERNOVA_2 = 10
    DDR_OMNI_X = 11
    DDR_OMNI_X2 = 12
    DDR_OMNI_X3 = 13
    DDR_OMNI_2013 = 14
    DDR_OMNI_2014 = 15
    DDR_OMNI_ACE = 16
    DDR_OMNI_A20 = 17
    DDR_OMNI_MIX = 18
    DDR_OMNI_CS = 200

    CLASSIC_DDR_1STMIX = 1
    CLASSIC_DDR_2NDMIX = 2
    CLASSIC_DDR_3RDMIX = 3
    CLASSIC_DDR_4THMIX = 4
    CLASSIC_DDR_5THMIX = 5
    CLASSIC_DDR_6THMIX = 6
    CLASSIC_DDR_7THMIX = 7
    CLASSIC_DDR_EXTREME = 8
    CLASSIC_DDR_SUPERNOVA = 9
    CLASSIC_DDR_SUPERNOVA_2 = 10
    CLASSIC_DDR_X = 11

    DRUMMANIA_1ST = 1
    DRUMMANIA_2ND = 2
    DRUMMANIA_3RD = 3
    DRUMMANIA_4TH = 4
    DRUMMANIA_5TH = 5
    DRUMMANIA_6TH = 6
    DRUMMANIA_7TH = 7
    DRUMMANIA_8TH = 8
    DRUMMANIA_9TH = 9
    DRUMMANIA_10TH = 10
    DRUMMANIA_V = 11
    DRUMMANIA_V2 = 12
    DRUMMANIA_V3 = 13
    DRUMMANIA_V4 = 14
    DRUMMANIA_V5 = 15
    DRUMMANIA_V6 = 16
    DRUMMANIA_V7 = 17
    DRUMMANIA_V8 = 18

    GUITARFREAKS_1ST = 0
    GUITARFREAKS_2ND = 1
    GUITARFREAKS_3RD = 2
    GUITARFREAKS_4TH = 3
    GUITARFREAKS_5TH = 4
    GUITARFREAKS_6TH = 5
    GUITARFREAKS_7TH = 6
    GUITARFREAKS_8TH = 7
    GUITARFREAKS_9TH = 8
    GUITARFREAKS_10TH = 9
    GUITARFREAKS_11TH = 10
    GUITARFREAKS_V = 11
    GUITARFREAKS_V2 = 12
    GUITARFREAKS_V3 = 13
    GUITARFREAKS_V4 = 14
    GUITARFREAKS_V5 = 15
    GUITARFREAKS_V6 = 16
    GUITARFREAKS_V7 = 17
    GUITARFREAKS_V8 = 18

    GITADORA = 1
    GITADORA_OVERDRIVE = 2
    GITADORA_TRIBOOST = 3
    GITADORA_TRIBOOST_RE_EVOLVE = 4
    GITADORA_MATIXX = 5
    GITADORA_EXCHAIN = 6
    GITADORA_NEXTAGE = 7
    GITADORA_HIGH_VOLTAGE = 8
    GITADORA_FUZZUP = 9

    IIDXCLASS = 1
    IIDXCLASS_2ND_STYLE = 2
    IIDXCLASS_3RD_STYLE = 3
    IIDXCLASS_4TH_STYLE = 4
    IIDXCLASS_5TH_STYLE = 5
    IIDXCLASS_6TH_STYLE = 6
    IIDXCLASS_7TH_STYLE = 7
    IIDXCLASS_8TH_STYLE = 8
    IIDXCLASS_9TH_STYLE = 9
    IIDXCLASS_10TH_STYLE = 10
    IIDXCLASS_RED = 11
    IIDXCLASS_HAPPY_SKY = 12
    IIDXCLASS_DISTORTED = 13
    IIDXCLASS_GOLD = 14
    IIDXCLASS_DJ_TROOPERS = 15
    IIDXCLASS_EMPRESS = 16
    IIDXCLASS_SIRIUS = 17
    IIDXCLASS_RESORT_ANTHEM = 18
    IIDXCLASS_LINCLE = 19
    
    IIDX = 1
    IIDX_2ND_STYLE = 2
    IIDX_3RD_STYLE = 3
    IIDX_4TH_STYLE = 4
    IIDX_5TH_STYLE = 5
    IIDX_6TH_STYLE = 6
    IIDX_7TH_STYLE = 7
    IIDX_8TH_STYLE = 8
    IIDX_9TH_STYLE = 9
    IIDX_10TH_STYLE = 10
    IIDX_RED = 11
    IIDX_HAPPY_SKY = 12
    IIDX_DISTORTED = 13
    IIDX_GOLD = 14
    IIDX_DJ_TROOPERS = 15
    IIDX_EMPRESS = 16
    IIDX_SIRIUS = 17
    IIDX_RESORT_ANTHEM = 18
    IIDX_LINCLE = 19
    IIDX_TRICORO = 20
    IIDX_SPADA = 21
    IIDX_PENDUAL = 22
    IIDX_COPULA = 23
    IIDX_SINOBUZ = 24
    IIDX_CANNON_BALLERS = 25
    IIDX_ROOTAGE = 26
    IIDX_HEROIC_VERSE = 27
    IIDX_BISTROVER = 28
    IIDX_CASTHOUR = 29
    IIDX_RESIDENT = 30
    IIDX_EPOLIS = 31

    JUBEAT = 1
    JUBEAT_RIPPLES = 2
    JUBEAT_RIPPLES_APPEND = 3
    JUBEAT_KNIT = 4
    JUBEAT_KNIT_APPEND = 5
    JUBEAT_COPIOUS = 6
    JUBEAT_COPIOUS_APPEND = 7
    JUBEAT_SAUCER = 8
    JUBEAT_SAUCER_FULFILL = 9
    JUBEAT_PROP = 10
    JUBEAT_QUBELL = 11
    JUBEAT_CLAN = 12
    JUBEAT_FESTO = 13
    JUBEAT_AVE = 14

    MUSECA = 1
    MUSECA_1_PLUS = 2

    POPN_MUSIC = 1
    POPN_MUSIC_2 = 2
    POPN_MUSIC_3 = 3
    POPN_MUSIC_4 = 4
    POPN_MUSIC_5 = 5
    POPN_MUSIC_6 = 6
    POPN_MUSIC_7 = 7
    POPN_MUSIC_8 = 8
    POPN_MUSIC_9 = 9
    POPN_MUSIC_10 = 10
    POPN_MUSIC_11 = 11
    POPN_MUSIC_IROHA = 12
    POPN_MUSIC_CARNIVAL = 13
    POPN_MUSIC_FEVER = 14
    POPN_MUSIC_ADVENTURE = 15
    POPN_MUSIC_PARTY = 16
    POPN_MUSIC_THE_MOVIE = 17
    POPN_MUSIC_SENGOKU_RETSUDEN = 18
    POPN_MUSIC_TUNE_STREET = 19
    POPN_MUSIC_FANTASIA = 20
    POPN_MUSIC_SUNNY_PARK = 21
    POPN_MUSIC_LAPISTORIA = 22
    POPN_MUSIC_ECLALE = 23
    POPN_MUSIC_USANEKO = 24
    POPN_MUSIC_PEACE = 25
    POPN_MUSIC_KAIMEI_RIDDLES = 26
    POPN_MUSIC_UNILAB = 27

    HELLO_POPN_MUSIC = 1

    REFLEC_BEAT = 1
    REFLEC_BEAT_LIMELIGHT = 2
    REFLEC_BEAT_COLETTE = 3
    REFLEC_BEAT_GROOVIN = 4
    REFLEC_BEAT_VOLZZA = 5
    REFLEC_BEAT_VOLZZA_2 = 6
    REFLEC_BEAT_REFLESIA = 7

    SDVX_BOOTH = 1
    SDVX_INFINITE_INFECTION = 2
    SDVX_GRAVITY_WARS = 3
    SDVX_HEAVENLY_HAVEN = 4
    SDVX_VIVID_WAVE = 5
    SDVX_EXCEED_GEAR = 6

    QMA = 1
    QMA_II = 2
    QMA_III = 3
    QMA_IV = 4
    QMA_V = 5
    QMA_VI = 6
    QMA_VII = 7
    QMA_VIII = 8
    QMA_GATE = 9
    QMA_CAMPUS = 10
    QMA_DAWN = 11
    QMA_TOKYO = 12
    QMA_EVOLVE = 13
    QMA_MAXIVCORD = 14
    QMA_XROSS_VOYAGE = 15
    QMA_KIBOU = 16
    QMA_MUGEN = 17

    SILENT_HILL_THE_ARCADE = 1

    SILENT_SCOPE_BONE_EATER = 1

    LOVEPLUS_ARCADE = 1
    LOVEPLUS_CC = 2

    WINNING_ELEVEN_2008 = 1
    WINNING_ELEVEN_2010 = 2
    WINNING_ELEVEN_2012 = 3
    WINNING_ELEVEN_2014 = 4

    DISNEY_TSUM_TSUM = 1

    MGA = 1

    DANCERUSH_STARDOM = 1

    SCOTTO = 1 # lol

    PASELI_CHARGE_MACHINE = 1

    MFC_ZERO = 24
    
class ValidatedDict(dict):
    """
    ValidatedDict is the amazing work Dragonminded. 100% of this code is her work.

    Helper class which gives a Dict object superpowers. Allows stores and loads to be
    validated so you only ever update when given good data, and only ever return
    non-default values when data is good. Used primarily for storing data pulled
    directly from game responses, or reading data to echo to a game.

    All of the get functions will verify that the attribute exists and is the right
    type. If it is not, the default value is returned.

    all of the set functions will verify that the to-be-stored value matches the
    type. If it does not, the value is not updated.
    """

    def get_int(self, name: str, default: int=0) -> int:
        """
        Given the name of a value, return an integer stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't an integer.

        Returns:
            An integer.
        """
        val = self.get(name)
        if val is None:
            return default
        if type(val) != int:
            return default
        return val

    def get_float(self, name: str, default: float=0.0) -> float:
        """
        Given the name of a value, return a float stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't a float.

        Returns:
            A float.
        """
        val = self.get(name)
        if val is None:
            return default
        if type(val) != float:
            return default
        return val

    def get_bool(self, name: str, default: bool=False) -> bool:
        """
        Given the name of a value, return a boolean stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't a boolean.

        Returns:
            A boolean.
        """
        val = self.get(name)
        if val is None:
            return default
        if type(val) != bool:
            return default
        return val

    def get_str(self, name: str, default: str='') -> str:
        """
        Given the name of a value, return string stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't a string.

        Returns:
            A string.
        """
        val = self.get(name)
        if val is None:
            return default
        if type(val) != str:
            return default
        return val

    def get_bytes(self, name: str, default: bytes=b'') -> bytes:
        """
        Given the name of a value, return bytes stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't bytes.

        Returns:
            A bytestring.
        """
        val = self.get(name)
        if val is None:
            return default
        if type(val) != bytes:
            return default
        return val

    def get_int_array(self, name: str, length: int, default: Optional[List[int]]=None) -> List[int]:
        """
        Given the name of a value, return a list of integers stored under that name.

        Parameters:
            name - Name of attribute
            length - The expected length of the array
            default - The default to return if the value doesn't exist, or isn't a list of integers
                      of the right length.

        Returns:
            A list of integers.
        """
        if default is None:
            default = [0] * length
        if len(default) != length:
            raise Exception('Gave default of wrong length!')

        val = self.get(name)
        if val is None:
            return default
        if type(val) != list:
            return default
        if len(val) != length:
            return default
        for v in val:
            if type(v) != int:
                return default
        return val

    def get_bool_array(self, name: str, length: int, default: Optional[List[bool]]=None) -> List[bool]:
        """
        Given the name of a value, return a list of booleans stored under that name.

        Parameters:
            name - Name of attribute
            length - The expected length of the array
            default - The default to return if the value doesn't exist, or isn't a list of booleans
                      of the right length.

        Returns:
            A list of booleans.
        """
        if default is None:
            default = [False] * length
        if len(default) != length:
            raise Exception('Gave default of wrong length!')

        val = self.get(name)
        if val is None:
            return default
        if type(val) != list:
            return default
        if len(val) != length:
            return default
        for v in val:
            if type(v) != bool:
                return default
        return val

    def get_bytes_array(self, name: str, length: int, default: Optional[List[bytes]]=None) -> List[bytes]:
        """
        Given the name of a value, return a list of bytestrings stored under that name.

        Parameters:
            name - Name of attribute
            length - The expected length of the array
            default - The default to return if the value doesn't exist, or isn't a list of bytestrings
                      of the right length.

        Returns:
            A list of bytestrings.
        """
        if default is None:
            default = [b''] * length
        if len(default) != length:
            raise Exception('Gave default of wrong length!')

        val = self.get(name)
        if val is None:
            return default
        if type(val) != list:
            return default
        if len(val) != length:
            return default
        for v in val:
            if type(v) != bytes:
                return default
        return val

    def get_str_array(self, name: str, length: int, default: Optional[List[str]]=None) -> List[str]:
        """
        Given the name of a value, return a list of strings stored under that name.

        Parameters:
            name - Name of attribute
            length - The expected length of the array
            default - The default to return if the value doesn't exist, or isn't a list of strings
                      of the right length.

        Returns:
            A list of strings.
        """
        if default is None:
            default = [''] * length
        if len(default) != length:
            raise Exception('Gave default of wrong length!')

        val = self.get(name)
        if val is None:
            return default
        if type(val) != list:
            return default
        if len(val) != length:
            return default
        for v in val:
            if type(v) != str:
                return default
        return val

    def get_dict(self, name: str, default: Optional[Dict[Any, Any]]=None) -> 'ValidatedDict':
        """
        Given the name of a value, return a dictionary stored under that name.

        Parameters:
            name - Name of attribute
            default - The default to return if the value doesn't exist, or isn't a dictionary.

        Returns:
            A dictionary, wrapped with this helper class so the same helper methods may be called.
        """
        if default is None:
            default = {}
        validateddefault = ValidatedDict(default)

        val = self.get(name)
        if val is None:
            return validateddefault
        if not isinstance(val, dict):
            return validateddefault
        return ValidatedDict(val)

    def replace_int(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually an integer.
        """
        if val is None:
            return
        if type(val) != int:
            return
        self[name] = val

    def replace_float(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually a float
        """
        if val is None:
            return
        if type(val) != float:
            return
        self[name] = val

    def replace_bool(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually a boolean.
        """
        if val is None:
            return
        if type(val) != bool:
            return
        self[name] = val

    def replace_str(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually a string.
        """
        if val is None:
            return
        if type(val) != str:
            return
        self[name] = val

    def replace_bytes(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually a bytestring.
        """
        if val is None:
            return
        if type(val) != bytes:
            return
        self[name] = val

    def replace_int_array(self, name: str, length: int, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            length - Expected length of the list
            val - The value to store, if it is actually a list of integers containing length elements.
        """
        if val is None:
            return
        if type(val) != list:
            return
        if len(val) != length:
            return
        for v in val:
            if type(v) != int:
                return
        self[name] = val

    def replace_bool_array(self, name: str, length: int, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            length - Expected length of the list
            val - The value to store, if it is actually a list of booleans containing length elements.
        """
        if val is None:
            return
        if type(val) != list:
            return
        if len(val) != length:
            return
        for v in val:
            if type(v) != bool:
                return
        self[name] = val

    def replace_bytes_array(self, name: str, length: int, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            length - Expected length of the list
            val - The value to store, if it is actually a list of bytestrings containing length elements.
        """
        if val is None:
            return
        if type(val) != list:
            return
        if len(val) != length:
            return
        for v in val:
            if type(v) != bytes:
                return
        self[name] = val

    def replace_str_array(self, name: str, length: int, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            length - Expected length of the list
            val - The value to store, if it is actually a list of strings containing length elements.
        """
        if val is None:
            return
        if type(val) != list:
            return
        if len(val) != length:
            return
        for v in val:
            if type(v) != str:
                return
        self[name] = val

    def replace_dict(self, name: str, val: Any) -> None:
        """
        Given the name of a value and a new value to store, update that value.

        Parameters:
            name - Name of attribute
            val - The value to store, if it is actually a dictionary.
        """
        if val is None:
            return
        if not isinstance(val, dict):
            return
        self[name] = val

    def increment_int(self, name: str) -> None:
        """
        Given the name of a value, increment the value by 1.

        If the value doesn't exist or isn't an integer, converts it to an integer
        and sets it to 1 (as if it was 0 before). If it is an integer, increments
        it by 1.

        Parameters:
            name - Name of attribute
        """
        if name not in self:
            self[name] = 1
        elif type(self[name]) != int:
            self[name] = 1
        else:
            self[name] = self[name] + 1
