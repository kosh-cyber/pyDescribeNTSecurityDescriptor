import io,re,struct,random,binascii
from enums import *
from IntFlags import *
import pandas as pd



class SID(object):
    """
    Represents a Security Identifier (SID) in various formats and provides methods for manipulation and conversion between them.

    Attributes:
        revisionLevel (int): The revision level of the SID.
        subAuthorityCount (int): The number of sub-authorities in the SID.
        identifierAuthority (SID_IDENTIFIER_AUTHORITY): The identifier authority value.
        reserved (bytes): Reserved bytes, should always be empty.
        subAuthorities (list): A list of sub-authorities.
        relativeIdentifier (int): The relative identifier.

    Methods:
        load(data): Class method to load a SID from either a string or raw bytes.
        fromStrFormat(data): Class method to create a SID instance from a string representation.
        fromRawBytes(data): Class method to create a SID instance from raw bytes.

    See: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
    """
    
    bytesize = 0
    
    revisionLevel = 0
    subAuthorityCount = 0
    identifierAuthority = 0
    reserved = b''
    subAuthorities = []
    relativeIdentifier = 0

    wellKnownSIDs =  {
        "S-1-0-0": "Nobody",
        "S-1-1-0": "World",
        "S-1-2-0": "Local",
        "S-1-2-1": "Console Logon",
        "S-1-3-0": "Creator Owner",
        "S-1-3-1": "Creator Group",
        "S-1-3-2": "Creator Owner Server",
        "S-1-3-3": "Creator Owner Group",
        "S-1-3-4": "Owner rights",
        "S-1-5-1": "Dialup DIALUP",
        "S-1-5-2": "NT AUTHORITY\\NETWORK",
        "S-1-5-3": "NT AUTHORITY\\BATCH",
        "S-1-5-4": "NT AUTHORITY\\INTERACTIVE",
        #"S-1-5-5-x-y": "Logon SID identifying logon session. This SID can be queried using whoami.exe /logonid",
        "S-1-5-6": "SERVICE",
        "S-1-5-7": "ANONYMOUS LOGON",
        "S-1-5-8": "PROXY",
        "S-1-5-9": "ENTERPRISE DOMAIN CONTROLLERS",
        "S-1-5-10": "SELF",
        "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
        "S-1-5-12": "NT AUTHORITY\\RESTRICTED",
        "S-1-5-13": "TERMINAL SERVER USER",
        "S-1-5-14": "NT AUTHORITY\\REMOTE INTERACTIVE LOGON",
        "S-1-5-15": "NT AUTHORITY\\This Organization",
        "S-1-5-17": "NT AUTHORITY\\IUSR",
        "S-1-5-18": "NT AUTHORITY\\SYSTEM",
        "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
        "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
        #"S-1-5-21-…": "User accounts (and also domains?)",
        #"S-1-5-21-do-ma-in-500": "(local?) Administrator",
        #"S-1-5-21-do-ma-in-501": "A domain's guest account which allows users that don't have a domain account to log in",
        #"S-1-5-21-do-ma-in-503": "The Default Account (aka Default System Managed Account)",
        #"S-1-5-21-do-ma-in-504": "",
        "S-1-5-32": "The built-in domain, it contains groups that define roles on a local machine. BUILTIN",
        "S-1-5-32-544": "BUILTIN\\Administrators",
        "S-1-5-32-545": "BUILTIN\\Users",
        "S-1-5-32-546": "BUILTIN\\Guests",
        "S-1-5-32-547": "BUILTIN\\Power Users",
        "S-1-5-32-551": "BUILTIN\\Backup Operators",
        "S-1-5-32-552": "BUILTIN\\Replicator",
        "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
        "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
        "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
        "S-1-5-32-559": "BUILTIN\\Performance Log Users",
        "S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
        "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
        "S-1-5-32-573": "BUILTIN\\Event Log Readers",
        "S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
        "S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
        "S-1-5-32-581": "BUILTIN\\System Managed Accounts Group",
        "S-1-5-32-583": "BUILTIN\\Device Owners",
        "S-1-5-64-10": "NTLM Authentication",
        "S-1-5-80": "All services",
        # "S-1-5-80-…": "The SID of a particular service NT SERVICE\\…",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": "Trusted installer NT SERVICE\\TrustedInstaller",
        # "S-1-5-94-…": "Windows Remoting Virtual Users",
        "S-1-5-113": "Local account",
        "S-1-5-114": "Local account and member of Administrators group German: NT-AUTORITÄT\\Lokales Konto und Mitglied der Gruppse \"Administratoren\"",
        "S-1-15-2-1": "All applications running in an app package context. APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES",
        # "S-1-15-3-…": "All capability SIDs start with S-1-15-3.",
        # "S-1-16-…": "Mandatory Level See processes: integrity levels",
        "S-1-18-1": "Authentication authority asserted identity"
    }

    @classmethod
    def load(cls, data):
        self = None

        if type(data) == bytes and len(data) == 16:
            return SID.fromRawBytes(data)

        return self
    
    @classmethod
    def fromStrFormat(cls, data: str):
        """
        Creates a SID instance from a string representation.

        This method parses a string representation of a SID and initializes the class attributes based on the parsed values.
        The expected string format is "S-1-5-21-2127521184-1604012920-1887927527-171278", where each part after "S-1-" represents a sub-authority.

        Args:
            data (str): The string representation of a SID.

        Returns:
            SID: An instance of the SID class populated with the parsed data, or None if the string format is invalid.
        """

        matched = re.findall(r'(^S-(\d+)-(\d+))', data, re.IGNORECASE)
        if matched is not None:
            self = cls()

            return self
        else:
            return None

    @classmethod
    def fromRawBytes(cls, data: bytes):
        """
        Creates a SID instance from raw bytes.

        This method parses the raw bytes to extract the SID components according to the SID structure.
        It sets the class attributes based on the extracted values.

        Args:
            data (bytes): The raw bytes representing a SID.

        Returns:
            SID: An instance of the SID class populated with the parsed data.
        """

        self = cls()

        rawData = io.BytesIO(data)

        self.bytesize = 0

        self.revisionLevel = struct.unpack('<B', rawData.read(1))[0]
        self.bytesize += 1

        self.subAuthorityCount = struct.unpack('<B', rawData.read(1))[0]
        self.bytesize += 1

        __value = struct.unpack('>H', rawData.read(2))[0] << 16
        __value += struct.unpack('>H', rawData.read(2))[0] << 8
        __value += struct.unpack('>H', rawData.read(2))[0]

        self.identifierAuthority = SID_IDENTIFIER_AUTHORITY(__value)
        self.bytesize += 6

        self.subAuthorities = []
        for k in range(self.subAuthorityCount-1):
            self.subAuthorities.append(struct.unpack('<I', rawData.read(4))[0])
            self.bytesize += 4
        
        self.relativeIdentifier = struct.unpack('<I', rawData.read(4))[0]
        self.bytesize += 4

        return self
    
    def toRawBytes(self):
        """
        Converts the SID instance into its raw bytes representation.

        This method packs the SID attributes into a sequence of bytes according to the SID structure. It starts with the revision level, followed by the sub-authority count, the identifier authority, each of the sub-authorities, and finally the relative identifier.

        Returns:
            bytes: The raw bytes representation of the SID.
        """

        data = b''
        data += struct.pack("<B", self.revisionLevel)
        data += struct.pack("<B", self.subAuthorityCount)
        data += struct.pack(">H", self.identifierAuthority.value >> 16)
        data += struct.pack(">H", self.identifierAuthority.value >> 8)
        data += struct.pack(">H", self.identifierAuthority.value)
        for __subAuthority in self.subAuthorities:
            data += struct.pack("<I", __subAuthority)
        data += struct.pack("<I", self.relativeIdentifier)
        return data

    def toString(self):
        """
        Converts the SID instance into a string representation.

        This method constructs a string representation of the SID by concatenating the revision level, identifier authority value, sub-authorities, and the relative identifier, separated by hyphens. The string is prefixed with "S-" to denote a SID string.

        Returns:
            str: The string representation of the SID.
        """

        elements = [self.revisionLevel, self.identifierAuthority.value] + self.subAuthorities + [self.relativeIdentifier]

        return "S-%s" % '-'.join([str(e) for e in elements])
    
    def __str__(self):
        """
        Provides a string representation of the SID instance.

        This method returns a string representation of the SID. If the SID is recognized as a well-known SID, it returns the SID string directly. Otherwise, it appends the description of the SID (if available in the `wellKnownSIDs` dictionary) to the SID string.

        Returns:
            str: The string representation of the SID, optionally appended with its description.
        """
        str_repr = self.toString()
        if str_repr not in self.wellKnownSIDs.keys():
            return "<SID '%s'>" % str_repr
        else:
            return "<SID '%s' (%s)>" % (str_repr, self.wellKnownSIDs[str_repr])

    def describe(self, offset=0, indent=0):
        indent_prompt = " │ " * indent
        print("%s<SID at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        str_repr = self.toString()
        if str_repr not in self.wellKnownSIDs.keys():
            print("%s │ SID : %s" % (indent_prompt, str_repr))
        else:
            print("%s │ SID : %s (%s)" % (indent_prompt, str_repr, self.wellKnownSIDs[str_repr]))
        #print(''.join([" │ "]*indent + [" └─"])) 

SecurityIdentifier = SID

class InvalidGUIDFormat(Exception):
    pass

class GUID(object):
    """
    GUID

    See: https://docs.microsoft.com/en-us/dotnet/api/system.GUID?view=net-5.0
    """

    Format: GUIDFormat = None

    def __init__(self, a=None, b=None, c=None, d=None, e=None):
        super(GUID, self).__init__()
        if a is None:
            a = sum([random.randint(0, 0xff) << (8*k) for k in range(4)])
        if b is None:
            b = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
        if c is None:
            c = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
        if d is None:
            d = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
        if e is None:
            e = sum([random.randint(0, 0xff) << (8*k) for k in range(6)])
        self.a, self.b, self.c, self.d, self.e = a, b, c, d, e

    @classmethod
    def load(cls, data):
        self = None

        if type(data) == bytes and len(data) == 16:
            return GUID.fromRawBytes(data)

        elif type(data) == str:
            matched = re.match(GUIDImportFormatPattern.X.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatX(matched.group(0))
                self.Format = GUIDFormat.X
                return self

            matched = re.match(GUIDImportFormatPattern.P.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatP(matched.group(0))
                self.Format = GUIDFormat.P
                return self

            matched = re.match(GUIDImportFormatPattern.D.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatD(matched.group(0))
                self.Format = GUIDFormat.D
                return self

            matched = re.match(GUIDImportFormatPattern.B.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatB(matched.group(0))
                self.Format = GUIDFormat.B
                return self

            matched = re.match(GUIDImportFormatPattern.N.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatN(matched.group(0))
                self.Format = GUIDFormat.N
                return self

        return self

    # Import formats

    @classmethod
    def fromRawBytes(cls, data: bytes):
        if len(data) != 16:
            raise InvalidGUIDFormat("fromRawBytes takes exactly 16 bytes of data in input")
        # 0xffffff
        a = struct.unpack("<L", data[0:4])[0]
        # 0xffff
        b = struct.unpack("<H", data[4:6])[0]
        # 0xffff
        c = struct.unpack("<H", data[6:8])[0]
        # 0xffff
        d = struct.unpack(">H", data[8:10])[0]
        # 0xffffffffffff
        e = binascii.hexlify(data[10:16]).decode("UTF-8").rjust(6, '0')
        e = int(e, 16)
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatN(cls, data):
        # N => 32 digits : 00000000000000000000000000000000
        if not re.match(GUIDImportFormatPattern.N.value, data, re.IGNORECASE):
            raise InvalidGUIDFormat("GUID Format N should be 32 hexadecimal characters separated in five parts.")
        a = int(data[0:8], 16)
        b = int(data[8:12], 16)
        c = int(data[12:16], 16)
        d = int(data[16:20], 16)
        e = int(data[20:32], 16)
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatD(cls, data):
        # D => 32 digits separated by hyphens :
        # 00000000-0000-0000-0000-000000000000
        if not re.match(GUIDImportFormatPattern.D.value, data, re.IGNORECASE):
            raise InvalidGUIDFormat("GUID Format D should be 32 hexadecimal characters separated in five parts.")
        a, b, c, d, e = map(lambda x: int(x, 16), data.split("-"))
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatB(cls, data):
        # B => 32 digits separated by hyphens, enclosed in braces :
        # {00000000-0000-0000-0000-000000000000}
        if not re.match(GUIDImportFormatPattern.B.value, data, re.IGNORECASE):
            raise InvalidGUIDFormat("GUID Format B should be 32 hexadecimal characters separated in five parts enclosed in braces.")
        a, b, c, d, e = map(lambda x: int(x, 16), data[1:-1].split("-"))
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatP(cls, data):
        # P => 32 digits separated by hyphens, enclosed in parentheses :
        # (00000000-0000-0000-0000-000000000000)
        if not re.match(GUIDImportFormatPattern.P.value, data, re.IGNORECASE):
            raise InvalidGUIDFormat("GUID Format P should be 32 hexadecimal characters separated in five parts enclosed in parentheses.")
        a, b, c, d, e = map(lambda x: int(x, 16), data[1:-1].split("-"))
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatX(cls, data):
        # X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of
        # eight hexadecimal values that is also enclosed in braces :
        # {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
        if not re.match(GUIDImportFormatPattern.X.value, data, re.IGNORECASE):
            raise InvalidGUIDFormat("GUID Format X should be in this format {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}.")
        hex_a, hex_b, hex_c, rest = data[1:-1].split(',', 3)
        rest = rest[1:-1].split(',')
        a = int(hex_a, 16)
        b = int(hex_b, 16)
        c = int(hex_c, 16)
        d = int(rest[0], 16) * 0x100 + int(rest[1], 16)
        e = int(rest[2], 16) * (0x1 << (8 * 5))
        e += int(rest[3], 16) * (0x1 << (8 * 4))
        e += int(rest[4], 16) * (0x1 << (8 * 3))
        e += int(rest[5], 16) * (0x1 << (8 * 2))
        e += int(rest[6], 16) * (0x1 << 8)
        e += int(rest[7], 16)
        self = cls(a, b, c, d, e)
        return self

    # Export formats

    def toRawBytes(self):
        data = b''
        data += struct.pack("<L", self.a)
        data += struct.pack("<H", self.b)
        data += struct.pack("<H", self.c)
        data += struct.pack(">H", self.d)
        data += binascii.unhexlify(hex(self.e)[2:].rjust(12, '0'))
        return data

    def toFormatN(self) -> str:
        # N => 32 digits :
        # 00000000000000000000000000000000
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "%s%s%s%s%s" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatD(self) -> str:
        # D => 32 digits separated by hyphens :
        # 00000000-0000-0000-0000-000000000000
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "%s-%s-%s-%s-%s" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatB(self) -> str:
        # B => 32 digits separated by hyphens, enclosed in braces :
        # {00000000-0000-0000-0000-000000000000}
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "{%s-%s-%s-%s-%s}" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatP(self) -> str:
        # P => 32 digits separated by hyphens, enclosed in parentheses :
        # (00000000-0000-0000-0000-000000000000)
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "(%s-%s-%s-%s-%s)" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatX(self) -> str:
        # X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of
        # eight hexadecimal values that is also enclosed in braces :
        # {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_d1, hex_d2 = hex_d[:2], hex_d[2:4]
        hex_e = hex(self.e)[2:].rjust(12, '0')
        hex_e1, hex_e2, hex_e3, hex_e4, hex_e5, hex_e6 = hex_e[:2], hex_e[2:4], hex_e[4:6], hex_e[6:8], hex_e[8:10], hex_e[10:12]
        return "{0x%s,0x%s,0x%s,{0x%s,0x%s,0x%s,0x%s,0x%s,0x%s,0x%s,0x%s}}" % (hex_a, hex_b, hex_c, hex_d1, hex_d2, hex_e1, hex_e2, hex_e3, hex_e4, hex_e5, hex_e6)

    def __repr__(self):
        return "<GUID %s>" % self.toFormatB()

## 

class OwnerSID(object):
    """
    Represents an Owner Security Identifier (SID) in a security descriptor.

    Attributes:
        verbose (bool): If True, enables verbose output for debugging.
        value (bytes): The raw bytes representing the SID.
        bytesize (int): The size in bytes of the SID.
        sid (SID): An instance of the SID class representing the parsed SID.

    Methods:
        parse(value=None): Parses the raw bytes to extract the SID. Optionally takes a new value to parse.
        describe(offset=0, indent=0): Prints a formatted description of the OwnerSID, including its offset, size, and SID value.
    """

    def __init__(self, value, ldap_searcher=None, verbose=False):
        self.verbose = verbose
        self.value = value
        self.ldap_searcher = ldap_searcher
        self.displayName = None
        #
        self.bytesize = 0
        #
        self.parse()

    def parse(self, value=None):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))

        if value is not None:
            self.value = value

        self.sid = SID.fromRawBytes(self.value)
        self.bytesize = self.sid.bytesize

        # Resolve display Name
        __sid_str_repr = self.sid.toString()
        if __sid_str_repr in self.sid.wellKnownSIDs.keys():
            self.displayName = self.sid.wellKnownSIDs[__sid_str_repr]
        
        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        indent_prompt = " │ " * indent
        print("%s<OwnerSID at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        #print(''.join([" │ "]*indent + [" └─"]))


class GroupSID(object):
    """
    Represents a Group Security Identifier (SID) in a security descriptor.

    Attributes:
        verbose (bool): If True, enables verbose output for debugging.
        value (bytes): The raw bytes representing the SID.
        bytesize (int): The size in bytes of the SID.
        sid (SID): An instance of the SID class representing the parsed SID.

    Methods:
        parse(value=None): Parses the raw bytes to extract the SID. Optionally takes a new value to parse.
        describe(offset=0, indent=0): Prints a formatted description of the GroupSID, including its offset, size, and SID value.
    """

    def __init__(self, value, ldap_searcher=None, verbose=False):
        self.verbose = verbose
        self.value = value
        self.ldap_searcher = ldap_searcher
        self.displayName = None
        #
        self.bytesize = 0
        #
        self.parse()

    def parse(self, value=None):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))

        if value is not None:
            self.value = value

        self.sid = SID.fromRawBytes(self.value)
        self.bytesize = self.sid.bytesize

        # Resolve display Name
        __sid_str_repr = self.sid.toString()
        if __sid_str_repr in self.sid.wellKnownSIDs.keys():
            self.displayName = self.sid.wellKnownSIDs[__sid_str_repr]
        

        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        indent_prompt = " │ " * indent
        print("%s<GroupSID at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        if self.displayName is not None:
            print("%s │ SID : %s (%s)" % (indent_prompt, self.sid.toString(), self.displayName))
        else:
            print("%s │ SID : %s" % (indent_prompt, self.sid.toString()))
        #print(''.join([" │ "]*indent + [" └─"]))


class ACESID(object):
    """
    Represents an Access Control Entry's Security Identifier (SID) in a Discretionary Access Control List (DACL) or System Access Control List (SACL).

    Attributes:
        verbose (bool): If True, enables verbose output for debugging.
        value (bytes): The raw bytes representing the SID.
        bytesize (int): The size in bytes of the SID.
        sid (SID): An instance of the SID class representing the parsed SID.

    Methods:
        parse(value=None): Parses the raw bytes to extract the SID. Optionally takes a new value to parse.
        describe(offset=0, indent=0): Prints a formatted description of the ACESID, including its offset, size, and SID value.
    """

    def __init__(self, value, ldap_searcher=None, verbose=False):
        self.verbose = verbose
        self.value = value
        self.ldap_searcher = ldap_searcher
        self.displayName = None
        #
        self.bytesize = 0
        #
        self.parse()

    def parse(self, value=None):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))

        if value is not None:
            self.value = value

        self.sid = SID.fromRawBytes(self.value)
        self.bytesize = self.sid.bytesize

        # Resolve display Name
        __sid_str_repr = self.sid.toString()
        if __sid_str_repr in self.sid.wellKnownSIDs.keys():
            self.displayName = self.sid.wellKnownSIDs[__sid_str_repr]
        
        # Try to resolve it from the LDAP
        '''
        if self.displayName is None:
            if self.ldap_searcher is not None:
                search_base = ldap_server.info.other["defaultNamingContext"][0]
                __ldap_results = self.ldap_searcher.query(
                    base_dn=search_base,
                    query="(objectSid=%s)" % self.sid.toString(),
                    attributes=["sAMAccountName"]
                )
                if len(__ldap_results.keys()) != 0:
                    __dn = list(__ldap_results.keys())[0].upper()
                    __dc_string = "DC=" + __dn.split(',DC=',1)[1]
                    __domain = '.'.join([dc.replace('DC=','',1) for dc in __dc_string.split(',')])
                    self.displayName = "%s\\%s" % (__domain, __ldap_results[__dn.lower()]["sAMAccountName"])
        '''

        # 
        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        '''
        indent_prompt = " │ " * indent
        print("%s<ACESID at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        if self.displayName is not None:
            print("%s │ SID : %s (%s)" % (indent_prompt, self.sid.toString(), self.displayName))
        else:
            print("%s │ SID : %s" % (indent_prompt, self.sid.toString()))
        print(''.join([" │ "]*indent + [" └─"]))
        '''
        data = []

        # ACESID Header
        '''
        data.append({
            "Field": f"<ACESID at offset 0x{offset:x} (size=0x{self.bytesize:x})>",
            "Value": ""
        })
        '''

        # SID with or without displayName
        '''
        if self.displayName is not None:
\
            data.append({
                "SID": f"SID",
                "Value": f"{self.sid.toString()} ({self.displayName})"

        else:
            data.append({
                "Field": f"SID",
                "Value": f"{self.sid.toString()}"
            })
        '''
        data.append({
                "SID": f"{self.sid.toString()}"
            })
        # Convert to DataFrame
        df = pd.DataFrame(data)
        #print(df)
        return(df)

class AccessControlObjectType(object):
    """
    Represents an Access Control Object Type, which is a component of an Access Control Entry (ACE) that
    specifies the type of object or property to which an access control applies. This class parses and
    encapsulates the object type information from a binary representation into a more accessible form.

    Attributes:
        verbose (bool): If set to True, provides detailed parsing information.
        value (bytes): The binary representation of the Access Control Object Type.
        bytesize (int): The size in bytes of the Access Control Object Type.
        guid (GUID): The globally unique identifier (GUID) associated with the object type.
        flags (int): Flags that provide additional information about the object type.

    Methods:
        parse(value=None): Parses the binary representation to extract the GUID and flags.
        describe(offset=0, indent=0): Prints a formatted description of the Access Control Object Type.
    """

    def __init__(self, value, ldap_searcher=None, verbose=False):
        self.value = value
        self.ldap_searcher = ldap_searcher
        self.verbose = verbose
        #
        self.bytesize = 0
        self.ObjectTypeGuid = None
        self.ObjectTypeGuid_text = None
        self.InheritedObjectTypeGuid = None
        self.InheritedObjectTypeGuid_text = None
        self.flags = 0
        #
        self.parse()

    def parse(self, value=None):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))

        if value is not None:
            self.value = value

        rawData = io.BytesIO(self.value)

        self.bytesize = 4
        self.flags = AccessControlObjectTypeFlags(struct.unpack("<I", rawData.read(4))[0])

        # Todo create a function to parse the text

        if (self.flags & AccessControlObjectTypeFlags.ACE_OBJECT_TYPE_PRESENT) and (self.flags & AccessControlObjectTypeFlags.ACE_INHERITED_OBJECT_TYPE_PRESENT):
            self.bytesize += 16
            self.ObjectTypeGuid = GUID.fromRawBytes(rawData.read(16))
            self.ObjectTypeGuid_text = self.resolve_name(objectGuid=self.ObjectTypeGuid) 

            self.bytesize += 16
            self.InheritedObjectTypeGuid = GUID.fromRawBytes(rawData.read(16))
            self.InheritedObjectTypeGuid_text = self.resolve_name(objectGuid=self.InheritedObjectTypeGuid)

        elif (self.flags & AccessControlObjectTypeFlags.ACE_OBJECT_TYPE_PRESENT):
            self.bytesize += 16
            self.ObjectTypeGuid = GUID.fromRawBytes(rawData.read(16))
            self.ObjectTypeGuid_text = self.resolve_name(objectGuid=self.ObjectTypeGuid)

        elif (self.flags & AccessControlObjectTypeFlags.ACE_INHERITED_OBJECT_TYPE_PRESENT):
            self.bytesize += 16
            self.InheritedObjectTypeGuid = GUID.fromRawBytes(rawData.read(16))
            self.InheritedObjectTypeGuid_text = self.resolve_name(objectGuid=self.InheritedObjectTypeGuid)

        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        indent_prompt = " │ " * indent

        properties = []
        properties.append("Flags")
        if self.ObjectTypeGuid is not None:
            properties.append("ObjectTypeGuid")
        if self.InheritedObjectTypeGuid is not None:
            properties.append("InheritedObjectTypeGuid")
        padding_len = max([len(p) for p in properties])
        '''

        print("%s<AccessControlObjectType at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))       
       
        print("%s │ %s : 0x%08x (%s)" % (indent_prompt, "Flags".ljust(padding_len), self.flags.value, self.flags.name))
        
        if self.ObjectTypeGuid is not None:
            if self.ObjectTypeGuid_text is not None:
                print("%s │ %s : %s (%s)" % (indent_prompt, "ObjectTypeGuid".ljust(padding_len), self.ObjectTypeGuid.toFormatD(), self.ObjectTypeGuid_text))
            else:
                print("%s │ %s : %s" % (indent_prompt, "ObjectTypeGuid".ljust(padding_len), self.ObjectTypeGuid.toFormatD()))
        
        if self.InheritedObjectTypeGuid is not None:
            if self.InheritedObjectTypeGuid_text is not None:
                print("%s │ %s : %s (%s)" % (indent_prompt, "InheritedObjectTypeGuid".ljust(padding_len), self.InheritedObjectTypeGuid.toFormatD(), self.InheritedObjectTypeGuid_text))
            else:
                print("%s │ %s : %s" % (indent_prompt, "InheritedObjectTypeGuid".ljust(padding_len), self.InheritedObjectTypeGuid.toFormatD()))
        
        print(''.join([" │ "]*indent + [" └─"]))
        '''
        data = []

        # AccessControlObjectType Header
        data.append({
            "Field": f"{indent_prompt}<AccessControlObjectType at offset 0x{offset:x} (size=0x{self.bytesize:x})>",
            "Value": ""
        })

        # Flags
        data.append({
            "Field": f"{indent_prompt} {'Flags'.ljust(padding_len)}",
            "Value": f"0x{self.flags.value:08x} ({self.flags.name})"
        })

        # ObjectTypeGuid (if exists)
        if self.ObjectTypeGuid is not None:
            object_type_guid_value = self.ObjectTypeGuid.toFormatD()
            object_type_guid_text = self.ObjectTypeGuid_text
            if object_type_guid_text:
                data.append({
                    "Field": f"{indent_prompt} {'ObjectTypeGuid'.ljust(padding_len)}",
                    "Value": f"{object_type_guid_value} ({object_type_guid_text})"
                })
            else:
                data.append({
                    "Field": f"{indent_prompt} {'ObjectTypeGuid'.ljust(padding_len)}",
                    "Value": f"{object_type_guid_value}"
                })

        # InheritedObjectTypeGuid (if exists)
        if self.InheritedObjectTypeGuid is not None:
            inherited_object_type_guid_value = self.InheritedObjectTypeGuid.toFormatD()
            inherited_object_type_guid_text = self.InheritedObjectTypeGuid_text
            if inherited_object_type_guid_text:
                data.append({
                    "Field": f"{'InheritedObjectTypeGuid'.ljust(padding_len)}",
                    "Value": f"{inherited_object_type_guid_value} ({inherited_object_type_guid_text})"
                })
            else:
                data.append({
                    "Field": f"{'InheritedObjectTypeGuid'.ljust(padding_len)}",
                    "Value": f"{inherited_object_type_guid_value}"
                })

        # Convert to DataFrame
        df = pd.DataFrame(data)
        

    def resolve_name(self, objectGuid):
        name = None

        # Parse Extended Rights
        if objectGuid.toFormatD() in [_.value for _ in ExtendedRights]:
            name = "Extended Right %s" % ExtendedRights(objectGuid.toFormatD()).name
        
        # Parse Property Set
        elif objectGuid.toFormatD() in [_.value for _ in PropertySet]:
            name = "Property Set %s" % PropertySet(objectGuid.toFormatD()).name
        
        # Else, we don't know the object, print its GUID
        elif self.ldap_searcher is not None:
            if objectGuid.toFormatD() in self.ldap_searcher.schemaIDGUID.keys():
                name = "LDAP Attribute %s" % self.ldap_searcher.schemaIDGUID[objectGuid.toFormatD()]["ldapDisplayName"]   
        
        return name

    def __getitem__(self, key):
        return self.__data[key]

    def __setitem__(self, key, value):
        self.__data[key] = value

    def keys(self):
        return self.__data.keys()
    

class AccessControlMask(object):
    """
    This class represents the Access Control Mask, which is a set of bit flags that define access permissions to an object. These permissions can include the ability to read, write, execute, or delete an object, among others. The Access Control Mask is a crucial component of the security descriptor that defines the security of an object.

    The Access Control Mask is used in conjunction with Access Control Entries (ACEs) within an Access Control List (ACL) to define the security and access permissions for an object. Each ACE contains an Access Control Mask that specifies the permissions granted or denied by that ACE.

    Attributes:
        verbose (bool): If True, enables verbose output for debugging purposes.
        value (bytes): The raw bytes representing the Access Control Mask.
        bytesize (int): The size in bytes of the Access Control Mask.
        AccessMask (int): The integer value of the Access Control Mask, parsed from the raw bytes.
        __data (dict): A dictionary holding the parsed AccessMask and any flags associated with it.

    Methods:
        parse(value=None): Parses the raw bytes to extract the Access Control Mask. Optionally takes a new value to parse.
        describe(offset=0, indent=0): Prints a formatted description of the Access Control Mask, including its value and any flags associated with it.

    Source:
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
    """

    def __init__(self, value, verbose=False):
        self.verbose = verbose
        self.value = value
        self.bytesize = 4
        self.__data = {"AccessMask": 0}
        self.AccessMask = 0
        #
        self.parse()

    def parse(self, value=None):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))

        if value is not None:
            self.value = value

        rawData = io.BytesIO(self.value)

        self.__data = {"AccessMask": 0, "AccessMaskFlags":[]}

        self.__data["AccessMask"] = AccessMaskFlags(struct.unpack('<I', rawData.read(4))[0])
        self.AccessMask = self.__data["AccessMask"]

        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        '''
        indent_prompt = " │ " * indent
        print("%s<AccessControlMask at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        print("%s │ AccessMask : 0x%08x (%s)" % (
                indent_prompt,
                self.__data["AccessMask"].value,
                self.__data["AccessMask"].name
            )
        )
        print(''.join([" │ "]*indent + [" └─"]))
        '''
        data = []
        data.append({"AccessMask":f"{self.__data['AccessMask'].name}"})
        '''
        data = {
            "Field": [
                f"<AccessControlMask at offset 0x{offset:x} (size=0x{self.bytesize:x})>",
                "AccessMask"
            ],
            "Value": [
                "",  # 留空給 Header 描述
                f"0x{self.__data['AccessMask'].value:08x} ({self.__data['AccessMask'].name})"
            ]
        }
        '''
        df = pd.DataFrame(data)
        return df

    def __getitem__(self, key):
        return self.__data[key]

    def __setitem__(self, key, value):
        self.__data[key] = value

    def keys(self):
        return self.__data.keys()

class AccessControlEntry_Header(object):
    """
    Initializes an AccessControlEntry_Header object with the given binary data and optional verbosity flag.

    The AccessControlEntry_Header object represents the header of an Access Control Entry (ACE) in a security descriptor. 
    It contains information about the type of ACE, its flags, and its size. This information is crucial for interpreting 
    the ACE and applying the appropriate access control based on it.

    Parameters:
    - value (bytes): The binary data representing the ACE header.
    - verbose (bool, optional): A flag indicating whether to print detailed parsing information. Defaults to False.

    Attributes:
    - verbose (bool): Indicates whether detailed parsing information is printed.
    - value (bytes): The binary data representing the ACE header.
    - bytesize (int): The size of the ACE header in bytes.
    - __data (dict): A dictionary holding the parsed ACE header fields, including AceType, AceFlags, and AceSize.
    - AceType (AccessControlEntry_Type): The type of the ACE, indicating the action (e.g., allow or deny) and the object it applies to.
    - AceFlags (AccessControlEntry_Flags): Flags providing additional information about the ACE, such as inheritance rules.
    - AceSize (int): The size of the ACE, including the header and the specific data associated with the ACE type.

    Methods:
    - parse(self, value=None): Parses the binary data to populate the ACE header fields. If 'value' is provided, it updates the 'value' attribute before parsing.
    - describe(self, offset=0, indent=0): Prints a formatted description of the ACE header, including its type, flags, and size. 'offset' and 'indent' parameters allow for formatted output within larger structures.

    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
    https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header
    """
    def __init__(self, value, verbose=False):
        self.verbose = verbose
        self.value = value
        self.bytesize = 4
        self.__data = {
            "AceType": 0,
            "AceFlags": 0,
            "AceSize": 0
        }
        self.AceType = 0
        self.AceFlags = 0
        self.AceSize = 0
        #
        self.parse()
    
    def parse(self, value=None):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))

        if value is not None:
            self.value = value

        rawData = io.BytesIO(self.value)

        self.__data = {
            "AceType": 0,
            "AceFlags": 0,
            "AceSize": 0
        }
        self.AceType = 0
        self.AceFlags = 0
        self.AceSize = 0

        self.bytesize = 0

        

        # Parsing header
        
        self.__data["AceType"] = AccessControlEntry_Type(struct.unpack('<B', rawData.read(1))[0])
        self.AceType = self.__data["AceType"]
        self.bytesize += 1

        self.__data["AceFlags"] = AccessControlEntry_Flags(struct.unpack('<B', rawData.read(1))[0])
        self.AceFlags = self.__data["AceFlags"]
        self.bytesize += 1

        self.__data["AceSize"] = struct.unpack('<H', rawData.read(2))[0]
        self.AceSize = int(self.__data["AceSize"])
        self.bytesize += 2    

        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        '''
        indent_prompt = " │ " * indent
        print("%s<AccessControlEntry_Header at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        print("%s │ AceType  : 0x%02x (%s)" % (indent_prompt, self.__data["AceType"].value, self.__data["AceType"].name))
        print("%s │ AceFlags : 0x%02x (%s)" % (indent_prompt, self.__data["AceFlags"].value, self.__data["AceFlags"].name))
        print("%s │ AceSize  : 0x%04x" % (indent_prompt, self.__data["AceSize"]))
        print(''.join([" │ "]*indent + [" └─"]))
        '''
        data = []
        
        data.append({
        "AceType": f"{self.__data['AceType'].name}",
        "AceFlags":f"{self.__data['AceFlags'].name}",
        "AceSize": f"0x{self.__data['AceSize']:04x}"
        })
        df = pd.DataFrame(data)
        #print(df)
        return df

    def __getitem__(self, key):
        return self.__data[key]

    def __setitem__(self, key, value):
        self.__data[key] = value


class AccessControlEntry(object):
    def __init__(self, value, ldap_searcher=None, verbose=False):
        
        self.verbose = verbose
        self.value = value
        self.ldap_searcher = ldap_searcher
        #
        self.bytesize = 0
        self.header = None
        self.mask = None
        self.object_type = None
        self.ace_sid = None
        #
        self.parse()

    def parse(self):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))
        
        # Parsing header
        self.header = AccessControlEntry_Header(value=self.value, verbose=self.verbose)
        self.value = self.value[self.header.bytesize:]
        self.bytesize = self.header.bytesize
        
        if (self.header.AceType.value == AccessControlEntry_Type.ACCESS_ALLOWED_ACE_TYPE.value):
            # Parsing ACE of type ACCESS_ALLOWED_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb
            
            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize
            
            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize
            
        elif (self.header.AceType.value == AccessControlEntry_Type.ACCESS_DENIED_ACE_TYPE.value):
            # Parsing ACE of type ACCESS_DENIED_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/b1e1321d-5816-4513-be67-b65d8ae52fe8

            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize
            
            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_AUDIT_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_AUDIT_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/9431fd0f-5b9a-47f0-b3f0-3015e2d0d4f9

            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize
            
            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            # An access attempt of a kind specified by the Mask field by any trustee whose SID
            # matches the Sid field causes the system to generate an audit message. If an application
            # does not specify a SID for this field, audit messages are generated for the specified
            # access rights for all trustees.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_ALARM_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_ALARM_ACE_TYPE
            # Source: ?
            
            # Reserved for future use.
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

            pass

        elif (self.header.AceType.value == AccessControlEntry_Type.ACCESS_ALLOWED_COMPOUND_ACE_TYPE.value):
            # Parsing ACE of type ACCESS_ALLOWED_COMPOUND_ACE_TYPE
            # Source: ?
            
            # Reserved for future use.
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

            pass

        elif (self.header.AceType.value == AccessControlEntry_Type.ACCESS_ALLOWED_OBJECT_ACE_TYPE.value):
            # Parsing ACE of type ACCESS_ALLOWED_OBJECT_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
            
            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize
            
            # Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
            # indicate whether the ObjectType and InheritedObjectType fields contain valid data.
            # This parameter can be one or more of the following values.
            #
            # ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
            # or type of child object. The purpose of this GUID depends on the user rights specified
            # in the Mask field. This field is valid only if the ACE _OBJECT_TYPE_PRESENT bit is set
            # in the Flags field. Otherwise, the ObjectType field is ignored. For information on
            # access rights and for a mapping of the control access rights to the corresponding GUID
            # value that identifies each right, see [MS-ADTS] sections 5.1.3.2 and 5.1.3.2.1.
            # ACCESS_MASK bits are not mutually exclusive. Therefore, the ObjectType field can be set
            # in an ACE with any ACCESS_MASK. If the AccessCheck algorithm calls this ACE and does not
            # find an appropriate GUID, then that ACE will be ignored. For more information on access
            # checks and object access, see [MS-ADTS] section 5.1.3.3.3.
            # 
            # InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
            # can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
            # ACE_HEADER, as well as by any protection against inheritance placed on the child
            # objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
            # in the Flags member. Otherwise, the InheritedObjectType field is ignored.
            self.object_type = AccessControlObjectType(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.object_type.bytesize:]
            self.bytesize += self.object_type.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

        elif (self.header.AceType.value == AccessControlEntry_Type.ACCESS_DENIED_OBJECT_ACE_TYPE.value):
            # Parsing ACE of type ACCESS_DENIED_OBJECT_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/8720fcf3-865c-4557-97b1-0b3489a6c270
                        
            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize
            
            # Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
            # indicate whether the ObjectType and InheritedObjectType fields contain valid data.
            # This parameter can be one or more of the following values.
            #
            # ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
            # or type of child object. The purpose of this GUID depends on the user rights specified
            # in the Mask field. This field is valid only if the ACE _OBJECT_TYPE_PRESENT bit is set
            # in the Flags field. Otherwise, the ObjectType field is ignored. For information on
            # access rights and for a mapping of the control access rights to the corresponding GUID
            # value that identifies each right, see [MS-ADTS] sections 5.1.3.2 and 5.1.3.2.1.
            # ACCESS_MASK bits are not mutually exclusive. Therefore, the ObjectType field can be set
            # in an ACE with any ACCESS_MASK. If the AccessCheck algorithm calls this ACE and does not
            # find an appropriate GUID, then that ACE will be ignored. For more information on access
            # checks and object access, see [MS-ADTS] section 5.1.3.3.3.
            # 
            # InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
            # can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
            # ACE_HEADER, as well as by any protection against inheritance placed on the child
            # objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
            # in the Flags member. Otherwise, the InheritedObjectType field is ignored.
            self.object_type = AccessControlObjectType(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.object_type.bytesize:]
            self.bytesize += self.object_type.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_AUDIT_OBJECT_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_AUDIT_OBJECT_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c8da72ae-6b54-4a05-85f4-e2594936d3d5

            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize
            
            # Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
            # indicate whether the ObjectType and InheritedObjectType fields contain valid data.
            # This parameter can be one or more of the following values.
            #
            # ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
            # or type of child object. The purpose of this GUID depends on the user rights specified
            # in the Mask field. This field is valid only if the ACE _OBJECT_TYPE_PRESENT bit is set
            # in the Flags field. Otherwise, the ObjectType field is ignored. For information on
            # access rights and for a mapping of the control access rights to the corresponding GUID
            # value that identifies each right, see [MS-ADTS] sections 5.1.3.2 and 5.1.3.2.1.
            # ACCESS_MASK bits are not mutually exclusive. Therefore, the ObjectType field can be set
            # in an ACE with any ACCESS_MASK. If the AccessCheck algorithm calls this ACE and does not
            # find an appropriate GUID, then that ACE will be ignored. For more information on access
            # checks and object access, see [MS-ADTS] section 5.1.3.3.3.
            # 
            # InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
            # can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
            # ACE_HEADER, as well as by any protection against inheritance placed on the child
            # objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
            # in the Flags member. Otherwise, the InheritedObjectType field is ignored.
            self.object_type = AccessControlObjectType(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.object_type.bytesize:]
            self.bytesize += self.object_type.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

            # ApplicationData (variable): Optional application data. The size of the application
            # data is determined by the AceSize field of the ACE_HEADER.
            # TODO

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_ALARM_OBJECT_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_ALARM_OBJECT_ACE_TYPE
            # Source: ?
            
            # Reserved for future use.
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

            pass

        elif (self.header.AceType.value == AccessControlEntry_Type.ACCESS_ALLOWED_CALLBACK_ACE_TYPE.value):
            # Parsing ACE of type ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c9579cf4-0f4a-44f1-9444-422dfb10557a

            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

            # ApplicationData (variable): Optional application data. The size of the application
            # data is determined by the AceSize field of the ACE_HEADER.
            # TODO

        elif (self.header.AceType.value == AccessControlEntry_Type.ACCESS_DENIED_CALLBACK_ACE_TYPE.value):
            # Parsing ACE of type ACCESS_DENIED_CALLBACK_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/35adad6b-fda5-4cc1-b1b5-9beda5b07d2e

            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

            # ApplicationData (variable): Optional application data. The size of the application
            # data is determined by the AceSize field of the ACE_HEADER.
            # TODO

        elif (self.header.AceType.value == AccessControlEntry_Type.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE.value):
            # Parsing ACE of type ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            # Source: 
            
            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize
            
            # Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
            # indicate whether the ObjectType and InheritedObjectType fields contain valid data.
            # This parameter can be one or more of the following values.
            #
            # ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
            # or type of child object. The purpose of this GUID depends on the user rights specified
            # in the Mask field. This field is valid only if the ACE _OBJECT_TYPE_PRESENT bit is set
            # in the Flags field. Otherwise, the ObjectType field is ignored. For information on
            # access rights and for a mapping of the control access rights to the corresponding GUID
            # value that identifies each right, see [MS-ADTS] sections 5.1.3.2 and 5.1.3.2.1.
            # ACCESS_MASK bits are not mutually exclusive. Therefore, the ObjectType field can be set
            # in an ACE with any ACCESS_MASK. If the AccessCheck algorithm calls this ACE and does not
            # find an appropriate GUID, then that ACE will be ignored. For more information on access
            # checks and object access, see [MS-ADTS] section 5.1.3.3.3.
            # 
            # InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
            # can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
            # ACE_HEADER, as well as by any protection against inheritance placed on the child
            # objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
            # in the Flags member. Otherwise, the InheritedObjectType field is ignored.
            self.object_type = AccessControlObjectType(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.object_type.bytesize:]
            self.bytesize += self.object_type.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

            # ApplicationData (variable): Optional application data. The size of the application
            # data is determined by the AceSize field of the ACE_HEADER.
            # TODO

        elif (self.header.AceType.value == AccessControlEntry_Type.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE.value):
            # Parsing ACE of type ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            # Source: 
            
            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize
            
            # Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
            # indicate whether the ObjectType and InheritedObjectType fields contain valid data.
            # This parameter can be one or more of the following values.
            #
            # ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
            # or type of child object. The purpose of this GUID depends on the user rights specified
            # in the Mask field. This field is valid only if the ACE _OBJECT_TYPE_PRESENT bit is set
            # in the Flags field. Otherwise, the ObjectType field is ignored. For information on
            # access rights and for a mapping of the control access rights to the corresponding GUID
            # value that identifies each right, see [MS-ADTS] sections 5.1.3.2 and 5.1.3.2.1.
            # ACCESS_MASK bits are not mutually exclusive. Therefore, the ObjectType field can be set
            # in an ACE with any ACCESS_MASK. If the AccessCheck algorithm calls this ACE and does not
            # find an appropriate GUID, then that ACE will be ignored. For more information on access
            # checks and object access, see [MS-ADTS] section 5.1.3.3.3.
            # 
            # InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
            # can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
            # ACE_HEADER, as well as by any protection against inheritance placed on the child
            # objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
            # in the Flags member. Otherwise, the InheritedObjectType field is ignored.
            self.object_type = AccessControlObjectType(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.object_type.bytesize:]
            self.bytesize += self.object_type.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

            # ApplicationData (variable): Optional application data. The size of the application
            # data is determined by the AceSize field of the ACE_HEADER.
            # TODO

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_AUDIT_CALLBACK_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/bd6b6fd8-4bef-427e-9a43-b9b46457e934

            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

            # ApplicationData (variable): Optional application data. The size of the application
            # data is determined by the AceSize field of the ACE_HEADER.
            # TODO

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_ALARM_CALLBACK_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_ALARM_CALLBACK_ACE_TYPE
            # Source: ?
            
            # Reserved for future use.
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

            pass

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            # Source: 

            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize

            # Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
            # indicate whether the ObjectType and InheritedObjectType fields contain valid data.
            # This parameter can be one or more of the following values.
            #
            # ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
            # or type of child object. The purpose of this GUID depends on the user rights specified
            # in the Mask field. This field is valid only if the ACE _OBJECT_TYPE_PRESENT bit is set
            # in the Flags field. Otherwise, the ObjectType field is ignored. For information on
            # access rights and for a mapping of the control access rights to the corresponding GUID
            # value that identifies each right, see [MS-ADTS] sections 5.1.3.2 and 5.1.3.2.1.
            # ACCESS_MASK bits are not mutually exclusive. Therefore, the ObjectType field can be set
            # in an ACE with any ACCESS_MASK. If the AccessCheck algorithm calls this ACE and does not
            # find an appropriate GUID, then that ACE will be ignored. For more information on access
            # checks and object access, see [MS-ADTS] section 5.1.3.3.3.
            # 
            # InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
            # can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
            # ACE_HEADER, as well as by any protection against inheritance placed on the child
            # objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
            # in the Flags member. Otherwise, the InheritedObjectType field is ignored.
            self.object_type = AccessControlObjectType(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.object_type.bytesize:]
            self.bytesize += self.object_type.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

            # ApplicationData (variable): Optional application data. The size of the application
            # data is determined by the AceSize field of the ACE_HEADER.
            # TODO

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
            # Source: ?
            
            # Reserved for future use.
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586 

            pass

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_MANDATORY_LABEL_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_MANDATORY_LABEL_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/25fa6565-6cb0-46ab-a30a-016b32c4939a

            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize
            
            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/352944c7-4fb6-4988-8036-0a25dcedc730

            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

            # ApplicationData (variable): Optional application data. The size of the application
            # data is determined by the AceSize field of the ACE_HEADER.
            # TODO

        elif (self.header.AceType.value == AccessControlEntry_Type.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE.value):
            # Parsing ACE of type SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
            # Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/aa0c0f62-4b4c-44f0-9718-c266a6accd9f

            # Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
            self.mask = AccessControlMask(value=self.value, verbose=self.verbose)
            self.value = self.value[self.mask.bytesize:]
            self.bytesize += self.mask.bytesize

            # Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
            self.ace_sid = ACESID(value=self.value, ldap_searcher=self.ldap_searcher, verbose=self.verbose)
            self.value = self.value[self.ace_sid.bytesize:]
            self.bytesize += self.ace_sid.bytesize

            # ApplicationData (variable): Optional application data. The size of the application
            # data is determined by the AceSize field of the ACE_HEADER.
            # TODO

        if self.verbose:
            self.describe()

    def describe(self, ace_number=0, offset=0, indent=0):
        #accessControlEntrydf = pd.DataFrame()
        # AccessControlEntry struct
        '''

        indent_prompt = " │ " * indent
        print("%s<AccessControlEntry #%d at offset 0x%x (size=0x%x)>" % (indent_prompt, ace_number, offset, self.bytesize))
        '''
        data = []
        data.append({
        f"AccessControlEntry":f"#{ace_number}",
        "offset": f"0x{offset:x}",
        "size":f"0x{self.bytesize:x}"
        })
        df = pd.DataFrame(data)
        #print(df)
        headerdf = self.header.describe(offset=offset, indent=(indent + 1))
        accessControlEntrydf = pd.concat([df,headerdf],axis=1)
        #print(accessControlEntrydf.to_string())
        offset += self.header.bytesize
        
        #self.mask.describe(offset=offset, indent=(indent + 1))
        maskdf = self.mask.describe(offset=offset, indent=(indent + 1))
        accessControlEntrydf = pd.concat([accessControlEntrydf,maskdf],axis=1)
        #print(accessControlEntrydf.to_string())
        offset += self.mask.bytesize
                
        if self.object_type is not None:
            #self.object_type.describe(offset=offset, indent=(indent + 1))
            object_typedf = self.object_type.describe(offset=offset, indent=(indent + 1))
            accessControlEntrydf = pd.concat([accessControlEntrydf,object_typedf],axis=1)
        
        if self.ace_sid is not None:
            #self.ace_sid.describe(offset=offset, indent=(indent + 1))
            ace_siddf = self.ace_sid.describe(offset=offset, indent=(indent + 1))
            accessControlEntrydf = pd.concat([accessControlEntrydf,ace_siddf],axis=1)
        
        #print(accessControlEntrydf.to_string())
        return accessControlEntrydf

        #print(''.join([" │ "]*indent + [" └─"]))

## SACL

class SystemAccessControlList_Header(object):
    """
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
    https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl
    """

    def __init__(self, value, verbose=False):
        self.verbose = verbose
        self.value = value
        self.bytesize = 8
        #
        self.Revision = 0
        self.Sbz1 = 0
        self.AclSize = 0
        self.AceCount = 0
        self.Sbz2 = 0
        #
        self.__data = {
            "Revision": 0,
            "Sbz1": 0,
            "AclSize": 0,
            "AceCount": 0,
            "Sbz2": 0
        }
        #
        self.parse()

    def parse(self, value=None):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))
    
        if value is not None:
            self.value = value

        rawData = io.BytesIO(self.value)

        self.__data = {"Revision": 0, "Sbz1": 0, "AclSize": 0, "AceCount": 0, "Sbz2": 0}

        # Parsing header
        self.__data["Revision"] = AccessControlList_Revision(struct.unpack('<B', rawData.read(1))[0])
        self.Revision = self.__data["Revision"] 

        self.__data["Sbz1"] = struct.unpack('<B', rawData.read(1))[0]
        self.Sbz1 = self.__data["Sbz1"] 

        self.__data["AclSize"] = struct.unpack('<H', rawData.read(2))[0]
        self.AclSize = self.__data["AclSize"] 

        self.__data["AceCount"] = struct.unpack('<H', rawData.read(2))[0]
        self.AceCount = self.__data["AceCount"] 

        self.__data["Sbz2"] = struct.unpack('<H', rawData.read(2))[0]
        self.Sbz2 = self.__data["Sbz2"] 

        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        '''
        indent_prompt = " │ " * indent
        print("%s<SystemAccessControlList_Header at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        print("%s │ Revision : 0x%02x (%s)" % (indent_prompt, self.Revision.value, self.Revision.name))
        print("%s │ Sbz1     : 0x%02x" % (indent_prompt, self.__data["Sbz1"]))
        print("%s │ AclSize  : 0x%04x" % (indent_prompt, self.__data["AclSize"]))
        print("%s │ AceCount : 0x%04x" % (indent_prompt, self.__data["AceCount"]))
        print("%s │ Sbz2     : 0x%04x" % (indent_prompt, self.__data["Sbz2"]))
        print(''.join([" │ "]*indent + [" └─"]))
        '''

    def __getitem__(self, key):
        return self.__data[key]

    def __setitem__(self, key, value):
        self.__data[key] = value

    def keys(self):
        return self.__data.keys()


class SystemAccessControlList(object):
    def __init__(self, value, ldap_searcher=None, verbose=False):
        self.verbose = verbose
        self.value = value
        #
        self.bytesize = 0
        #
        self.header = None
        self.entries = []
        self.ldap_searcher = ldap_searcher
        #
        self.parse()

    def parse(self):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))
    
        self.header = SystemAccessControlList_Header(value=self.value)
        self.bytesize += self.header.bytesize
        self.value = self.value[self.header.bytesize:]

        # Parsing ACE entries
        self.entries = []
        for k in range(self.header["AceCount"]):
            ace = AccessControlEntry(value=self.value, verbose=self.verbose, ldap_searcher=self.ldap_searcher)
            self.entries.append(ace)

            self.bytesize += ace.bytesize
            self.value = self.value[(ace.bytesize):]

        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        indent_prompt = " │ " * indent
        #print("%s<SystemAccessControlList at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        self.header.describe(offset=offset, indent=(indent + 1))
        offset += self.header.bytesize
        ace_number = 0
        for ace in self.entries:
            ace_number += 1
            ace.describe(ace_number=ace_number, offset=offset, indent=(indent + 1))
            offset += ace.bytesize
        #print(''.join([" │ "]*indent + [" └─"]))

    def __getitem__(self, key):
        return self.entries[key]

    def __setitem__(self, key, value):
        self.entries[key] = value

    def __iter__(self):
        yield from self.entries

    def __len__(self):
        return len(self.entries)

## DACL

class DiscretionaryAccessControlList_Header(object):
    """
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
    https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl
    """

    def __init__(self, value, verbose=False):
        self.verbose = verbose
        self.value = value
        self.bytesize = 8
        #
        self.Revision = 0
        self.Sbz1 = 0
        self.AclSize = 0
        self.AceCount = 0
        self.Sbz2 = 0
        #
        self.__data = {
            "Revision": 0,
            "Sbz1": 0,
            "AclSize": 0,
            "AceCount": 0,
            "Sbz2": 0
        }
        #
        self.parse()

    def parse(self, value=None):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))

        if value is not None:
            self.value = value

        rawData = io.BytesIO(self.value)

        self.__data = {"Revision": 0, "Sbz1": 0, "AclSize": 0, "AceCount": 0, "Sbz2": 0}

        # Parsing header
        self.__data["Revision"] = AccessControlList_Revision(struct.unpack('<B', rawData.read(1))[0])
        self.Revision = self.__data["Revision"] 

        self.__data["Sbz1"] = struct.unpack('<B', rawData.read(1))[0]
        self.Sbz1 = self.__data["Sbz1"] 

        self.__data["AclSize"] = struct.unpack('<H', rawData.read(2))[0]
        self.AclSize = self.__data["AclSize"] 

        self.__data["AceCount"] = struct.unpack('<H', rawData.read(2))[0]
        self.AceCount = self.__data["AceCount"] 

        self.__data["Sbz2"] = struct.unpack('<H', rawData.read(2))[0]
        self.Sbz2 = self.__data["Sbz2"] 

        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        '''
        indent_prompt = " │ " * indent
        print("%s<DiscretionaryAccessControlList_Header at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        print("%s │ Revision : 0x%02x (%s)" % (indent_prompt, self.Revision.value, self.Revision.name))
        print("%s │ Sbz1     : 0x%02x" % (indent_prompt, self.__data["Sbz1"]))
        print("%s │ AclSize  : 0x%04x" % (indent_prompt, self.__data["AclSize"]))
        print("%s │ AceCount : 0x%04x" % (indent_prompt, self.__data["AceCount"]))
        print("%s │ Sbz2     : 0x%04x" % (indent_prompt, self.__data["Sbz2"]))
        print(''.join([" │ "]*indent + [" └─"]))
        '''
        data = []
        data.append({"Revision":f"{self.Revision.name}",
                     "Sbz1":f"0x{self.__data["Sbz1"]:02x}",
                     "AclSize":f"0x{self.__data["AclSize"]:04x}",
                     "AceCount":f"0x{self.__data["AceCount"]:04x}",
                     "Sbz2":f"0x{self.__data['Sbz2']:04x}"})
        '''
        # DiscretionaryAccessControlList_Header
        data.append({
            "Field": f"<DiscretionaryAccessControlList_Header at offset 0x{offset:x} (size=0x{self.bytesize:x})>",
            "Value": ""
        })

        # Revision
        data.append({
            "Field": f"Revision",
            "Value": f"0x{self.Revision.value:02x} ({self.Revision.name})"
        })

        # Sbz1
        data.append({
            "Field": f"Sbz1",
            "Value": f"0x{self.__data["Sbz1"]:02x}"
        })

        # AclSize
        data.append({
            "Field": f"AclSize",
            "Value": f"0x{self.__data["AclSize"]:04x}"
        })

        # AceCount
        data.append({
            "Field": f"AceCount",
            "Value": f"0x{self.__data["AceCount"]:04x}"
        })

        # Sbz2
        data.append({
            "Field": f"Sbz2",
            "Value": f"0x{self.__data['Sbz2']:04x}"
        })
        '''

        # Convert to DataFrame
        df = pd.DataFrame(data)
        print(df)

    def __getitem__(self, key):
        return self.__data[key]

    def __setitem__(self, key, value):
        self.__data[key] = value

    def keys(self):
        return self.__data.keys()


class DiscretionaryAccessControlList(object):
    def __init__(self, value, ldap_searcher=None, verbose=False):
        self.verbose = verbose
        self.value = value
        #
        self.bytesize = 0
        #
        self.header = None
        self.entries = []
        self.ldap_searcher = ldap_searcher
        self.dataframe = None
        #
        self.parse()

    def parse(self):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))
        
        self.header = DiscretionaryAccessControlList_Header(value=self.value[:8], verbose=self.verbose)
        self.bytesize += self.header.bytesize
        self.value = self.value[self.header.bytesize:]

        # Parsing ACE entries
        self.entries = []
        for k in range(self.header["AceCount"]):
            ace = AccessControlEntry(value=self.value, verbose=self.verbose, ldap_searcher=self.ldap_searcher)
            self.entries.append(ace)

            self.bytesize += ace.bytesize
            self.value = self.value[(ace.bytesize):]

        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        #indent_prompt = " │ " * indent
        
        #print("%s<DiscretionaryAccessControlList at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        #self.header.describe(offset=offset, indent=(indent + 1))
        offset += self.header.bytesize
        ace_number = 0
        '''
        data = []
        data.append({
        "Field": f"<DiscretionaryAccessControlList #{ace_number} at offset 0x{offset:x} (size=0x{self.bytesize:x})>",
        "Value": ""
        })
        df = pd.DataFrame(data)
        print(df)
        '''
        for ace in self.entries:
            ace_number += 1
            self.dataframe = pd.concat([self.dataframe,ace.describe(ace_number=ace_number, offset=offset, indent=(indent + 1))],axis=0, ignore_index=True)
            offset += ace.bytesize
        
        #print(self.dataframe.to_string)
        return self.dataframe
        #print(''.join([" │ "]*indent + [" └─"]))

    def __getitem__(self, key):
        return self.entries[key]

    def __setitem__(self, key, value):
        self.entries[key] = value

    def __iter__(self):
        yield from self.entries

    def __len__(self):
        return len(self.entries)


class NTSecurityDescriptor_Header(object):
    def __init__(self, value, verbose=False):
        self.bytesize = 20
        self.value = value
        self.__data = {
            "Revision": 0,
            "Sbz1": 0,
            "Control": 0,
            "OffsetOwner": 0,
            "OffsetGroup": 0,
            "OffsetSacl": 0,
            "OffsetDacl": 0
        }
        self.Revision = 0
        self.Sbz1 = 0
        self.Control = 0
        self.OffsetOwner = 0
        self.OffsetGroup = 0
        self.OffsetSacl = 0
        self.sacl = None
        self.OffsetDacl = 0
        self.dacl = None
        self.verbose = verbose
        #
        self.parse()

    def parse(self, value=None):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value[:self.bytesize])))

        if value is not None:
            self.value = value

        rawData = io.BytesIO(self.value)

        self.__data = {"Revision": 0, "Sbz1": 0, "Control": 0, "OffsetOwner": 0, "OffsetGroup": 0, "OffsetSacl": 0, "OffsetDacl": 0}

        # Parsing header
        self.__data["Revision"] = struct.unpack('<B', rawData.read(1))[0]
        self.Revision = self.__data["Revision"]
        
        self.__data["Sbz1"] = struct.unpack('<B', rawData.read(1))[0]
        self.Sbz1 = self.__data["Sbz1"]

        self.__data["Control"] = struct.unpack('<H', rawData.read(2))[0]
        self.Control = self.__data["Control"]

        self.__data["OffsetOwner"] = struct.unpack('<I', rawData.read(4))[0]
        self.OffsetOwner = self.__data["OffsetOwner"]

        self.__data["OffsetGroup"] = struct.unpack('<I', rawData.read(4))[0]
        self.OffsetGroup = self.__data["OffsetGroup"]

        self.__data["OffsetSacl"] = struct.unpack('<I', rawData.read(4))[0]
        self.OffsetSacl = self.__data["OffsetSacl"]

        self.__data["OffsetDacl"] = struct.unpack('<I', rawData.read(4))[0]
        self.OffsetDacl = self.__data["OffsetDacl"]

        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        #indent_prompt = " │ " * indent
        data = {
        "Field": ["Header at offset", "Revision", "Sbz1", "Control", "OffsetOwner", "OffsetGroup", "OffsetSacl", "OffsetDacl"],
        "Value": [
            f"<NTSecurityDescriptor_Header at offset 0x{offset:x} (size=0x{self.bytesize:x})>",
            f"0x{self.__data['Revision']:02x}",
            f"0x{self.__data['Sbz1']:02x}",
            f"0x{self.__data['Control']:04x}",
            f"0x{self.__data['OffsetOwner']:08x}",
            f"0x{self.__data['OffsetGroup']:08x}",
            f"0x{self.__data['OffsetSacl']:08x}",
            f"0x{self.__data['OffsetDacl']:08x}"
        ]
    
        }
        df = pd.DataFrame(data)
        print(df)
        '''
        print("%s<NTSecurityDescriptor_Header at offset 0x%x (size=0x%x)>" % (indent_prompt, offset, self.bytesize))
        print("%s │ Revision    : 0x%02x" % (indent_prompt, self.__data["Revision"]))
        print("%s │ Sbz1        : 0x%02x" % (indent_prompt, self.__data["Sbz1"]))
        print("%s │ Control     : 0x%04x" % (indent_prompt, self.__data["Control"]))
        print("%s │ OffsetOwner : 0x%08x" % (indent_prompt, self.__data["OffsetOwner"]))
        print("%s │ OffsetGroup : 0x%08x" % (indent_prompt, self.__data["OffsetGroup"]))
        print("%s │ OffsetSacl  : 0x%08x" % (indent_prompt, self.__data["OffsetSacl"]))
        print("%s │ OffsetDacl  : 0x%08x" % (indent_prompt, self.__data["OffsetDacl"]))
        print(''.join([" │ "]*indent + [" └─"]))
        '''

    def __getitem__(self, key):
        return self.__data[key]

    def __setitem__(self, key, value):
        self.__data[key] = value

    def keys(self):
        return self.__data.keys()


class NTSecurityDescriptor(object):
    def __init__(self, value, ldap_searcher=None, verbose=False):
        self.value = value
        #print(self.value)
        # Properties of this section
        self.header = None
        self.dacl = None
        self.sacl = None
        self.owner = None
        self.group = None
        self.verbose = verbose
        self.ldap_searcher = ldap_searcher
        # 
        self.parse()

    def parse(self):
        if self.verbose:
            print("[>] Parsing %s\n  | value: %s" % (__class__, binascii.hexlify(self.value)))
        self.header = NTSecurityDescriptor_Header(value=self.value, verbose=self.verbose)
        self.value = self.value[self.header.bytesize:]

        # Parse OwnerSID if present
        if self.header.OffsetOwner == 0:
            self.owner = None
        else:
            self.owner = OwnerSID(
                value=self.value[self.header.OffsetOwner-self.header.bytesize:], 
                verbose=self.verbose,
                ldap_searcher=self.ldap_searcher
            )

        # Parse GroupSID if present
        if self.header.OffsetGroup == 0:
            self.group = None
        else:
            self.group = GroupSID(
                value=self.value[self.header.OffsetGroup-self.header.bytesize:], 
                verbose=self.verbose,
                ldap_searcher=self.ldap_searcher
            )

        # Parse DACL if present
        if self.header.OffsetDacl == 0:
            self.dacl = None
        else:
            self.dacl = DiscretionaryAccessControlList(
                value=self.value[self.header.OffsetDacl-self.header.bytesize:], 
                verbose=self.verbose,
                ldap_searcher=self.ldap_searcher
            )
        
        # Parse SACL if present
        if self.header.OffsetSacl == 0:
            self.sacl = None
        else:
            self.sacl = SystemAccessControlList(
                value=self.value[self.header.OffsetSacl-self.header.bytesize:], 
                verbose=self.verbose,
                ldap_searcher=self.ldap_searcher
            )

        if self.verbose:
            self.describe()

    def describe(self, offset=0, indent=0):
        #print("<NTSecurityDescriptor>")
        #self.header.describe(offset=offset, indent=indent+1)
        offset += self.header.bytesize
        if self.header.OffsetDacl < self.header.OffsetSacl:
            # Print DACL
            if self.dacl is not None:
                self.dacl.describe(offset=self.header.OffsetDacl, indent=indent+1)
            else:
                #print("%s<DiscretionaryAccessControlList is not present>" % (" │ " * (indent+1)))
                print("DiscretionaryAccessControlList is not present")
                #print("%s └─" % (" │ " * (indent+1)))
            # Print SACL
            '''
            if self.sacl is not None:
                self.sacl.describe(offset=self.header.OffsetSacl, indent=indent+1)
            else:
                #print("%s<SystemAccessControlList is not present>" % (" │ " * (indent+1)))
                print("SystemAccessControlList is not present>")
                #print("%s └─" % (" │ " * (indent+1)))
            '''
        else:
            # Print SACL
            '''
            if self.sacl is not None:
                self.sacl.describe(offset=self.header.OffsetSacl, indent=indent+1)
            else:
                #print("%s<SystemAccessControlList is not present>" % (" │ " * (indent+1)))
                print("SystemAccessControlList is not present>")
                #print("%s └─" % (" │ " * (indent+1)))
             '''
            # Print DACL
            if self.dacl is not None:
                return self.dacl.describe(offset=self.header.OffsetDacl, indent=indent+1)
            else:
                #print("%s<DiscretionaryAccessControlList is not present>" % (" │ " * (indent+1)))
                print("<DiscretionaryAccessControlList is not present>")
                #print("%s └─" % (" │ " * (indent+1)))
        #print(" └─")


