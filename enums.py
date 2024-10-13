from enum import Enum, IntFlag

class PropertySet(Enum):
    """
    PropertySet is an enumeration of GUIDs representing various property sets in Active Directory.
    These property sets group related properties of AD objects, making it easier to manage and apply permissions to these properties.
    Each entry in this enumeration maps a human-readable name to the corresponding GUID of the property set.
    These GUIDs are used in Access Control Entries (ACEs) to grant or deny permissions to read or write a set of properties on AD objects.

    The GUIDs are defined by Microsoft and can be found in the Microsoft documentation and technical specifications.
    Property sets are a crucial part of the Active Directory schema and help in defining the security model by allowing fine-grained access control.

    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/177c0db5-fa12-4c31-b75a-473425ce9cca
    """
    DOMAIN_PASSWORD_AND_LOCKOUT_POLICIES = "c7407360-20bf-11d0-a768-00aa006e0529"
    GENERAL_INFORMATION = "59ba2f42-79a2-11d0-9020-00c04fc2d3cf"
    ACCOUNT_RESTRICTIONS = "4c164200-20c0-11d0-a768-00aa006e0529"
    LOGON_INFORMATION = "5f202010-79a5-11d0-9020-00c04fc2d4cf"
    GROUP_MEMBERSHIP = "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"
    PHONE_AND_MAIL_OPTIONS = "e45795b2-9455-11d1-aebd-0000f80367c1"
    PERSONAL_INFORMATION = "77b5b886-944a-11d1-aebd-0000f80367c1"
    WEB_INFORMATION = "e45795b3-9455-11d1-aebd-0000f80367c1"
    PUBLIC_INFORMATION = "e48d0154-bcf8-11d1-8702-00c04fb96050"
    REMOTE_ACCESS_INFORMATION = "037088f8-0ae1-11d2-b422-00a0c968f939"
    OTHER_DOMAIN_PARAMETERS_FOR_USE_BY_SAM = "b8119fd0-04f6-4762-ab7a-4986c76b3f9a"
    DNS_HOST_NAME_ATTRIBUTES = "72e39547-7b18-11d1-adef-00c04fd8d5cd"
    MS_TS_GATEWAYACCESS = "ffa6f046-ca4b-4feb-b40d-04dfee722543"
    PRIVATE_INFORMATION = "91e647de-d96f-4b70-9557-d63ff4f3ccd8"
    TERMINAL_SERVER_LICENSE_SERVER = "5805bc62-bdc9-4428-a5e2-856a0f4c185e"


class ExtendedRights(Enum):
    """
    ExtendedRights is an enumeration of GUIDs representing various extended rights in Active Directory.
    These rights are associated with specific operations that can be performed on AD objects.
    Each entry in this enumeration maps a human-readable name to the corresponding GUID of the extended right.
    These GUIDs are used in Access Control Entries (ACEs) to grant or deny these rights to security principals (users, groups, etc.).

    The rights include, but are not limited to, the ability to create or delete specific types of child objects,
    force password resets, read/write specific properties, and more. They play a crucial role in defining
    the security model of Active Directory by allowing fine-grained access control to objects.

    The GUIDs are defined by Microsoft and can be found in the Microsoft documentation and technical specifications.

    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/443fe66f-c9b7-4c50-8c24-c708692bbf1d
    """

    # 
    ABANDON_REPLICATION = "ee914b82-0a98-11d1-adbb-00c04fd8d5cd"
	#
    ADD_GUID = "440820ad-65b4-11d1-a3da-0000f875ae0d"
	#
    ALLOCATE_RIDS = "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd"
	#
    ALLOWED_TO_AUTHENTICATE = "68b1d179-0d15-4d4f-ab71-46152e79a7bc"
	#
    APPLY_GROUP_POLICY = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
    # 
    CERTIFICATE_ENROLLMENT = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	# 
    CHANGE_DOMAIN_MASTER = "014bf69c-7b3b-11d1-85f6-08002be74fab"
	# 
    CHANGE_INFRASTRUCTURE_MASTER = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd"
	# 
    CHANGE_PDC = "bae50096-4752-11d1-9052-00c04fc2d4cf"
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fcb2b5e7-302f-43cb-8adf-4c9cd9423178
    CHANGE_RID_MASTER = "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd"
	# 
    CHANGE_SCHEMA_MASTER = "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd"
	# 
    CREATE_INBOUND_FOREST_TRUST = "e2a36dc9-ae17-47c3-b58b-be34c55ba633"
	# 
    DO_GARBAGE_COLLECTION = "fec364e0-0a98-11d1-adbb-00c04fd8d5cd"
	# 
    DOMAIN_ADMINISTER_SERVER = "ab721a52-1e2f-11d0-9819-00aa0040529b"
	# 
    DS_CHECK_STALE_PHANTOMS = "69ae6200-7f46-11d2-b9ad-00c04f79f805"
	# 
    DS_CLONE_DOMAIN_CONTROLLER = "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e"
	# 
    DS_EXECUTE_INTENTIONS_SCRIPT = "2f16c4a5-b98e-432c-952a-cb388ba33f2e"
	# 
    DS_INSTALL_REPLICA = "9923a32a-3607-11d2-b9be-0000f87a36b2"
	# 
    DS_QUERY_SELF_QUOTA = "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc"
	# 
    DS_REPLICATION_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	# 
    DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	# 
    DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET = "89e95b76-444d-4c62-991a-0facbeda640c"
	# 
    DS_REPLICATION_MANAGE_TOPOLOGY = "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2"
	# 
    DS_REPLICATION_MONITOR_TOPOLOGY = "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96"
	# 
    DS_REPLICATION_SYNCHRONIZE = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
	# 
    ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD = "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5"
	# 
    GENERATE_RSOP_LOGGING = "b7b1b3de-ab09-4242-9e30-9980e5d322f7"
	# 
    GENERATE_RSOP_PLANNING = "b7b1b3dd-ab09-4242-9e30-9980e5d322f7"
	# 
    MANAGE_OPTIONAL_FEATURES = "7c0e2a7c-a419-48e4-a995-10180aad54dd"
	# 
    MIGRATE_SID_HISTORY = "ba33815a-4f93-4c76-87f3-57574bff8109"
	# 
    MSMQ_OPEN_CONNECTOR = "b4e60130-df3f-11d1-9c86-006008764d0e"
	# 
    MSMQ_PEEK = "06bd3201-df3e-11d1-9c86-006008764d0e"
	# 
    MSMQ_PEEK_COMPUTER_JOURNAL = "4b6e08c3-df3c-11d1-9c86-006008764d0e"
	# 
    MSMQ_PEEK_DEAD_LETTER = "4b6e08c1-df3c-11d1-9c86-006008764d0e"
	# 
    MSMQ_RECEIVE = "06bd3200-df3e-11d1-9c86-006008764d0e"
	# 
    MSMQ_RECEIVE_COMPUTER_JOURNAL = "4b6e08c2-df3c-11d1-9c86-006008764d0e"
	# 
    MSMQ_RECEIVE_DEAD_LETTER = "4b6e08c0-df3c-11d1-9c86-006008764d0e"
	# 
    MSMQ_RECEIVE_JOURNAL = "06bd3203-df3e-11d1-9c86-006008764d0e"
	# 
    MSMQ_SEND = "06bd3202-df3e-11d1-9c86-006008764d0e"
	# 
    OPEN_ADDRESS_BOOK = "a1990816-4298-11d1-ade2-00c04fd8d5cd"
	# 
    READ_ONLY_REPLICATION_SECRET_SYNCHRONIZATION = "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2"
	# 
    REANIMATE_TOMBSTONES = "45ec5156-db7e-47bb-b53f-dbeb2d03c40f"
	# 
    RECALCULATE_HIERARCHY = "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd"
	# 
    RECALCULATE_SECURITY_INHERITANCE = "62dd28a8-7f46-11d2-b9ad-00c04f79f805"
	# 
    RECEIVE_AS = "ab721a56-1e2f-11d0-9819-00aa0040529b"
	# 
    REFRESH_GROUP_CACHE = "9432c620-033c-4db7-8b58-14ef6d0bf477"
	# 
    RELOAD_SSL_CERTIFICATE = "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8"
	# 
    RUN_PROTECT_ADMIN_GROUPS_TASK = "7726b9d5-a4b4-4288-a6b2-dce952e80a7f"
	# 
    SAM_ENUMERATE_ENTIRE_DOMAIN = "91d67418-0135-4acc-8d79-c08e857cfbec"
	# 
    SEND_AS = "ab721a54-1e2f-11d0-9819-00aa0040529b"
	# 
    SEND_TO = "ab721a55-1e2f-11d0-9819-00aa0040529b"
	# 
    UNEXPIRE_PASSWORD = "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"
	# 
    UPDATE_PASSWORD_NOT_REQUIRED_BIT = "280f369c-67c7-438e-ae98-1d46f3c6f541"
	# 
    UPDATE_SCHEMA_CACHE = "be2bb760-7f46-11d2-b9ad-00c04f79f805"
	# 
    USER_CHANGE_PASSWORD = "ab721a53-1e2f-11d0-9819-00aa0040529b"
	# 
    USER_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"


## SID 


class SID_IDENTIFIER_AUTHORITY(Enum):
    """
    Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c6ce4275-3d90-4890-ab3a-514745e4637e
    """
    NULL_SID_AUTHORITY = 0x00
    WORLD_SID_AUTHORITY = 0x01
    LOCAL_SID_AUTHORITY = 0x02
    CREATOR_SID_AUTHORITY = 0x03
    NON_UNIQUE_AUTHORITY = 0x04
    SECURITY_NT_AUTHORITY = 0x05
    SECURITY_APP_PACKAGE_AUTHORITY = 0x0f
    SECURITY_MANDATORY_LABEL_AUTHORITY = 0x10
    SECURITY_SCOPED_POLICY_ID_AUTHORITY = 0x11
    SECURITY_AUTHENTICATION_AUTHORITY = 0x12

class GUIDFormat(Enum):
    """
    N => 32 digits : 00000000000000000000000000000000
    D => 32 digits separated by hyphens : 00000000-0000-0000-0000-000000000000
    B => 32 digits separated by hyphens, enclosed in braces : {00000000-0000-0000-0000-000000000000}
    P => 32 digits separated by hyphens, enclosed in parentheses : (00000000-0000-0000-0000-000000000000)
    X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of eight hexadecimal values that is also enclosed in braces : {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
    """
    N = 0
    D = 1
    B = 2
    P = 3
    X = 4


class GUIDImportFormatPattern(Enum):
    """
    N => 32 digits : 00000000000000000000000000000000
    D => 32 digits separated by hyphens : 00000000-0000-0000-0000-000000000000
    B => 32 digits separated by hyphens, enclosed in braces : {00000000-0000-0000-0000-000000000000}
    P => 32 digits separated by hyphens, enclosed in parentheses : (00000000-0000-0000-0000-000000000000)
    X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of eight hexadecimal values that is also enclosed in braces : {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
    """
    N = "^([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$"
    D = "^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$"
    B = "^{([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})}$"
    P = "^\\(([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\\)$"
    X = "^{0x([0-9a-f]{8}),0x([0-9a-f]{4}),0x([0-9a-f]{4}),{0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2})}}$"


class AccessControlEntry_Type(Enum):
    ACCESS_ALLOWED_ACE_TYPE = 0x00  # Access-allowed ACE that uses the ACCESS_ALLOWED_ACE (section 2.4.4.2) structure.
    ACCESS_DENIED_ACE_TYPE = 0x01  # Access-denied ACE that uses the ACCESS_DENIED_ACE (section 2.4.4.4) structure.
    SYSTEM_AUDIT_ACE_TYPE = 0x02  # System-audit ACE that uses the SYSTEM_AUDIT_ACE (section 2.4.4.10) structure.
    SYSTEM_ALARM_ACE_TYPE = 0x03  # Reserved for future use.
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04  # Reserved for future use.
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05  # Object-specific access-allowed ACE that uses the ACCESS_ALLOWED_OBJECT_ACE (section 2.4.4.3) structure.
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06  # Object-specific access-denied ACE that uses the ACCESS_DENIED_OBJECT_ACE (section 2.4.4.5) structure.
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07  # Object-specific system-audit ACE that uses the SYSTEM_AUDIT_OBJECT_ACE (section 2.4.4.11) structure.
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08  # Reserved for future use.
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09  # Access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_ACE (section 2.4.4.6) structure.
    ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A  # Access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_ACE (section 2.4.4.7) structure.
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B  # Object-specific access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_OBJECT_ACE (section 2.4.4.8) structure.
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C  # Object-specific access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_OBJECT_ACE (section 2.4.4.9) structure.
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D  # System-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_ACE (section 2.4.4.12) structure.
    SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E  # Reserved for future use.
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F  # Object-specific system-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_OBJECT_ACE (section 2.4.4.14) structure.
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10  # Reserved for future use.
    SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11  # Mandatory label ACE that uses the SYSTEM_MANDATORY_LABEL_ACE (section 2.4.4.13) structure.
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12  # Resource attribute ACE that uses the SYSTEM_RESOURCE_ATTRIBUTE_ACE (section 2.4.4.15).
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13  # A central policy ID ACE that uses the SYSTEM_SCOPED_POLICY_ID_ACE (section 2.4.4.16).

## ACL

class AccessControlList_Revision(Enum):
    ACL_REVISION = 0x02 
    ACL_REVISION_DS = 0x04