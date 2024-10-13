from enum import IntFlag

class AccessControlObjectTypeFlags(IntFlag):
    """
    A set of bit flags that indicate whether the ObjectType and InheritedObjectType members are present. This parameter can be one or more of the following values.
    
    https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace
    """
    NONE = 0x00000000 # Neither ObjectType nor InheritedObjectType are valid.
    ACE_OBJECT_TYPE_PRESENT = 0x00000001 # ObjectType is valid.
    ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002 # InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.

class AccessMaskFlags(IntFlag):
    """
    AccessMaskFlags: Enum class that defines constants for access mask flags.

    This class defines constants for various access mask flags as specified in the Microsoft documentation. These flags represent permissions or rights that can be granted or denied for security principals in access control entries (ACEs) of an access control list (ACL).

    The flags include permissions for creating or deleting child objects, listing contents, reading or writing properties, deleting a tree of objects, and controlling access. Additionally, it includes generic rights like GENERIC_ALL, GENERIC_EXECUTE, GENERIC_WRITE, and GENERIC_READ.

    The values for these flags are derived from the following Microsoft documentation sources:
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584
    - https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum

    Attributes:
        DS_CREATE_CHILD (int): Permission to create child objects.
        DS_DELETE_CHILD (int): Permission to delete child objects.
        DS_LIST_CONTENTS (int): Permission to list contents.
        DS_WRITE_PROPERTY_EXTENDED (int): Permission to write properties (extended).
        DS_READ_PROPERTY (int): Permission to read properties.
        DS_WRITE_PROPERTY (int): Permission to write properties.
        DS_DELETE_TREE (int): Permission to delete a tree of objects.
        DS_LIST_OBJECT (int): Permission to list objects.
        DS_CONTROL_ACCESS (int): Permission for access control.
        DELETE (int): Permission to delete.
        READ_CONTROL (int): Permission to read security descriptor.
        WRITE_DAC (int): Permission to modify discretionary access control list (DACL).
        WRITE_OWNER (int): Permission to change the owner.
        GENERIC_ALL (int): Generic all permissions.
        GENERIC_EXECUTE (int): Generic execute permissions.
        GENERIC_WRITE (int): Generic write permissions.
        GENERIC_READ (int): Generic read permissions.
    """

    DS_CREATE_CHILD = 0x00000001
    DS_DELETE_CHILD = 0x00000002
    DS_LIST_CONTENTS = 0x00000004
    DS_WRITE_PROPERTY_EXTENDED = 0x00000008
    DS_READ_PROPERTY = 0x00000010
    DS_WRITE_PROPERTY = 0x00000020
    DS_DELETE_TREE = 0x00000040
    DS_LIST_OBJECT = 0x00000080
    DS_CONTROL_ACCESS = 0x00000100
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    # Generic rights
    GENERIC_ALL = 0x10000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_WRITE = 0x40000000
    GENERIC_READ = 0x80000000


class AccessControlEntry_Flags(IntFlag):
    OBJECT_INHERIT_ACE = 0x01  # Noncontainer child objects inherit the ACE as an effective ACE.
    CONTAINER_INHERIT_ACE = 0x02  # Child objects that are containers, such as directories, inherit the ACE as an effective ACE. The inherited ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set.
    NO_PROPAGATE_INHERIT_ACE = 0x04  # If the ACE is inherited by a child object, the system clears the OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE flags in the inherited ACE. This prevents the ACE from being inherited by subsequent generations of objects.
    INHERIT_ONLY_ACE = 0x08  # Indicates an inherit-only ACE, which does not control access to the object to which it is attached. If this flag is not set, the ACE is an effective ACE that controls access to the object to which it is attached.
    INHERITED_ACE = 0x10  # Used to indicate that the ACE was inherited. See section 2.5.3.5 for processing rules for setting this flag.
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40  # Used with system-audit ACEs in a system access control list (SACL) to generate audit messages for successful access attempts.
    FAILED_ACCESS_ACE_FLAG = 0x80  # Used with system-audit ACEs in a system access control list (SACL) to generate audit messages for failed access attempts.

