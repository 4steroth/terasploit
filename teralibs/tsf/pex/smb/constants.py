import dataclasses
from typing import ClassVar

from teralibs.tsf.pex.struct2.cstruct_template import CStructTemplate


def make_nbs(template: CStructTemplate) -> CStructTemplate:
    """Create a NetBIOS session packet template."""
    return CStructTemplate(
        ["uint8", "Type", 0],
        ["uint8", "Flags", 0],
        ["uint16n", "PayloadLen", 0],
        ["template", "Payload", template],
    ).create_restraints(["Payload", "PayloadLen", None, True])


@dataclasses.dataclass(init=False)
class Constants:
    """
    This class serves as a centralized repository for all SMB-related constants,
    including command codes, flags, error codes, and other protocol-specific values.

    It also defines the structures for SMB headers using ctypes to ensure correct
    byte layout and endianness when constructing or parsing SMB packets.
    """

    # SMB Commands
    SMB_COM_CREATE_DIRECTORY = 0x00
    SMB_COM_DELETE_DIRECTORY = 0x01
    SMB_COM_OPEN = 0x02
    SMB_COM_CREATE = 0x03
    SMB_COM_CLOSE = 0x04
    SMB_COM_FLUSH = 0x05
    SMB_COM_DELETE = 0x06
    SMB_COM_RENAME = 0x07
    SMB_COM_QUERY_INFORMATION = 0x08
    SMB_COM_SET_INFORMATION = 0x09
    SMB_COM_READ = 0x0A
    SMB_COM_WRITE = 0x0B
    SMB_COM_LOCK_BYTE_RANGE = 0x0C
    SMB_COM_UNLOCK_BYTE_RANGE = 0x0D
    SMB_COM_CREATE_TEMPORARY = 0x0E
    SMB_COM_CREATE_NEW = 0x0F
    SMB_COM_CHECK_DIRECTORY = 0x10
    SMB_COM_PROCESS_EXIT = 0x11
    SMB_COM_SEEK = 0x12
    SMB_COM_LOCK_AND_READ = 0x13
    SMB_COM_WRITE_AND_UNLOCK = 0x14
    SMB_COM_READ_RAW = 0x1A
    SMB_COM_READ_MPX = 0x1B
    SMB_COM_READ_MPX_SECONDARY = 0x1C
    SMB_COM_WRITE_RAW = 0x1D
    SMB_COM_WRITE_MPX = 0x1E
    SMB_COM_WRITE_MPX_SECONDARY = 0x1F
    SMB_COM_WRITE_COMPLETE = 0x20
    SMB_COM_QUERY_SERVER = 0x21
    SMB_COM_SET_INFORMATION2 = 0x22
    SMB_COM_QUERY_INFORMATION2 = 0x23
    SMB_COM_LOCKING_ANDX = 0x24
    SMB_COM_TRANSACTION = 0x25
    SMB_COM_TRANSACTION_SECONDARY = 0x26
    SMB_COM_IOCTL = 0x27
    SMB_COM_IOCTL_SECONDARY = 0x28
    SMB_COM_COPY = 0x29
    SMB_COM_MOVE = 0x2A
    SMB_COM_ECHO = 0x2B
    SMB_COM_WRITE_AND_CLOSE = 0x2C
    SMB_COM_OPEN_ANDX = 0x2D
    SMB_COM_READ_ANDX = 0x2E
    SMB_COM_WRITE_ANDX = 0x2F
    SMB_COM_NEW_FILE_SIZE = 0x30
    SMB_COM_CLOSE_AND_TREE_DISC = 0x31
    SMB_COM_TRANSACTION2 = 0x32
    SMB_COM_TRANSACTION2_SECONDARY = 0x33
    SMB_COM_FIND_CLOSE2 = 0x34
    SMB_COM_FIND_NOTIFY_CLOSE = 0x35
    SMB_COM_TREE_CONNECT = 0x70
    SMB_COM_TREE_DISCONNECT = 0x71
    SMB_COM_NEGOTIATE = 0x72
    SMB_COM_SESSION_SETUP_ANDX = 0x73
    SMB_COM_LOGOFF_ANDX = 0x74
    SMB_COM_TREE_CONNECT_ANDX = 0x75
    SMB_COM_QUERY_INFORMATION_DISK = 0x80
    SMB_COM_SEARCH = 0x81
    SMB_COM_FIND = 0x82
    SMB_COM_FIND_UNIQUE = 0x83
    SMB_COM_FIND_CLOSE = 0x84
    SMB_COM_NT_TRANSACT = 0xA0
    SMB_COM_NT_TRANSACT_SECONDARY = 0xA1
    SMB_COM_NT_CREATE_ANDX = 0xA2
    SMB_COM_NT_CANCEL = 0xA4
    SMB_COM_NT_RENAME = 0xA5
    SMB_COM_OPEN_PRINT_FILE = 0xC0
    SMB_COM_WRITE_PRINT_FILE = 0xC1
    SMB_COM_CLOSE_PRINT_FILE = 0xC2
    SMB_COM_GET_PRINT_QUEUE = 0xC3
    SMB_COM_READ_BULK = 0xD8
    SMB_COM_WRITE_BULK = 0xD9
    SMB_COM_NO_ANDX_COMMAND = 0xFF

    # SMB Version 2 Commands
    SMB2_OP_NEGPROT = 0x00
    SMB2_OP_SESSSETUP = 0x01
    SMB2_OP_LOGOFF = 0x02
    SMB2_OP_TCON = 0x03
    SMB2_OP_TDIS = 0x04
    SMB2_OP_CREATE = 0x05
    SMB2_OP_CLOSE = 0x06
    SMB2_OP_FLUSH = 0x07
    SMB2_OP_READ = 0x08
    SMB2_OP_WRITE = 0x09
    SMB2_OP_LOCK = 0x0A
    SMB2_OP_IOCTL = 0x0B
    SMB2_OP_CANCEL = 0x0C
    SMB2_OP_KEEPALIVE = 0x0D
    SMB2_OP_FIND = 0x0E
    SMB2_OP_NOTIFY = 0x0F
    SMB2_OP_GETINFO = 0x10
    SMB2_OP_SETINFO = 0x11
    SMB2_OP_BREAK = 0x12

    # SMB_COM_NT_TRANSACT Subcommands
    NT_TRANSACT_CREATE = 1
    NT_TRANSACT_IOCTL = 2
    NT_TRANSACT_SET_SECURITY_DESC = 3
    NT_TRANSACT_NOTIFY_CHANGE = 4
    NT_TRANSACT_RENAME = 5
    NT_TRANSACT_QUERY_SECURITY_DESC = 6
    NT_TRANSACT_GET_USER_QUOTA = 7
    NT_TRANSACT_SET_USER_QUOTA = 8

    # NT Flags bits
    FLAGS_REQ_RES = 0x80
    FLAGS_NOTIFY = 0x40
    FLAGS_OP_LOCKS = 0x20
    FLAGS_PATH_NORMALIZED = 0x10
    FLAGS_CASE_SENSITIVE = 0x8
    FLAGS_RESERVED = 0x4
    FLAGS_POSTED = 0x2
    FLAGS_LOCK_SUPPORT = 0x1

    # NT Flags2 bits
    FLAGS2_LONG_PATH_COMPONENTS = 0x0001
    FLAGS2_EXTENDED_ATTRIBUTES = 0x0002
    FLAGS2_SMB_SECURITY_SIGNATURES = 0x0004
    FLAGS2_SMB_SECURITY_SIGNATURES_REQUIRED = 0x0010
    FLAGS2_IS_LONG_NAME = 0x0040
    FLAGS2_EXTENDED_SECURITY = 0x0800
    FLAGS2_DFS_PATHNAMES = 0x1000
    FLAGS2_READ_PERMIT_EXECUTE = 0x2000
    FLAGS2_32_BIT_ERROR_CODES = 0x4000
    FLAGS2_UNICODE_STRINGS = 0x8000
    FLAGS2_WIN2K_SIGNATURE = 0xC852

    # Negotiate & Setup Modes
    NEG_SECURITY_SHARE = 1
    NEG_SECURITY_PASSWORD = 2

    SMB_SETUP_GUEST = 1
    SMB_SETUP_USE_LANMAN_KEY = 2

    # SMB Negotiate Capabilities
    CAP_RAW_MODE = 0x0001
    CAP_MPX_MODE = 0x0002
    CAP_UNICODE = 0x0004
    CAP_LARGE_FILES = 0x0008
    CAP_NT_SMBS = 0x0010
    CAP_RPC_REMOTE_APIS = 0x0020
    CAP_STATUS32 = 0x0040
    CAP_LEVEL_II_OPLOCKS = 0x0080
    CAP_LOCK_AND_READ = 0x0100
    CAP_NT_FIND = 0x0200
    CAP_DFS = 0x1000
    CAP_PASSTHRU = 0x2000
    CAP_LARGE_READX = 0x4000
    CAP_LARGE_WRITEX = 0x8000
    CAP_UNIX_EXTENSIONS = 0x800000

    # Open Modes & Shared Access
    OPEN_MODE_CREAT = 0x10
    OPEN_MODE_EXCL = 0x00
    OPEN_MODE_OPEN = 0x01
    OPEN_MODE_TRUNC = 0x02

    OPEN_SHARE_COMPAT = 0x00
    OPEN_SHARE_DENY_EXCL = 0x10
    OPEN_SHARE_DENY_WRITE = 0x20
    OPEN_SHARE_DENY_READEXEC = 0x30
    OPEN_SHARE_DENY_NONE = 0x40

    # OpLock Levels & Dispositions
    NO_OPLOCK = 0x00
    EXCLUSIVE_OPLOCK = 0x01
    BATCH_OPLOCK = 0x02
    LEVEL_II_OPLOCK = 0x03

    FILE_SUPERSEDE = 0x00000000
    FILE_OPEN = 0x00000001
    FILE_CREATE = 0x00000002
    FILE_OPEN_IF = 0x00000003
    FILE_OVERWRITE = 0x00000004
    FILE_OVERWRITE_IF = 0x00000005

    # Access Rights
    OPEN_ACCESS_READ = 0x00
    OPEN_ACCESS_WRITE = 0x01
    OPEN_ACCESS_READWRITE = 0x02
    OPEN_ACCESS_EXEC = 0x03

    CREATE_ACCESS_SUPERSEDE = 0x00
    CREATE_ACCESS_EXIST = 0x01
    CREATE_ACCESS_CREATE = 0x02
    CREATE_ACCESS_OPENCREATE = 0x03
    CREATE_ACCESS_OVEREXIST = 0x04
    CREATE_ACCESS_OVERCREATE = 0x05

    SMB_READ_ACCESS = 1
    SMB_WRITE_ACCESS = 2
    SMB_APPEND_ACCESS = 4
    SMB_READ_EA_ACCESS = 8
    SMB_WRITE_EA_ACCESS = 0x10
    SMB_EXECUTE_ACCESS = 0x20
    SMB_DELETE_CHILD_ACCESS = 0x40
    SMB_READ_ATTRIBUTES_ACCESS = 0x80
    SMB_WRITE_ATTRIBUTES_ACCESS = 0x100
    SMB_DELETE_ACCESS = 0x10000
    SMB_READ_CONTROL_ACCESS = 0x20000
    SMB_WRITE_DAC_ACCESS = 0x40000
    SMB_WRITE_OWNER_ACCESS = 0x80000
    SMB_SYNC_ACCESS = 0x100000

    NETBIOS_REDIR = "CACACACACACACACACACACACACACACAAA"

    # SMB_COM_TRANSACTION2 SubCommands
    TRANS2_OPEN2 = 0
    TRANS2_FIND_FIRST2 = 1
    TRANS2_FIND_NEXT2 = 2
    TRANS2_QUERY_FS_INFO = 3
    TRANS2_SET_FS_INFO = 4
    TRANS2_QUERY_PATH_INFO = 5
    TRANS2_SET_PATH_INFO = 6
    TRANS2_QUERY_FILE_INFO = 7
    TRANS2_SET_FILE_INFO = 8
    TRANS2_FSCTL = 9
    TRANS2_IOCTL2 = 10
    TRANS2_FIND_NOTIFY_FIRST = 11
    TRANS2_FIND_NOTIFY_NEXT = 12
    TRANS2_CREATE_DIRECTORY = 13
    TRANS2_SESSION_SETUP = 14
    TRANS2_GET_DFS_REFERRAL = 16
    TRANS2_REPORT_DFS_INCONSISTENCY = 17

    # Query Info Levels (FS, Path, Trans2)
    SMB_INFO_ALLOCATION = 1
    SMB_INFO_VOLUME = 2
    SMB_QUERY_FS_VOLUME_INFO = 0x102
    SMB_QUERY_FS_SIZE_INFO = 0x103
    SMB_QUERY_FS_DEVICE_INFO = 0x104
    SMB_QUERY_FS_ATTRIBUTE_INFO = 0x105

    SMB_INFO_STANDARD = 1
    SMB_INFO_QUERY_EA_SIZE = 2
    SMB_INFO_QUERY_EAS_FROM_LIST = 3
    SMB_INFO_QUERY_ALL_EAS = 4
    SMB_INFO_IS_NAME_VALID = 6
    SMB_QUERY_FILE_BASIC_INFO = 0x101
    SMB_QUERY_FILE_STANDARD_INFO = 0x102
    SMB_QUERY_FILE_EA_INFO = 0x103
    SMB_QUERY_FILE_NAME_INFO = 0x104
    SMB_QUERY_FILE_ALL_INFO = 0x107
    SMB_QUERY_FILE_ALT_NAME_INFO = 0x108
    SMB_QUERY_FILE_STREAM_INFO = 0x109
    SMB_QUERY_FILE_COMPRESSION_INFO = 0x10B
    SMB_QUERY_FILE_UNIX_BASIC = 0x200
    SMB_QUERY_FILE_UNIX_LINK = 0x201
    SMB_QUERY_FILE_BASIC_INFO_ALIAS = 0x3EC
    SMB_SET_FILE_BASIC_INFO_ALIAS = 0x3EC
    SMB_QUERY_FILE_STANDARD_INFO_ALIAS = 0x3ED
    SMB_QUERY_FILE_INTERNAL_INFO_ALIAS = 0x3EE
    SMB_QUERY_FILE_EA_INFO_ALIAS = 0x3EF
    SMB_QUERY_FILE_NAME_INFO_ALIAS = 0x3F1
    SMB_QUERY_FILE_NETWORK_OPEN_INFO = 0x40A
    SMB_INFO_PASSTHROUGH = 0x1000

    SMB_QUERY_BASIC_MDC = 0x0028
    SMB_QUERY_STANDARD_MDC1 = 0x0018
    SMB_QUERY_STANDARD_MDC2 = 0x0102
    SMB_QUERY_FILE_INTERNAL_INFO_MDC = 0x0008
    SMB_QUERY_FILE_NETWORK_INFO_MDC = 0x0038

    SMB_FIND_FILE_DIRECTORY_INFO = 0x101
    SMB_FIND_FILE_FULL_DIRECTORY_INFO = 0x102
    SMB_FIND_FILE_NAMES_INFO = 0x103
    SMB_FIND_FILE_BOTH_DIRECTORY_INFO = 0x104
    SMB_FIND_ID_FULL_DIRECTORY_INFO = 0x105
    SMB_FIND_ID_BOTH_DIRECTORY_INFO = 0x106

    # Device Types
    FILE_DEVICE_BEEP = 0x00000001
    FILE_DEVICE_CD_ROM = 0x00000002
    FILE_DEVICE_CD_ROM_FILE_SYSTEM = 0x00000003
    FILE_DEVICE_CONTROLLER = 0x00000004
    FILE_DEVICE_DATALINK = 0x00000005
    FILE_DEVICE_DFS = 0x00000006
    FILE_DEVICE_DISK = 0x00000007
    FILE_DEVICE_DISK_FILE_SYSTEM = 0x00000008
    FILE_DEVICE_FILE_SYSTEM = 0x00000009
    FILE_DEVICE_INPORT_PORT = 0x0000000A
    FILE_DEVICE_KEYBOARD = 0x0000000B
    FILE_DEVICE_MAILSLOT = 0x0000000C
    FILE_DEVICE_MIDI_IN = 0x0000000D
    FILE_DEVICE_MIDI_OUT = 0x0000000E
    FILE_DEVICE_MOUSE = 0x0000000F
    FILE_DEVICE_MULTI_UNC_PROVIDER = 0x00000010
    FILE_DEVICE_NAMED_PIPE = 0x00000011
    FILE_DEVICE_NETWORK = 0x00000012
    FILE_DEVICE_NETWORK_BROWSER = 0x00000013
    FILE_DEVICE_NETWORK_FILE_SYSTEM = 0x00000014
    FILE_DEVICE_NULL = 0x00000015
    FILE_DEVICE_PARALLEL_PORT = 0x00000016
    FILE_DEVICE_PHYSICAL_NETCARD = 0x00000017
    FILE_DEVICE_PRINTER = 0x00000018
    FILE_DEVICE_SCANNER = 0x00000019
    FILE_DEVICE_SERIAL_MOUSE_PORT = 0x0000001A
    FILE_DEVICE_SERIAL_PORT = 0x0000001B
    FILE_DEVICE_SCREEN = 0x0000001C
    FILE_DEVICE_SOUND = 0x0000001D
    FILE_DEVICE_STREAMS = 0x0000001E
    FILE_DEVICE_TAPE = 0x0000001F
    FILE_DEVICE_TAPE_FILE_SYSTEM = 0x00000020
    FILE_DEVICE_TRANSPORT = 0x00000021
    FILE_DEVICE_UNKNOWN = 0x00000022
    FILE_DEVICE_VIDEO = 0x00000023
    FILE_DEVICE_VIRTUAL_DISK = 0x00000024
    FILE_DEVICE_WAVE_IN = 0x00000025
    FILE_DEVICE_WAVE_OUT = 0x00000026
    FILE_DEVICE_8042_PORT = 0x00000027
    FILE_DEVICE_NETWORK_REDIRECTOR = 0x00000028
    FILE_DEVICE_BATTERY = 0x00000029
    FILE_DEVICE_BUS_EXTENDER = 0x0000002A
    FILE_DEVICE_MODEM = 0x0000002B
    FILE_DEVICE_VDM = 0x0000002C

    # File and Device Attributes
    FILE_REMOVABLE_MEDIA = 0x00000001
    FILE_READ_ONLY_DEVICE = 0x00000002
    FILE_FLOPPY_DISKETTE = 0x00000004
    FILE_WRITE_ONE_MEDIA = 0x00000008
    FILE_REMOTE_DEVICE = 0x00000010
    FILE_DEVICE_IS_MOUNTED = 0x00000020
    FILE_VIRTUAL_VOLUME = 0x00000040
    FILE_CASE_SENSITIVE_SEARCH = 0x00000001
    FILE_CASE_PRESERVED_NAMES = 0x00000002
    FILE_PERSISTENT_ACLS = 0x00000004
    FILE_FILE_COMPRESSION = 0x00000008
    FILE_VOLUME_QUOTAS = 0x00000010
    FILE_VOLUME_IS_COMPRESSED = 0x00008000

    SMB_EXT_FILE_ATTR_READONLY = 0x00000001
    SMB_EXT_FILE_ATTR_HIDDEN = 0x00000002
    SMB_EXT_FILE_ATTR_SYSTEM = 0x00000004
    SMB_EXT_FILE_ATTR_DIRECTORY = 0x00000010
    SMB_EXT_FILE_ATTR_ARCHIVE = 0x00000020
    SMB_EXT_FILE_ATTR_NORMAL = 0x00000080
    SMB_EXT_FILE_ATTR_TEMPORARY = 0x00000100
    SMB_EXT_FILE_ATTR_COMPRESSED = 0x00000800
    SMB_EXT_FILE_POSIX_SEMANTICS = 0x01000000
    SMB_EXT_FILE_BACKUP_SEMANTICS = 0x02000000
    SMB_EXT_FILE_DELETE_ON_CLOSE = 0x04000000
    SMB_EXT_FILE_SEQUENTIAL_SCAN = 0x08000000
    SMB_EXT_FILE_RANDOM_ACCESS = 0x10000000
    SMB_EXT_FILE_NO_BUFFERING = 0x20000000
    SMB_EXT_FILE_WRITE_THROUGH = 0x80000000

    # SMB Error Codes & Resource Types
    SMB_STATUS_SUCCESS = 0x00000000
    SMB_ERROR_BUFFER_OVERFLOW = 0x80000005
    SMB_STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
    SMB_STATUS_ACCESS_DENIED = 0xC0000022
    SMB_STATUS_LOGON_FAILURE = 0xC000006D
    SMB_STATUS_NO_SUCH_FILE = 0xC000000F
    SMB_STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
    SMB_NT_STATUS_NOT_FOUND = 0xC0000225

    SMB_RESOURCE_FILE_TYPE_DISK = 0x0000
    SMB_RESOURCE_FILE_TYPE_BYTE_MODE_PIPE = 0x0001
    SMB_RESOURCE_FILE_TYPE_MESSAGE_MODE_PIPE = 0x0002
    SMB_RESOURCE_FILE_TYPE_PRINTER = 0x0003
    SMB_RESOURCE_FILE_TYPE_COMM_DEVICE = 0x0004
    SMB_RESOURCE_FILE_TYPE_PIPE = 0x0005
    SMB_RESOURCE_FILE_TYPE_UNKNOWN = 0xFFFF

    # Response Word Counts
    SMB_NEGOTIATE_RES_WORD_COUNT = 0x11
    SMB_CLOSE_RES_WORD_COUNT = 0x00
    SMB_NT_CREATE_ANDX_RES_WORD_COUNT = 0x22
    SMB_READ_ANDX_RES_WORD_COUNT = 0x0C
    SMB_TREE_CONN_ANDX_WORD_COUNT = 0x07
    SMB_SESSION_SETUP_ANDX_RES_WORD_COUNT = 0x03
    SMB_TRANS2_RES_WORD_COUNT = 0x0A

    # SMB Dialect Compatibility Arrays
    DIALECT: ClassVar = {
        "PC NETWORK PROGRAM 1.0": [
            SMB_COM_CHECK_DIRECTORY,
            SMB_COM_CLOSE,
            SMB_COM_CLOSE_PRINT_FILE,
            SMB_COM_CREATE,
            SMB_COM_CREATE_DIRECTORY,
            SMB_COM_CREATE_NEW,
            SMB_COM_CREATE_TEMPORARY,
            SMB_COM_DELETE,
            SMB_COM_DELETE_DIRECTORY,
            SMB_COM_FLUSH,
            SMB_COM_GET_PRINT_QUEUE,
            SMB_COM_LOCK_BYTE_RANGE,
            SMB_COM_NEGOTIATE,
            SMB_COM_OPEN,
            SMB_COM_OPEN_PRINT_FILE,
            SMB_COM_PROCESS_EXIT,
            SMB_COM_QUERY_INFORMATION,
            SMB_COM_QUERY_INFORMATION_DISK,
            SMB_COM_READ,
            SMB_COM_RENAME,
            SMB_COM_SEARCH,
            SMB_COM_SEEK,
            SMB_COM_SET_INFORMATION,
            SMB_COM_TREE_CONNECT,
            SMB_COM_TREE_DISCONNECT,
            SMB_COM_UNLOCK_BYTE_RANGE,
            SMB_COM_WRITE,
            SMB_COM_WRITE_PRINT_FILE,
        ],
        "LANMAN 1.0": [
            SMB_COM_CHECK_DIRECTORY,
            SMB_COM_CLOSE,
            SMB_COM_CLOSE_PRINT_FILE,
            SMB_COM_CREATE,
            SMB_COM_CREATE_DIRECTORY,
            SMB_COM_CREATE_NEW,
            SMB_COM_CREATE_TEMPORARY,
            SMB_COM_DELETE,
            SMB_COM_DELETE_DIRECTORY,
            SMB_COM_FLUSH,
            SMB_COM_GET_PRINT_QUEUE,
            SMB_COM_LOCK_BYTE_RANGE,
            SMB_COM_NEGOTIATE,
            SMB_COM_OPEN,
            SMB_COM_OPEN_PRINT_FILE,
            SMB_COM_PROCESS_EXIT,
            SMB_COM_QUERY_INFORMATION,
            SMB_COM_QUERY_INFORMATION_DISK,
            SMB_COM_READ,
            SMB_COM_RENAME,
            SMB_COM_SEARCH,
            SMB_COM_SEEK,
            SMB_COM_SET_INFORMATION,
            SMB_COM_TREE_CONNECT,
            SMB_COM_TREE_DISCONNECT,
            SMB_COM_UNLOCK_BYTE_RANGE,
            SMB_COM_WRITE,
            SMB_COM_WRITE_PRINT_FILE,
            SMB_COM_COPY,
            SMB_COM_ECHO,
            SMB_COM_FIND,
            SMB_COM_FIND_CLOSE,
            SMB_COM_FIND_UNIQUE,
            SMB_COM_IOCTL,
            SMB_COM_IOCTL_SECONDARY,
            SMB_COM_LOCK_AND_READ,
            SMB_COM_LOCKING_ANDX,
            SMB_COM_MOVE,
            SMB_COM_OPEN_ANDX,
            SMB_COM_QUERY_INFORMATION2,
            SMB_COM_READ_ANDX,
            SMB_COM_READ_MPX,
            SMB_COM_READ_RAW,
            SMB_COM_SESSION_SETUP_ANDX,
            SMB_COM_SET_INFORMATION2,
            SMB_COM_TRANSACTION,
            SMB_COM_TRANSACTION_SECONDARY,
            SMB_COM_TREE_CONNECT_ANDX,
            SMB_COM_WRITE_AND_CLOSE,
            SMB_COM_WRITE_AND_UNLOCK,
            SMB_COM_WRITE_ANDX,
            SMB_COM_WRITE_COMPLETE,
            SMB_COM_WRITE_MPX,
            SMB_COM_WRITE_MPX_SECONDARY,
            SMB_COM_WRITE_RAW,
        ],
        "LM1.2X002": [
            SMB_COM_CHECK_DIRECTORY,
            SMB_COM_CLOSE,
            SMB_COM_CLOSE_PRINT_FILE,
            SMB_COM_CREATE,
            SMB_COM_CREATE_DIRECTORY,
            SMB_COM_CREATE_NEW,
            SMB_COM_CREATE_TEMPORARY,
            SMB_COM_DELETE,
            SMB_COM_DELETE_DIRECTORY,
            SMB_COM_FLUSH,
            SMB_COM_GET_PRINT_QUEUE,
            SMB_COM_LOCK_BYTE_RANGE,
            SMB_COM_NEGOTIATE,
            SMB_COM_OPEN,
            SMB_COM_OPEN_PRINT_FILE,
            SMB_COM_PROCESS_EXIT,
            SMB_COM_QUERY_INFORMATION,
            SMB_COM_QUERY_INFORMATION_DISK,
            SMB_COM_READ,
            SMB_COM_RENAME,
            SMB_COM_SEARCH,
            SMB_COM_SEEK,
            SMB_COM_SET_INFORMATION,
            SMB_COM_TREE_CONNECT,
            SMB_COM_TREE_DISCONNECT,
            SMB_COM_UNLOCK_BYTE_RANGE,
            SMB_COM_WRITE,
            SMB_COM_WRITE_PRINT_FILE,
            SMB_COM_COPY,
            SMB_COM_ECHO,
            SMB_COM_FIND,
            SMB_COM_FIND_CLOSE,
            SMB_COM_FIND_UNIQUE,
            SMB_COM_IOCTL,
            SMB_COM_IOCTL_SECONDARY,
            SMB_COM_LOCK_AND_READ,
            SMB_COM_LOCKING_ANDX,
            SMB_COM_MOVE,
            SMB_COM_OPEN_ANDX,
            SMB_COM_QUERY_INFORMATION2,
            SMB_COM_READ_ANDX,
            SMB_COM_READ_MPX,
            SMB_COM_READ_RAW,
            SMB_COM_SESSION_SETUP_ANDX,
            SMB_COM_SET_INFORMATION2,
            SMB_COM_TRANSACTION,
            SMB_COM_TRANSACTION_SECONDARY,
            SMB_COM_TREE_CONNECT_ANDX,
            SMB_COM_WRITE_AND_CLOSE,
            SMB_COM_WRITE_AND_UNLOCK,
            SMB_COM_WRITE_ANDX,
            SMB_COM_WRITE_COMPLETE,
            SMB_COM_WRITE_MPX,
            SMB_COM_WRITE_MPX_SECONDARY,
            SMB_COM_WRITE_RAW,
            SMB_COM_FIND_CLOSE2,
            SMB_COM_LOGOFF_ANDX,
            SMB_COM_TRANSACTION2,
            SMB_COM_TRANSACTION2_SECONDARY,
        ],
        "NTLM 0.12": [
            SMB_COM_CHECK_DIRECTORY,
            SMB_COM_CLOSE,
            SMB_COM_CLOSE_PRINT_FILE,
            SMB_COM_CREATE,
            SMB_COM_CREATE_DIRECTORY,
            SMB_COM_CREATE_NEW,
            SMB_COM_CREATE_TEMPORARY,
            SMB_COM_DELETE,
            SMB_COM_DELETE_DIRECTORY,
            SMB_COM_FLUSH,
            SMB_COM_GET_PRINT_QUEUE,
            SMB_COM_LOCK_BYTE_RANGE,
            SMB_COM_NEGOTIATE,
            SMB_COM_OPEN,
            SMB_COM_OPEN_PRINT_FILE,
            SMB_COM_PROCESS_EXIT,
            SMB_COM_QUERY_INFORMATION,
            SMB_COM_QUERY_INFORMATION_DISK,
            SMB_COM_READ,
            SMB_COM_RENAME,
            SMB_COM_SEARCH,
            SMB_COM_SEEK,
            SMB_COM_SET_INFORMATION,
            SMB_COM_TREE_CONNECT,
            SMB_COM_TREE_DISCONNECT,
            SMB_COM_UNLOCK_BYTE_RANGE,
            SMB_COM_WRITE,
            SMB_COM_WRITE_PRINT_FILE,
            SMB_COM_COPY,
            SMB_COM_ECHO,
            SMB_COM_FIND,
            SMB_COM_FIND_CLOSE,
            SMB_COM_FIND_UNIQUE,
            SMB_COM_IOCTL,
            SMB_COM_IOCTL_SECONDARY,
            SMB_COM_LOCK_AND_READ,
            SMB_COM_LOCKING_ANDX,
            SMB_COM_MOVE,
            SMB_COM_OPEN_ANDX,
            SMB_COM_QUERY_INFORMATION2,
            SMB_COM_READ_ANDX,
            SMB_COM_READ_MPX,
            SMB_COM_READ_RAW,
            SMB_COM_SESSION_SETUP_ANDX,
            SMB_COM_SET_INFORMATION2,
            SMB_COM_TRANSACTION,
            SMB_COM_TRANSACTION_SECONDARY,
            SMB_COM_TREE_CONNECT_ANDX,
            SMB_COM_WRITE_AND_CLOSE,
            SMB_COM_WRITE_AND_UNLOCK,
            SMB_COM_WRITE_ANDX,
            SMB_COM_WRITE_COMPLETE,
            SMB_COM_WRITE_MPX,
            SMB_COM_WRITE_MPX_SECONDARY,
            SMB_COM_WRITE_RAW,
            SMB_COM_FIND_CLOSE2,
            SMB_COM_LOGOFF_ANDX,
            SMB_COM_TRANSACTION2,
            SMB_COM_TRANSACTION2_SECONDARY,
            SMB_COM_NT_CANCEL,
            SMB_COM_NT_CREATE_ANDX,
            SMB_COM_NT_RENAME,
            SMB_COM_NT_TRANSACT,
            SMB_COM_NT_TRANSACT_SECONDARY,
        ],
    }

    # A raw NetBIOS session template (Matches your Ruby layout exactly)
    NBRAW_HDR_PKT = CStructTemplate(["string", "Payload", None, ""])

    # Wrapped via the factory method to prepend the 4-byte NetBIOS framing header
    NBRAW_PKT = make_nbs(NBRAW_HDR_PKT)

    # A raw SMB header template (Matches your Ruby layout exactly)
    SMB_HDR = CStructTemplate(
        ["uint32n", "Magic", 0xFF534D42],
        ["uint8", "Command", 0],
        ["uint32v", "ErrorClass", 0],
        ["uint8", "Flags1", 0],
        ["uint16v", "Flags2", 0],
        ["uint16v", "ProcessIDHigh", 0],
        ["uint32v", "Signature1", 0],
        ["uint32v", "Signature2", 0],
        ["uint16v", "Reserved1", 0],
        ["uint16v", "TreeID", 0],
        ["uint16v", "ProcessID", 0],
        ["uint16v", "UserID", 0],
        ["uint16v", "MultiplexID", 0],
        ["uint8", "WordCount", 0],
    )

    SMB_HDR_LENGTH = 33

    # The SMB2 header template
    SMB2_HDR = CStructTemplate(
        ["uint32n", "Magic", 0xFE534D42],
        ["uint16v", "HeaderLen", 64],
        ["uint16v", "Reserved0", 0],
        ["uint32v", "NTStatus", 0],
        ["uint16v", "Opcode", 0],
        ["uint16v", "Reserved1", 0],
        ["uint16v", "Flags1", 0],
        ["uint16v", "Flags2", 0],
        ["uint32v", "ChainOffset", 0],
        ["uint32v", "SequenceHigh", 0],
        ["uint32v", "SequenceLow", 0],
        ["uint32v", "ProcessID", 0],
        ["uint32v", "TreeID", 0],
        ["uint32v", "UserIDHigh", 0],
        ["uint32v", "UserIDLow", 0],
        ["uint32v", "SignatureA", 0],
        ["uint32v", "SignatureB", 0],
        ["uint32v", "SignatureC", 0],
        ["uint32v", "SignatureD", 0],
        ["string", "Payload", None, ""],
    )

    # A basic SMB template to read all responses
    SMB_BASE_HDR_PKT = CStructTemplate(["template", "SMB", SMB_HDR], ["uint16v", "ByteCount", 0], ["string", "Payload", None, ""]).create_restraints(
        ["Payload", "ByteCount", None, True]
    )
    SMB_BASE_PKT = make_nbs(SMB_BASE_HDR_PKT)

    # A SMB template for SMB Dialect negotiation
    SMB_NEG_HDR_PKT = CStructTemplate(["template", "SMB", SMB_HDR], ["uint16v", "ByteCount", 0], ["string", "Payload", None, ""]).create_restraints(
        ["Payload", "ByteCount", None, True]
    )
    SMB_NEG_PKT = make_nbs(SMB_NEG_HDR_PKT)

    # A SMB template for SMB Dialect negotiation responses (LANMAN)
    SMB_NEG_RES_LM_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint16v", "Dialect", 0],
        ["uint16v", "SecurityMode", 0],
        ["uint16v", "MaxBuff", 0],
        ["uint16v", "MaxMPX", 0],
        ["uint16v", "MaxVCS", 0],
        ["uint16v", "RawMode", 0],
        ["uint32v", "SessionKey", 0],
        ["uint16v", "DosTime", 0],
        ["uint16v", "DosDate", 0],
        ["uint16v", "Timezone", 0],
        ["uint16v", "KeyLength", 0],
        ["uint16v", "Reserved1", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "EncryptionKey", None, ""],
    ).create_restraints(["EncryptionKey", "ByteCount", None, True])
    SMB_NEG_RES_LM_PKT = make_nbs(SMB_NEG_RES_LM_HDR_PKT)

    # A SMB template for SMB Dialect negotiation responses (NTLM)
    SMB_NEG_RES_NT_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint16v", "Dialect", 0],
        ["uint8", "SecurityMode", 0],
        ["uint16v", "MaxMPX", 0],
        ["uint16v", "MaxVCS", 0],
        ["uint32v", "MaxBuff", 0],
        ["uint32v", "MaxRaw", 0],
        ["uint32v", "SessionKey", 0],
        ["uint32v", "Capabilities", 0],
        ["uint32v", "SystemTimeLow", 0],
        ["uint32v", "SystemTimeHigh", 0],
        ["uint16v", "ServerTimeZone", 0],
        ["uint8", "KeyLength", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_NEG_RES_NT_PKT = make_nbs(SMB_NEG_RES_NT_HDR_PKT)

    # A SMB template for SMB Dialect negotiation responses (ERROR)
    SMB_NEG_RES_ERR_HDR_PKT = CStructTemplate(["template", "SMB", SMB_HDR], ["uint16v", "Dialect", 0], ["uint16v", "ByteCount", 0])
    SMB_NEG_RES_ERR_PKT = make_nbs(SMB_NEG_RES_ERR_HDR_PKT)

    # A SMB template for SMB Session Setup responses (LANMAN/NTLMV1)
    SMB_SETUP_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "Action", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_SETUP_RES_PKT = make_nbs(SMB_SETUP_RES_HDR_PKT)

    # A SMB template for SMB Session Setup requests (LANMAN)
    SMB_SETUP_LANMAN_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "MaxBuff", 0],
        ["uint16v", "MaxMPX", 0],
        ["uint16v", "VCNum", 0],
        ["uint32v", "SessionKey", 0],
        ["uint16v", "PasswordLen", 0],
        ["uint32v", "Reserved2", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_SETUP_LANMAN_PKT = make_nbs(SMB_SETUP_LANMAN_HDR_PKT)

    # A SMB template for SMB Session Setup requests (NTLMV1)
    SMB_SETUP_NTLMV1_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "MaxBuff", 0],
        ["uint16v", "MaxMPX", 0],
        ["uint16v", "VCNum", 0],
        ["uint32v", "SessionKey", 0],
        ["uint16v", "PasswordLenLM", 0],
        ["uint16v", "PasswordLenNT", 0],
        ["uint32v", "Reserved2", 0],
        ["uint32v", "Capabilities", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_SETUP_NTLMV1_PKT = make_nbs(SMB_SETUP_NTLMV1_HDR_PKT)

    # A SMB template for SMB Session Setup requests (When extended security is being used)
    SMB_SETUP_NTLMV2_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "MaxBuff", 0],
        ["uint16v", "MaxMPX", 0],
        ["uint16v", "VCNum", 0],
        ["uint32v", "SessionKey", 0],
        ["uint16v", "SecurityBlobLen", 0],
        ["uint32v", "Reserved2", 0],
        ["uint32v", "Capabilities", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_SETUP_NTLMV2_PKT = make_nbs(SMB_SETUP_NTLMV2_HDR_PKT)

    # A SMB template for SMB Session Setup responses (When extended security is being used)
    SMB_SETUP_NTLMV2_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "Action", 0],
        ["uint16v", "SecurityBlobLen", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_SETUP_NTLMV2_RES_PKT = make_nbs(SMB_SETUP_NTLMV2_RES_HDR_PKT)

    # A SMB template for SMB Tree Connect requests
    SMB_TREE_CONN_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "Flags", 0],
        ["uint16v", "PasswordLen", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_TREE_CONN_PKT = make_nbs(SMB_TREE_CONN_HDR_PKT)

    # A SMB template for SMB Tree Connect requests
    SMB_TREE_CONN_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "OptionalSupport", 0],
        ["string", "SupportWords", None, ""],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_TREE_CONN_RES_PKT = make_nbs(SMB_TREE_CONN_RES_HDR_PKT)

    # A SMB template for SMB Tree Disconnect requests
    SMB_TREE_DISCONN_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR], ["uint16v", "ByteCount", 0], ["string", "Payload", None, ""]
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_TREE_DISCONN_PKT = make_nbs(SMB_TREE_DISCONN_HDR_PKT)

    # A SMB template for SMB Tree Disconnect requests
    SMB_TREE_DISCONN_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR], ["uint16v", "ByteCount", 0], ["string", "Payload", None, ""]
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_TREE_DISCONN_RES_PKT = make_nbs(SMB_TREE_DISCONN_RES_HDR_PKT)

    # A SMB template for SMB Transaction requests
    SMB_TRANS_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint16v", "ParamCountTotal", 0],
        ["uint16v", "DataCountTotal", 0],
        ["uint16v", "ParamCountMax", 0],
        ["uint16v", "DataCountMax", 0],
        ["uint8", "SetupCountMax", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "Flags", 0],
        ["uint32v", "Timeout", 0],
        ["uint16v", "Reserved2", 0],
        ["uint16v", "ParamCount", 0],
        ["uint16v", "ParamOffset", 0],
        ["uint16v", "DataCount", 0],
        ["uint16v", "DataOffset", 0],
        ["uint8", "SetupCount", 0],
        ["uint8", "Reserved3", 0],
        ["string", "SetupData", None, ""],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_TRANS_PKT = make_nbs(SMB_TRANS_HDR_PKT)

    # A SMB template for SMB Transaction responses
    SMB_TRANS_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint16v", "ParamCountTotal", 0],
        ["uint16v", "DataCountTotal", 0],
        ["uint16v", "Reserved1", 0],
        ["uint16v", "ParamCount", 0],
        ["uint16v", "ParamOffset", 0],
        ["uint16v", "ParamDisplace", 0],
        ["uint16v", "DataCount", 0],
        ["uint16v", "DataOffset", 0],
        ["uint16v", "DataDisplace", 0],
        ["uint8", "SetupCount", 0],
        ["uint8", "Reserved2", 0],
        ["string", "SetupData", None, ""],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_TRANS_RES_PKT = make_nbs(SMB_TRANS_RES_HDR_PKT)

    SMB_TRANS_RES_PKT_LENGTH = SMB_HDR_LENGTH + 22

    # A SMB template for SMB Transaction2 requests
    SMB_TRANS2_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint16v", "ParamCountTotal", 0],
        ["uint16v", "DataCountTotal", 0],
        ["uint16v", "ParamCountMax", 0],
        ["uint16v", "DataCountMax", 0],
        ["uint8", "SetupCountMax", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "Flags", 0],
        ["uint32v", "Timeout", 0],
        ["uint16v", "Reserved2", 0],
        ["uint16v", "ParamCount", 0],
        ["uint16v", "ParamOffset", 0],
        ["uint16v", "DataCount", 0],
        ["uint16v", "DataOffset", 0],
        ["uint8", "SetupCount", 0],
        ["uint8", "Reserved3", 0],
        ["string", "SetupData", None, ""],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_TRANS2_PKT = make_nbs(SMB_TRANS2_HDR_PKT)

    # A SMB template for SMB NTTransaction requests
    SMB_NTTRANS_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "SetupCountMax", 0],
        ["uint16v", "Reserved1", 0],
        ["uint32v", "ParamCountTotal", 0],
        ["uint32v", "DataCountTotal", 0],
        ["uint32v", "ParamCountMax", 0],
        ["uint32v", "DataCountMax", 0],
        ["uint32v", "ParamCount", 0],
        ["uint32v", "ParamOffset", 0],
        ["uint32v", "DataCount", 0],
        ["uint32v", "DataOffset", 0],
        ["uint8", "SetupCount", 0],
        ["uint16v", "Subcommand", 0],
        ["string", "SetupData", None, ""],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_NTTRANS_PKT = make_nbs(SMB_NTTRANS_HDR_PKT)

    # A SMB template for SMB NTTransaction responses
    SMB_NTTRANS_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "Reserved1", 0],
        ["uint16v", "Reserved2", 0],
        ["uint32v", "ParamCountTotal", 0],
        ["uint32v", "DataCountTotal", 0],
        ["uint32v", "ParamCount", 0],
        ["uint32v", "ParamOffset", 0],
        ["uint32v", "ParamDisplace", 0],
        ["uint32v", "DataCount", 0],
        ["uint32v", "DataOffset", 0],
        ["uint32v", "DataDisplace", 0],
        ["uint8", "Reserved3", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_NTTRANS_RES_PKT = make_nbs(SMB_NTTRANS_RES_HDR_PKT)

    # A SMB template for SMB NTTransaction_Secondary requests
    SMB_NTTRANS_SECONDARY_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "Reserved1", 0],
        ["uint16v", "Reserved2", 0],
        ["uint32v", "ParamCountTotal", 0],
        ["uint32v", "DataCountTotal", 0],
        ["uint32v", "ParamCount", 0],
        ["uint32v", "ParamOffset", 0],
        ["uint32v", "ParamDisplace", 0],
        ["uint32v", "DataCount", 0],
        ["uint32v", "DataOffset", 0],
        ["uint32v", "DataDisplace", 0],
        ["uint8", "SetupCount", 0],
        ["string", "SetupData", None, ""],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_NTTRANS_SECONDARY_PKT = make_nbs(SMB_NTTRANS_SECONDARY_HDR_PKT)

    # A SMB template for SMB Create requests
    SMB_CREATE_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint8", "Reserved2", 0],
        ["uint16v", "FileNameLen", 0],
        ["uint32v", "CreateFlags", 0],
        ["uint32v", "RootFileID", 0],
        ["uint32v", "AccessMask", 0],
        ["uint32v", "AllocLow", 0],
        ["uint32v", "AllocHigh", 0],
        ["uint32v", "Attributes", 0],
        ["uint32v", "ShareAccess", 0],
        ["uint32v", "Disposition", 0],
        ["uint32v", "CreateOptions", 0],
        ["uint32v", "Impersonation", 0],
        ["uint8", "SecurityFlags", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_CREATE_PKT = make_nbs(SMB_CREATE_HDR_PKT)

    # A SMB template for SMB Create responses
    SMB_CREATE_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint8", "OpLock", 0],
        ["uint16v", "FileID", 0],
        ["uint32v", "Action", 0],
        ["uint32v", "CreateTimeLow", 0],
        ["uint32v", "CreateTimeHigh", 0],
        ["uint32v", "AccessTimeLow", 0],
        ["uint32v", "AccessTimeHigh", 0],
        ["uint32v", "WriteTimeLow", 0],
        ["uint32v", "WriteTimeHigh", 0],
        ["uint32v", "ChangeTimeLow", 0],
        ["uint32v", "ChangeTimeHigh", 0],
        ["uint32v", "Attributes", 0],
        ["uint32v", "AllocLow", 0],
        ["uint32v", "AllocHigh", 0],
        ["uint32v", "EOFLow", 0],
        ["uint32v", "EOFHigh", 0],
        ["uint16v", "FileType", 0],
        ["uint16v", "IPCState", 0],
        ["uint8", "IsDirectory", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_CREATE_RES_PKT = make_nbs(SMB_CREATE_RES_HDR_PKT)

    # A SMB template for SMB Create ANDX responses
    SMB_CREATE_ANDX_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint8", "OpLock", 0],
        ["uint16v", "FileID", 0],
        ["uint32v", "Action", 0],
        ["uint32v", "CreateTimeLow", 0],
        ["uint32v", "CreateTimeHigh", 0],
        ["uint32v", "AccessTimeLow", 0],
        ["uint32v", "AccessTimeHigh", 0],
        ["uint32v", "WriteTimeLow", 0],
        ["uint32v", "WriteTimeHigh", 0],
        ["uint32v", "ChangeTimeLow", 0],
        ["uint32v", "ChangeTimeHigh", 0],
        ["uint32v", "Attributes", 0],
        ["uint32v", "AllocLow", 0],
        ["uint32v", "AllocHigh", 0],
        ["uint32v", "EOFLow", 0],
        ["uint32v", "EOFHigh", 0],
        ["uint16v", "FileType", 0],
        ["uint16v", "IPCState", 0],
        ["uint8", "IsDirectory", 0],
        ["string", "VolumeGUID", 16, "", "\x00"],
        ["uint64v", "64bitFID", 0],
        ["uint32v", "MaxAccess", 0],
        ["uint32v", "GuestAccess", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_CREATE_ANDX_RES_PKT = make_nbs(SMB_CREATE_ANDX_RES_HDR_PKT)

    # A SMB template for SMB Write requests
    SMB_WRITE_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "FileID", 0],
        ["uint32v", "Offset", 0],
        ["uint32v", "Reserved2", 0],
        ["uint16v", "WriteMode", 0],
        ["uint16v", "Remaining", 0],
        ["uint16v", "DataLenHigh", 0],
        ["uint16v", "DataLenLow", 0],
        ["uint16v", "DataOffset", 0],
        ["uint32v", "DataOffsetHigh", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_WRITE_PKT = make_nbs(SMB_WRITE_HDR_PKT)

    # A SMB template for SMB Write responses
    SMB_WRITE_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "CountLow", 0],
        ["uint16v", "Remaining", 0],
        ["uint16v", "CountHigh", 0],
        ["uint16v", "Reserved2", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_WRITE_RES_PKT = make_nbs(SMB_WRITE_RES_HDR_PKT)

    # A SMB template for SMB OPEN requests
    SMB_OPEN_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "Flags", 0],
        ["uint16v", "Access", 0],
        ["uint16v", "SearchAttributes", 0],
        ["uint16v", "FileAttributes", 0],
        ["uint32v", "CreateTime", 0],
        ["uint16v", "OpenFunction", 0],
        ["uint32v", "AllocSize", 0],
        ["uint32v", "Reserved2", 0],
        ["uint32v", "Reserved3", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_OPEN_PKT = make_nbs(SMB_OPEN_HDR_PKT)

    # A SMB template for SMB OPEN responses
    SMB_OPEN_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "FileID", 0],
        ["uint16v", "FileAttributes", 0],
        ["uint32v", "WriteTime", 0],
        ["uint32v", "FileSize", 0],
        ["uint16v", "FileAccess", 0],
        ["uint16v", "FileType", 0],
        ["uint16v", "IPCState", 0],
        ["uint16v", "Action", 0],
        ["uint32v", "ServerFileID", 0],
        ["uint16v", "Reserved2", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_OPEN_RES_PKT = make_nbs(SMB_OPEN_RES_HDR_PKT)

    # A SMB template for SMB Close requests
    SMB_CLOSE_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint16v", "FileID", 0],
        ["uint32v", "LastWrite", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_CLOSE_PKT = make_nbs(SMB_CLOSE_HDR_PKT)

    # A SMB template for SMB Close responses
    SMB_CLOSE_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR], ["uint16v", "ByteCount", 0], ["string", "Payload", None, ""]
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_CLOSE_RES_PKT = make_nbs(SMB_CLOSE_RES_HDR_PKT)

    # A SMB template for SMB Delete requests
    SMB_DELETE_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint16v", "SearchAttribute", 0],
        ["uint16v", "ByteCount", 0],
        ["uint8", "BufferFormat", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_DELETE_PKT = make_nbs(SMB_DELETE_HDR_PKT)

    # A SMB template for SMB Delete responses
    SMB_DELETE_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR], ["uint16v", "ByteCount", 0], ["string", "Payload", None, ""]
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_DELETE_RES_PKT = make_nbs(SMB_DELETE_RES_HDR_PKT)

    # A SMB template for SMB Read requests
    SMB_READ_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "FileID", 0],
        ["uint32v", "Offset", 0],
        ["uint16v", "MaxCountLow", 0],
        ["uint16v", "MinCount", 0],
        ["uint32v", "Reserved2", 0],
        ["uint16v", "Remaining", 0],
        ["uint32v", "MaxCountHigh", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_READ_PKT = make_nbs(SMB_READ_HDR_PKT)

    # A SMB template for SMB Read responses
    SMB_READ_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint8", "AndX", 0],
        ["uint8", "Reserved1", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "Remaining", 0],
        ["uint16v", "DataCompaction", 0],
        ["uint16v", "Reserved2", 0],
        ["uint16v", "DataLenLow", 0],
        ["uint16v", "DataOffset", 0],
        ["uint32v", "DataLenHigh", 0],
        ["uint32v", "Reserved3", 0],
        ["uint16v", "Reserved4", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_READ_RES_PKT = make_nbs(SMB_READ_RES_HDR_PKT)

    SMB_READ_RES_HDR_PKT_LENGTH = SMB_HDR_LENGTH + 26

    # A SMB template for SMB Search requests
    SMB_SEARCH_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint16v", "MaxCount", 0],
        ["uint16v", "Attributes", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_SEARCH_PKT = make_nbs(SMB_SEARCH_HDR_PKT)

    # A template for SMB TRANS2_FIND_FIRST response parameters
    SMB_TRANS2_FIND_FIRST2_RES_PARAMETERS = CStructTemplate(
        ["uint16v", "SID", 0],
        ["uint16v", "SearchCount", 0],
        ["uint16v", "EndOfSearch", 0],
        ["uint16v", "EaErrorOffset", 0],
        ["uint16v", "LastNameOffset", 0],
    )

    # A template for SMB_FIND_FILE_BOTH_DIRECTORY_INFO Find information level
    SMB_FIND_FILE_BOTH_DIRECTORY_INFO_HDR = CStructTemplate(
        ["uint32v", "NextEntryOffset", 0],
        ["uint32v", "FileIndex", 0],
        ["uint32v", "loCreationTime", 0],
        ["uint32v", "hiCreationTime", 0],
        ["uint32v", "loLastAccessTime", 0],
        ["uint32v", "hiLastAccessTime", 0],
        ["uint32v", "loLastWriteTime", 0],
        ["uint32v", "hiLastWriteTime", 0],
        ["uint32v", "loLastChangeTime", 0],
        ["uint32v", "hiLastChangeTime", 0],
        ["uint64v", "EndOfFile", 0],
        ["uint64v", "AllocationSize", 0],
        ["uint32v", "ExtFileAttributes", 0],
        ["uint32v", "FileNameLength", 0],
        ["uint32v", "EaSize", 0],
        ["uint8", "ShortNameLength", 0],
        ["uint8", "Reserved", 0],
        ["string", "ShortName", 24, "", "\x00"],
        ["string", "FileName", None, ""],
    ).create_restraints(["FileName", "FileNameLength", None, True])

    SMB_FIND_FILE_BOTH_DIRECTORY_INFO_HDR_LENGTH = 94

    # A template for SMB_FIND_FILE_BOTH_DIRECTORY_INFO Find information level
    SMB_FIND_FILE_NAMES_INFO_HDR = CStructTemplate(
        ["uint32v", "NextEntryOffset", 0],
        ["uint32v", "FileIndex", 0],
        ["uint32v", "FileNameLength", 0],
        ["string", "FileName", None, ""],
    ).create_restraints(["FileName", "FileNameLength", None, True])

    SMB_FIND_FILE_NAMES_INFO_HDR_LENGTH = 12

    # A template for SMB_FIND_FILE_FULL_DIRECTORY_INFO Find information level
    SMB_FIND_FILE_FULL_DIRECTORY_INFO_HDR = CStructTemplate(
        ["uint32v", "NextEntryOffset", 0],
        ["uint32v", "FileIndex", 0],
        ["uint32v", "loCreationTime", 0],
        ["uint32v", "hiCreationTime", 0],
        ["uint32v", "loLastAccessTime", 0],
        ["uint32v", "hiLastAccessTime", 0],
        ["uint32v", "loLastWriteTime", 0],
        ["uint32v", "hiLastWriteTime", 0],
        ["uint32v", "loLastChangeTime", 0],
        ["uint32v", "hiLastChangeTime", 0],
        ["uint64v", "EndOfFile", 0],
        ["uint64v", "AllocationSize", 0],
        ["uint32v", "ExtFileAttributes", 0],
        ["uint32v", "FileNameLength", 0],
        ["uint32v", "EaSize", 0],
        ["string", "FileName", None, ""],
    ).create_restraints(["FileName", "FileNameLength", None, True])

    SMB_FIND_FILE_FULL_DIRECTORY_INFO_HDR_LENGTH = 68

    # A template for SMB FIND_FIRST2 TRANS2 response parameters
    SMB_TRANS2_QUERY_PATH_INFORMATION_RES_PARAMETERS = CStructTemplate(["uint16v", "EaErrorOffset", 0])

    # A template for SMB_QUERY_FILE_NETWORK_INFO query path information level
    SMB_QUERY_FILE_NETWORK_INFO_HDR = CStructTemplate(
        ["uint32v", "loCreationTime", 0],
        ["uint32v", "hiCreationTime", 0],
        ["uint32v", "loLastAccessTime", 0],
        ["uint32v", "hiLastAccessTime", 0],
        ["uint32v", "loLastWriteTime", 0],
        ["uint32v", "hiLastWriteTime", 0],
        ["uint32v", "loLastChangeTime", 0],
        ["uint32v", "hiLastChangeTime", 0],
        ["uint64v", "AllocationSize", 0],
        ["uint64v", "EndOfFile", 0],
        ["uint32v", "ExtFileAttributes", 0],
        ["uint32v", "Reserved", 0],
    )

    SMB_QUERY_FILE_NETWORK_INFO_HDR_LENGTH = 56

    # A template for SMB_QUERY_FILE_BASIC_INFO query path information level
    SMB_QUERY_FILE_BASIC_INFO_HDR = CStructTemplate(
        ["uint32v", "loCreationTime", 0],
        ["uint32v", "hiCreationTime", 0],
        ["uint32v", "loLastAccessTime", 0],
        ["uint32v", "hiLastAccessTime", 0],
        ["uint32v", "loLastWriteTime", 0],
        ["uint32v", "hiLastWriteTime", 0],
        ["uint32v", "loLastChangeTime", 0],
        ["uint32v", "hiLastChangeTime", 0],
        ["uint32v", "ExtFileAttributes", 0],
        ["uint32v", "Reserved", 0],
    )

    SMB_QUERY_FILE_BASIC_INFO_HDR_LENGTH = 40

    # A template for SMB_QUERY_FILE_STANDARD_INFO query path information level
    SMB_QUERY_FILE_STANDARD_INFO_HDR = CStructTemplate(
        ["uint64v", "AllocationSize", 0],
        ["uint64v", "EndOfFile", 0],
        ["uint32v", "NumberOfLinks", 0],
        ["uint8", "DeletePending", 0],
        ["uint8", "Directory", 0],
    )

    SMB_QUERY_FILE_STANDARD_INFO_HDR_LENGTH = 22

    # A template for SMB_Data blocks of the SMB_COM_TRANSACTION2 requests
    SMB_DATA_TRANS2 = CStructTemplate(
        ["uint16v", "SubCommand", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Parameters", None, ""],
    ).create_restraints(["Parameters", "ByteCount", None, True])

    # A template for SMB_Parameters blocks of the SMB_COM_TRANSACTION2 QUERY_PATH_INFO responses
    SMB_TRANS2_QUERY_PATH_PARAMETERS = CStructTemplate(
        ["uint16v", "InformationLevel", 0],
        ["uint32v", "Reserved", 0],
        ["string", "FileName", None, ""],
    )

    # A template for SMB_Parameters blocks of the SMB_COM_TRANSACTION2 QUERY_FILE_INFO responses
    SMB_TRANS2_QUERY_FILE_PARAMETERS = CStructTemplate(["uint16v", "FID", 0], ["uint16v", "InformationLevel", 0])

    # A template for SMB_Parameters blocks of the SMB_COM_TRANSACTION2 FIND_FIRST2 responses
    SMB_TRANS2_FIND_FIRST2_PARAMETERS = CStructTemplate(
        ["uint16v", "SearchAttributes", 0],
        ["uint16v", "SearchCount", 0],
        ["uint16v", "Flags", 0],
        ["uint16v", "InformationLevel", 0],
        ["uint32v", "SearchStorageType", 0],
        ["string", "FileName", None, ""],
    )

    # A template for SMB Tree Connect commands in responses
    SMB_TREE_CONN_ANDX_RES_PKT = CStructTemplate(
        ["uint8", "WordCount", 0],
        ["uint8", "AndXCommand", 0],
        ["uint8", "AndXReserved", 0],
        ["uint16v", "AndXOffset", 0],
        ["uint16v", "OptionalSupport", 0],
        ["uint32v", "AccessRights", 0],
        ["uint32v", "GuestAccessRights", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])

    # A template for SMB echo request/reply
    SMB_ECHO_RES_HDR_PKT = CStructTemplate(
        ["template", "SMB", SMB_HDR],
        ["uint16v", "EchoCount", 0],
        ["uint16v", "ByteCount", 0],
        ["string", "Payload", None, ""],
    ).create_restraints(["Payload", "ByteCount", None, True])
    SMB_ECHO_RES_PKT = make_nbs(SMB_ECHO_RES_HDR_PKT)
