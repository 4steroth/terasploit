import struct


def merge_dicts(*dict_args):
    """Merge multiple dictionaries into a single dictionary."""
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result


WIN7_64_SESSION_INFO = {
    "SESSION_SECCTX_OFFSET": 0xA0,
    "SESSION_ISNULL_OFFSET": 0xBA,
    "FAKE_SECCTX": struct.pack("<IIQQIIB", 0x28022A, 1, 0, 0, 2, 0, 1),
    "SECCTX_SIZE": 0x28,
}

WIN7_32_SESSION_INFO = {
    "SESSION_SECCTX_OFFSET": 0x80,
    "SESSION_ISNULL_OFFSET": 0x96,
    "FAKE_SECCTX": struct.pack("<IIIIIIB", 0x1C022A, 1, 0, 0, 2, 0, 1),
    "SECCTX_SIZE": 0x1C,
}

# Windows 8 and later.
WIN8_64_SESSION_INFO = {
    "SESSION_SECCTX_OFFSET": 0xB0,
    "SESSION_ISNULL_OFFSET": 0xCA,
    "FAKE_SECCTX": struct.pack("<IIQQQQIIB", 0x38022A, 1, 0, 0, 0, 0, 2, 0, 1),
    "SECCTX_SIZE": 0x38,
}

WIN8_32_SESSION_INFO = {
    "SESSION_SECCTX_OFFSET": 0x88,
    "SESSION_ISNULL_OFFSET": 0x9E,
    "FAKE_SECCTX": struct.pack("<IIIIIIIIB", 0x24022A, 1, 0, 0, 0, 0, 2, 0, 1),
    "SECCTX_SIZE": 0x24,
}

# Windows 2003 (Windows XP 64-bit uses the Windows 2003 kernel).
WIN2K3_64_SESSION_INFO = {
    "SESSION_ISNULL_OFFSET": 0xBA,
    "SESSION_SECCTX_OFFSET": 0xA0,
    "SECCTX_PCTXTHANDLE_OFFSET": 0x10,
    "PCTXTHANDLE_TOKEN_OFFSET": 0x40,
    "TOKEN_USER_GROUP_CNT_OFFSET": 0x4C,
    "TOKEN_USER_GROUP_ADDR_OFFSET": 0x68,
}

WIN2K3_32_SESSION_INFO = {
    "SESSION_ISNULL_OFFSET": 0x96,
    "SESSION_SECCTX_OFFSET": 0x80,
    "SECCTX_PCTXTHANDLE_OFFSET": 0x0C,
    "PCTXTHANDLE_TOKEN_OFFSET": 0x24,
    "TOKEN_USER_GROUP_CNT_OFFSET": 0x4C,
    "TOKEN_USER_GROUP_ADDR_OFFSET": 0x68,
}

# Windows XP.
WINXP_32_SESSION_INFO = {
    "SESSION_ISNULL_OFFSET": 0x94,
    "SESSION_SECCTX_OFFSET": 0x84,
    "PCTXTHANDLE_TOKEN_OFFSET": 0x24,
    "TOKEN_USER_GROUP_CNT_OFFSET": 0x4C,
    "TOKEN_USER_GROUP_ADDR_OFFSET": 0x68,
    "TOKEN_USER_GROUP_CNT_OFFSET_SP0_SP1": 0x40,
    "TOKEN_USER_GROUP_ADDR_OFFSET_SP0_SP1": 0x5C,
}

WIN2K_32_SESSION_INFO = {
    "SESSION_ISNULL_OFFSET": 0x94,
    "SESSION_SECCTX_OFFSET": 0x84,
    "PCTXTHANDLE_TOKEN_OFFSET": 0x24,
    "TOKEN_USER_GROUP_CNT_OFFSET": 0x3C,
    "TOKEN_USER_GROUP_ADDR_OFFSET": 0x58,
}

# Windows 2008 and later.
WIN7_32_TRANS_INFO = {
    "TRANS_SIZE": 0xA0,
    "TRANS_FLINK_OFFSET": 0x18,
    "TRANS_INPARAM_OFFSET": 0x40,
    "TRANS_OUTPARAM_OFFSET": 0x44,
    "TRANS_INDATA_OFFSET": 0x48,
    "TRANS_OUTDATA_OFFSET": 0x4C,
    "TRANS_PARAMCNT_OFFSET": 0x58,
    "TRANS_TOTALPARAMCNT_OFFSET": 0x5C,
    "TRANS_FUNCTION_OFFSET": 0x72,
    "TRANS_MID_OFFSET": 0x80,
}

WIN7_64_TRANS_INFO = {
    "TRANS_SIZE": 0xF8,
    "TRANS_FLINK_OFFSET": 0x28,
    "TRANS_INPARAM_OFFSET": 0x70,
    "TRANS_OUTPARAM_OFFSET": 0x78,
    "TRANS_INDATA_OFFSET": 0x80,
    "TRANS_OUTDATA_OFFSET": 0x88,
    "TRANS_PARAMCNT_OFFSET": 0x98,
    "TRANS_TOTALPARAMCNT_OFFSET": 0x9C,
    "TRANS_FUNCTION_OFFSET": 0xB2,
    "TRANS_MID_OFFSET": 0xC0,
}

WIN5_32_TRANS_INFO = {
    "TRANS_SIZE": 0x98,
    "TRANS_FLINK_OFFSET": 0x18,
    "TRANS_INPARAM_OFFSET": 0x3C,
    "TRANS_OUTPARAM_OFFSET": 0x40,
    "TRANS_INDATA_OFFSET": 0x44,
    "TRANS_OUTDATA_OFFSET": 0x48,
    "TRANS_PARAMCNT_OFFSET": 0x54,
    "TRANS_TOTALPARAMCNT_OFFSET": 0x58,
    "TRANS_FUNCTION_OFFSET": 0x6E,
    "TRANS_PID_OFFSET": 0x78,
    "TRANS_MID_OFFSET": 0x7C,
}

WIN5_64_TRANS_INFO = {
    "TRANS_SIZE": 0xE0,
    "TRANS_FLINK_OFFSET": 0x28,
    "TRANS_INPARAM_OFFSET": 0x68,
    "TRANS_OUTPARAM_OFFSET": 0x70,
    "TRANS_INDATA_OFFSET": 0x78,
    "TRANS_OUTDATA_OFFSET": 0x80,
    "TRANS_PARAMCNT_OFFSET": 0x90,
    "TRANS_TOTALPARAMCNT_OFFSET": 0x94,
    "TRANS_FUNCTION_OFFSET": 0xAA,
    "TRANS_PID_OFFSET": 0xB4,
    "TRANS_MID_OFFSET": 0xB8,
}

X86_INFO = {
    "ARCH": "x86",
    "PTR_SIZE": 4,
    "PTR_FMT": "<I",
    "FRAG_TAG_OFFSET": 12,
    "POOL_ALIGN": 8,
    "SRV_BUFHDR_SIZE": 8,
}

X64_INFO = {
    "ARCH": "x64",
    "PTR_SIZE": 8,
    "PTR_FMT": "<Q",
    "FRAG_TAG_OFFSET": 0x14,
    "POOL_ALIGN": 0x10,
    "SRV_BUFHDR_SIZE": 0x10,
}


OS_ARCH_INFO = {
    # Windows Vista, Server 2008, 7, and Server 2008 R2.
    "WIN7": {
        "x86": merge_dicts(
            X86_INFO,
            WIN7_32_TRANS_INFO,
            WIN7_32_SESSION_INFO,
        ),
        "x64": merge_dicts(
            X64_INFO,
            WIN7_64_TRANS_INFO,
            WIN7_64_SESSION_INFO,
        ),
    },
    # Windows 8 and later.
    "WIN8": {
        "x86": merge_dicts(
            X86_INFO,
            WIN7_32_TRANS_INFO,
            WIN8_32_SESSION_INFO,
        ),
        "x64": merge_dicts(
            X64_INFO,
            WIN7_64_TRANS_INFO,
            WIN8_64_SESSION_INFO,
        ),
    },
    "WINXP": {
        "x86": merge_dicts(
            X86_INFO,
            WIN5_32_TRANS_INFO,
            WINXP_32_SESSION_INFO,
        ),
        "x64": merge_dicts(
            X64_INFO,
            WIN5_64_TRANS_INFO,
            WIN2K3_64_SESSION_INFO,
        ),
    },
    "WIN2K3": {
        "x86": merge_dicts(
            X86_INFO,
            WIN5_32_TRANS_INFO,
            WIN2K3_32_SESSION_INFO,
        ),
        "x64": merge_dicts(
            X64_INFO,
            WIN5_64_TRANS_INFO,
            WIN2K3_64_SESSION_INFO,
        ),
    },
    "WIN2K": {
        "x86": merge_dicts(
            X86_INFO,
            WIN5_32_TRANS_INFO,
            WIN2K_32_SESSION_INFO,
        ),
    },
}
