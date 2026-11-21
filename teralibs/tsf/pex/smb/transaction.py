from impacket import smb


# info for exploitation
# for windows 2008+
WIN7_32_TRANS_INFO = {
    "TRANS_SIZE": 0xA0,  # struct size
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
    "TRANS_SIZE": 0xF8,  # struct size
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
    "TRANS_SIZE": 0x98,  # struct size
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
    "TRANS_SIZE": 0xE0,  # struct size
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
    "PTR_FMT": "I",
    "FRAG_TAG_OFFSET": 12,
    "POOL_ALIGN": 8,
    "SRV_BUFHDR_SIZE": 8,
}

X64_INFO = {
    "ARCH": "x64",
    "PTR_SIZE": 8,
    "PTR_FMT": "Q",
    "FRAG_TAG_OFFSET": 0x14,
    "POOL_ALIGN": 0x10,
    "SRV_BUFHDR_SIZE": 0x10,
}


class SMBTransactionSecondaryParameters(smb.SMBCommand_Parameters):
    """Wire structure for SMB_COM_TRANSACTION_SECONDARY (0x26)."""

    structure = (
        ("TotalParameterCount", "<H=0"),
        ("TotalDataCount", "<H"),
        ("ParameterCount", "<H=0"),
        ("ParameterOffset", "<H=0"),
        ("ParameterDisplacement", "<H=0"),
        ("DataCount", "<H"),
        ("DataOffset", "<H"),
        ("DataDisplacement", "<H=0"),
    )


class SMBTransaction2SecondaryParameters(smb.SMBCommand_Parameters):
    """Wire structure for SMB_COM_TRANSACTION2_SECONDARY (0x33)."""

    structure = (
        ("TotalParameterCount", "<H=0"),
        ("TotalDataCount", "<H"),
        ("ParameterCount", "<H=0"),
        ("ParameterOffset", "<H=0"),
        ("ParameterDisplacement", "<H=0"),
        ("DataCount", "<H"),
        ("DataOffset", "<H"),
        ("DataDisplacement", "<H=0"),
        ("FID", "<H=0"),
    )


class SMBNTTransactionSecondaryParameters(smb.SMBCommand_Parameters):
    """Wire structure for SMB_COM_NT_TRANSACTION_SECONDARY (0xA1)."""

    structure = (
        ("Reserved1", '3s=""'),
        ("TotalParameterCount", "<L"),
        ("TotalDataCount", "<L"),
        ("ParameterCount", "<L"),
        ("ParameterOffset", "<L"),
        ("ParameterDisplacement", "<L=0"),
        ("DataCount", "<L"),
        ("DataOffset", "<L"),
        ("DataDisplacement", "<L=0"),
        ("Reserved2", "<B=0"),
    )
