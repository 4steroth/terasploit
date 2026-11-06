import contextlib
import os
from collections.abc import Sequence

from impacket.smbconnection import SMB_DIALECT, SMBConnection

from teralibs.tsf.base.auxiliary import Auxiliary
from teralibs.tsf.pex.proto.smb.client import Client
from teralibs.tsf.pex.smb.constants import Constants
from teralibs.tsf.pex.smb.exception import ErrorCode


class TerasploitModule(Auxiliary):
    """Detects MS17-010 vulnerabillity and the presence of DoublePulsar in Windows System."""

    NAME: str = "MS17-010 DoublePulsar Detection "
    DESCRIPTION: str = (
        "This module detects the presence of the DoublePulsar backdoor on a target "
        "system by sending specially crafted SMB requests and analyzing the responses "
        "for indicators of infection. It identifies systems potentially compromised by "
        "the DoublePulsar implant without executing arbitrary code on the target."
    )
    AUTHOR: Sequence = [
        "Sean Dillon <sean.dillon@risksense.com> - @zerosum0x0",
        "Luke Jennings - DoublePulsar detection Python code",
        "4steroth - Terasploit module",
    ]
    LICENSE: str = "BSD-3-CLAUSE"
    VERSION: str = "1.0"
    RANK: str = "normal"
    REFERENCES: Sequence = [
        ["CVE", "2017-0143"],
        ["CVE", "2017-0144"],
        ["CVE", "2017-0145"],
        ["CVE", "2017-0146"],
        ["CVE", "2017-0147"],
        ["CVE", "2017-0148"],
        ["MSB", "MS17-010"],
        ["URL", "https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html"],
        ["URL", "https://github.com/countercept/doublepulsar-detection-script"],
        ["URL", "https://web.archive.org/web/20170513050203/https://technet.microsoft.com/en-us/library/security/ms17-010.aspx"],
    ]

    OPTIONS: Sequence = ["RHOST", ("RPORT", {"default": 445})]

    def __init__(self):
        self.named_pipes = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))),
            "data",
            "wordlists",
            "named_pipes.txt",
        )
        self.register_options(
            [
                self.opt("SMBDomain", ".", False, "The Windows domain to use for authentication", self.otype.STRING),
                self.opt("SMBName", "*SMBSERVER", True, "The NetBIOS hostname (required for port 139 connections)", self.otype.STRING),
                self.opt("SMBUser", "", False, "The username to authenticate as", self.otype.STRING),
                self.opt("SMBPass", "", False, "The password for the specified username", self.otype.STRING),
            ]
        )
        self.register_advanced_options(
            [
                self.opt("CHECK_PIPES", True, True, "Check for named pipe on vulnerable hosts", self.otype.BOOL),
                self.opt("NAMED_PIPES", self.named_pipes, True, "List of named pipes to check", self.otype.PATH),
            ]
        )

    # https://zerosum0x0.blogspot.com/2017/04/doublepulsar-initial-smb-backdoor-ring.html
    def calculate_doublepulsar_xor_key(self, s):
        """
        Calculates the 32-bit DoublePulsar stream cipher XOR key from the SMB Signature.
        """
        x = 2 * s ^ (((s & 0xFF00 | (s << 16)) << 8) | (((s >> 16) | s & 0xFF0000) >> 8))
        x = x & 0xFFFFFFFF  # this line was added just to truncate to 32 bits
        return x

    # The arch is adjacent to the XOR key in the SMB signature
    def calculate_doublepulsar_arch(self, s):
        """
        Deduces the remote operating system architecture from the SMB Signature field.
        """
        if s & 0xFFFFFFFF00000000 == 0:
            return "x86 (32-bit)"

        return "x64 (64-bit)"

    def check_pipes_on_vuln_host(self, ctx, conn, tree_id):
        """Scan for pipes on host vulnerable to MS17-010."""

        pipes = None
        with contextlib.suppress(Exception), open(self.named_pipes, encoding="utf-8", errors="ignore") as f:
            pipes = [x.strip() for x in f.readlines()]

        if not pipes:
            ctx.error(f"Could not open {self.named_pipes}")
            return

        # Scan for pipes
        ctx.info("Scanning for named pipes...")
        for pipe in pipes:
            with contextlib.suppress(Exception):
                pipe_path = f"\\{pipe}"
                fid = conn.createFile(treeId=tree_id, pathName=pipe_path, desiredAccess=0x00020089)

                # If it did not raise an exception, it's accessible.
                ctx.success(f"{ctx.get_option('RHOST')} - '{pipe_path}' pipe exists and accessible!")
                # Cleanup
                conn.closeFile(tree_id, fid)

    def run(self, ctx):
        """Scan for the presence of DoublePulsar from NSA."""
        ip = ctx.get_option("RHOST")
        ipc_share = f"\\\\{ip}\\IPC$"

        # Get the tree id
        try:
            conn, tree_id, uid = self.do_smb_setup_tree(ctx, ipc_share)

        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            ctx.error(f"Error: {exc}")
            return

        ctx.info(f"Connected to {ipc_share} with TID = {tree_id}")
        try:
            status = self.do_smb_ms17_010_probe(tree_id, uid, conn)
            ctx.info(f"Received {status} with FID = 0")

            # Check arch
            arch = None
            if status == "STATUS_INSUFF_SERVER_RESOURCES":
                arch = Client.dcerpc_getarch(ip)

            os_name = conn.getServerOS()
            target_system = f"{os_name} - {arch} Architecture"
            ctx.success(f"The host {ip} is likely vulnerable to MS17-010 - {target_system}")

            # Checking for the presence of doublepulsar in the system...
            ctx.info("Scanning for the presence of DoublePulsar...")
            code, signature1, signature2 = self.do_smb_doublepulsar_probe(tree_id, uid, conn)

            if code == 0x51:
                ctx.info(
                    f"The host {ip} is likey infected with doublepulsar - "
                    f"Arch {self.calculate_doublepulsar_arch(signature2)}, XOR Key {self.calculate_doublepulsar_xor_key(signature1)}"
                )
            else:
                ctx.info(f"The host {ip} is likely not infected with doublepulsar")

            if ctx.get_option("CHECK_PIPES"):
                self.check_pipes_on_vuln_host(ctx, conn, tree_id)

        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            ctx.error(f"Error: {exc}")

        finally:
            with contextlib.suppress(Exception):
                conn.logoff()
                conn.close()

    def do_smb_setup_tree(self, ctx, ipc_share):
        """
        Connects to an SMB target, authenticates, and returns an
        Impacket SMBConnection object ready for share/pipe operations.
        """
        smb_name = ctx.get_option("SMBName")
        rhost = ctx.get_option("RHOST")
        rport = int(ctx.get_option("RPORT"))

        # We force the connection wrapper to ONLY negotiate legacy SMB1
        conn = SMBConnection(smb_name, rhost, sess_port=rport, preferredDialect=SMB_DIALECT)
        conn.login(ctx.get_option("SMBUser"), ctx.get_option("SMBPass"), ctx.get_option("SMBDomain"))
        try:
            # Example: list root of the requested share (e.g., IPC$)
            tree_id = conn.connectTree(ipc_share)
            smb_server = conn.getSMBServer()

            # This is ignored because it is a library level error from pyright
            uid = smb_server.get_uid()  # pyright: ignore

        except Exception as e:
            conn.logoff()
            raise RuntimeError(f"Failed to connect to share {ipc_share}: {e}") from e

        return conn, tree_id, uid

    def do_smb_ms17_010_probe(self, tree_id, uid, conn):
        """Request transaction with fid = 0."""
        packet = self.make_smb_trans_ms17_010(tree_id, uid)

        smb = conn.getSMBServer()
        smb_socket = smb.get_socket()
        smb_socket.sendall(packet)
        bytes_received = smb_socket.recv(4096)

        smb_data = bytes_received[4:]

        # WordCount sits at byte 32 of the fixed SMB header. An error response
        # returns WordCount=0 — no TRANS parameter block follows. The framework raises.
        # Guard here so SMB_TRANS_RES_HDR_PKT only runs on responses that have a body.
        word_count = smb_data[32] if len(smb_data) > 32 else 0
        smb_error = ErrorCode()

        if word_count == 0:
            base = Constants.SMB_BASE_HDR_PKT.make_struct()
            base.from_s(smb_data)
            return smb_error.get_error(base["SMB"]["ErrorClass"])

        response = Constants.SMB_TRANS_RES_HDR_PKT.make_struct()
        response.from_s(smb_data)
        return smb_error.get_error(response["SMB"]["ErrorClass"])

    def do_smb_doublepulsar_probe(self, tree_id, uid, conn):
        """Do smb doublepulsar probe."""
        packet = self.make_smb_trans2_doublepulsar(tree_id, uid)

        smb = conn.getSMBServer()
        smb_socket = smb.get_socket()
        smb_socket.sendall(packet)
        bytes_received = smb_socket.recv(4096)

        smb_data = bytes_received[4:]
        word_count = smb_data[32] if len(smb_data) > 32 else 0

        if word_count == 0:
            base = Constants.SMB_BASE_HDR_PKT.make_struct()
            base.from_s(smb_data)
            return base["SMB"]["MultiplexID"], base["SMB"]["Signature1"], base["SMB"]["Signature2"]

        response = Constants.SMB_TRANS_RES_HDR_PKT.make_struct()
        response.from_s(smb_data)
        return response["SMB"]["MultiplexID"], response["SMB"]["Signature1"], response["SMB"]["Signature2"]

    def make_smb_trans2_doublepulsar(self, tree_id, uid):
        """Make a raw transaction packet (trans2)."""

        packet = Constants.SMB_TRANS2_PKT.make_struct()
        smb = Client(tree_id, uid)
        smb.smb_defaults(packet)

        # opcode 0x0e = SESSION_SETUP
        setup = b"\x0e\x00\x00\x00"
        setup_count = 1  # 1 word
        trans = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        # calculate offsets to the SetupData payload
        base_offset = len(packet.to_bytes()) + len(setup) - 4
        param_offset = base_offset + len(trans)
        _data_offset = param_offset  # + 0

        # packet baselines
        packet["Payload"]["SMB"]["Command"] = Constants.SMB_COM_TRANSACTION2
        packet["Payload"]["SMB"]["Flags1"] = 0x18
        packet["Payload"]["SMB"]["MultiplexID"] = 65
        packet["Payload"]["SMB"]["Flags2"] = 0xC007
        packet["Payload"]["SMB"]["TreeID"] = tree_id
        packet["Payload"]["SMB"]["WordCount"] = 14 + setup_count

        packet["Payload"]["Timeout"] = 0x00A4D9A6
        packet["Payload"]["ParamCountTotal"] = 12
        packet["Payload"]["ParamCount"] = 12
        packet["Payload"]["ParamCountMax"] = 1
        packet["Payload"]["DataCountMax"] = 0
        packet["Payload"]["ParamOffset"] = 66
        packet["Payload"]["DataOffset"] = 78

        packet["Payload"]["SetupCount"] = setup_count
        packet["Payload"]["SetupData"] = setup
        packet["Payload"]["Payload"] = trans

        return packet.to_bytes()

    def make_smb_trans_ms17_010(self, tree_id, uid):
        """Make a raw transaction packet."""

        packet = Constants.SMB_TRANS_PKT.make_struct()
        smb = Client(tree_id, uid)
        smb.smb_defaults(packet)

        # This evaluates precisely to: \PIPE\ followed by a null byte
        trans = b"\x5c\x50\x49\x50\x45\x5c\x00"

        # Setup definition (PeekNamedPipe opcode 0x23, FID 0)
        setup = b"\x23\x00\x00\x00"  # 4 bytes
        setup_count = 2  # 2 words

        # Calculate offsets to the SetupData payload
        base_offset = len(packet.to_bytes()) + len(setup) - 4
        param_offset = base_offset + len(trans)
        data_offset = param_offset  # + 0

        packet["Payload"]["SMB"]["Command"] = Constants.SMB_COM_TRANSACTION
        packet["Payload"]["SMB"]["Flags1"] = 0x18
        packet["Payload"]["SMB"]["Flags2"] = 0x2801  # 0xc803 would unicode
        packet["Payload"]["SMB"]["TreeID"] = tree_id
        packet["Payload"]["SMB"]["WordCount"] = 14 + setup_count

        packet["Payload"]["ParamCountMax"] = 0xFFFF
        packet["Payload"]["DataCountMax"] = 0xFFFF
        packet["Payload"]["ParamOffset"] = param_offset
        packet["Payload"]["DataOffset"] = data_offset

        # actual magic: PeekNamedPipe FID=0, \PIPE\
        packet["Payload"]["SetupCount"] = setup_count
        packet["Payload"]["SetupData"] = setup
        packet["Payload"]["Payload"] = trans

        return packet.to_bytes()
