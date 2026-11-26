import contextlib
from collections.abc import Sequence
from pathlib import Path

from libs.proto.smb.client import SMBClient
from libs.smb.constants import Constants
from libs.smb.exception import ErrorCode
from terasploit.module.auxiliary import Auxiliary
from terasploit.module.intel import (
    FindingRecord,
    HostRecord,
    ServiceRecord,
)


class TerasploitModule(Auxiliary):
    """Detects MS17-010 vulnerability and the presence of DoublePulsar in Windows System."""

    NAME: str = "MS17-010 Doublepulsar Detection"
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

    AUXILIARY_MODE: Sequence = [(0, "Check MS17-010 and Doublepulsar")]
    OPTIONS: Sequence = ["RHOST", ("RPORT", {"default": 445})]

    def __init__(self):
        """Initialize SMB detection options and named-pipe resources."""
        self.named_pipes = Path(__file__).resolve().parents[4] / "data" / "wordlists" / "named_pipes.txt"
        self.register_options(
            [
                self.opt(
                    "SMBDomain",
                    ".",
                    False,
                    "The Windows domain to use for authentication",
                    self.otype.STRING,
                ),
                self.opt(
                    "SMBName",
                    "*SMBSERVER",
                    True,
                    "The NetBIOS hostname (required for port 139 connections)",
                    self.otype.STRING,
                ),
                self.opt("SMBUser", "", False, "The username to authenticate as", self.otype.STRING),
                self.opt(
                    "SMBPass",
                    "",
                    False,
                    "The password for the specified username",
                    self.otype.STRING,
                ),
            ]
        )
        self.register_advanced_options(
            [
                self.opt(
                    "CHECK_PIPES",
                    False,
                    True,
                    "Check for named pipe on vulnerable hosts",
                    self.otype.BOOL,
                ),
                self.opt(
                    "NAMED_PIPES",
                    self.named_pipes,
                    True,
                    "List of named pipes to check",
                    self.otype.PATH,
                ),
            ]
        )

    def calculate_doublepulsar_xor_key(self, s):
        """Calculates the 32-bit DoublePulsar stream cipher XOR key from the SMB Signature."""
        x = 2 * s ^ (((s & 0xFF00 | (s << 16)) << 8) | (((s >> 16) | s & 0xFF0000) >> 8))
        x = x & 0xFFFFFFFF
        return x

    def calculate_doublepulsar_arch(self, s):
        """Deduces the remote operating system architecture from the SMB Signature field."""
        if s & 0xFFFFFFFF00000000 == 0:
            return "x86 (32-bit)"
        return "x64 (64-bit)"

    def check_pipes_on_vuln_host(self, ctx, conn):
        """Scan for pipes on a host vulnerable to MS17-010."""
        try:
            with open(self.named_pipes, encoding="utf-8", errors="ignore") as file:
                pipes = [pipe.strip() for pipe in file if pipe.strip()]
        except OSError as exc:
            ctx.error(f"Could not open {self.named_pipes}: {exc}")
            return

        if not pipes:
            ctx.error(f"No named pipes found in {self.named_pipes}")
            return

        ctx.info("Scanning for named pipes...")

        for pipe in pipes:
            pipe_path = pipe if pipe.startswith("\\") else f"\\{pipe}"
            fid = None

            try:
                with contextlib.suppress(Exception):
                    fid = conn.nt_create_andx(
                        conn.default_tid,
                        pipe_path,
                        accessMask=0x00020089,
                    )
                    ctx.success(f"{ctx.get_option('RHOST')} - connected to pipe: {pipe_path}")
            finally:
                if fid is not None:
                    with contextlib.suppress(Exception):
                        conn.close(conn.default_tid, fid)

    def run(self, ctx):
        """Scan for the presence of Doublepulsar Implant from NSA."""
        ip = ctx.get_option("RHOST")
        ipc_share = f"\\\\{ip}\\IPC$"

        try:
            conn = SMBClient(
                ctx.get_option("SMBName"),
                ctx.get_option("RHOST"),
                timeout=8,
            )
            conn.login(
                ctx.get_option("SMBUser"),
                ctx.get_option("SMBPass"),
                ctx.get_option("SMBDomain"),
            )
            conn.default_tid = conn.connect_tree(ipc_share)

        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            ctx.error(f"Error: {exc}")
            return

        ctx.info(f"Connected to {ipc_share} with TID = {conn.default_tid}")

        try:
            status = self.do_smb_ms17_010_probe(conn)
            ctx.info(f"Received {status} with FID = {conn.last_fid}")

            if status == "STATUS_INSUFF_SERVER_RESOURCES":
                arch = SMBClient.dcerpc_getarch(ip)
                os_name = conn.get_server_os()

                target_system = f"{os_name} - {arch} Architecture"
                ctx.success(f"The host {ip} is likely vulnerable to MS17-010 - {target_system}")
                self.record_host(
                    ctx,
                    HostRecord(
                        address=ip,
                        hostname=None,
                        platform=os_name,
                        arch=arch,
                        services=[
                            ServiceRecord(
                                port=445,
                                protocol="tcp",
                                name="smb",
                                product="Microsoft SMB",
                                version="SMBv1 (Server Message Block version 1)",
                            ),
                        ],
                        findings=[
                            FindingRecord(
                                name="MS17-010 SMB vulnerability detected",
                                severity="high",
                            ),
                        ],
                    ),
                )

                ctx.info("Scanning for the presence of Doublepulsar...")
                code, signature1, signature2 = self.do_smb_doublepulsar_probe(conn)

                if code == 0x51:
                    ctx.info(
                        f"The host {ip} is likely infected with Doublepulsar implant - "
                        f"Arch {self.calculate_doublepulsar_arch(signature2)}, "
                        f"XOR Key {self.calculate_doublepulsar_xor_key(signature1)}"
                    )
                    self.record_host(
                        ctx,
                        HostRecord(
                            address=ip,
                            hostname=None,
                            platform=os_name,
                            arch=arch,
                            services=[
                                ServiceRecord(
                                    port=445,
                                    protocol="tcp",
                                    name="smb",
                                    product="Microsoft SMB",
                                    version="SMBv1 (Server Message Block version 1)",
                                ),
                            ],
                            findings=[
                                FindingRecord(
                                    name="Doublepulsar nation-state implant detected",
                                    severity="critical",
                                ),
                            ],
                        ),
                    )
                else:
                    ctx.warning(f"The host {ip} is likely not infected with DoublePulsar")

                if ctx.get_option("CHECK_PIPES"):
                    self.check_pipes_on_vuln_host(ctx, conn)

            elif status in ("STATUS_ACCESS_DENIED", "STATUS_INVALID_HANDLE"):
                ctx.error(f"The host {ip} does NOT appear vulnerable to MS17-010")

            else:
                ctx.error(f"Unable to determine vulnerability status — received: {status}")

        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            ctx.error(f"Error: {exc}")

        finally:
            with contextlib.suppress(Exception):
                conn.disconnect_tree(conn.default_tid)
                conn.logoff()

            with contextlib.suppress(Exception):
                conn.get_socket().close()

    def do_smb_setup_tree(self, ctx, ipc_share):
        """Connect to an SMB1 target using SMBClient, authenticate, and connect to the share."""

        # SMBClient is required here — smb_defaults() must pull from an established session.
        conn = SMBClient(ctx.get_option("SMBName"), ctx.get_option("RHOST"), timeout=8)

        try:
            conn.login(
                ctx.get_option("SMBUser"),
                ctx.get_option("SMBPass"),
                ctx.get_option("SMBDomain"),
            )
            tree_id = conn.connect_tree(ipc_share)
            uid = conn.get_uid()
        except Exception as exc:
            with contextlib.suppress(Exception):
                conn.disconnect()
            raise RuntimeError(f"Failed to connect to share {ipc_share}: {exc}") from exc

        return conn, tree_id, uid

    def do_smb_ms17_010_probe(self, conn):
        """Send a TRANS request with FID=0 and return the NT status string."""
        packet = self.make_smb_trans_ms17_010(conn)

        smb_socket = conn.get_socket()
        smb_socket.sendall(packet)
        bytes_received = smb_socket.recv(4096)

        # Raw socket receive includes 4-byte NetBIOS session header — strip it.
        smb_data = bytes_received[4:]

        # SMB_TRANS_RES_HDR_PKT needs at least SMB_HDR (33) + TRANS fields (22) = 55 bytes.
        # Shorter responses are bare error headers — parse with SMB_BASE_HDR_PKT instead.
        smb_trans_res_min = Constants.SMB_TRANS_RES_PKT_LENGTH

        if len(smb_data) < smb_trans_res_min:
            base = Constants.SMB_BASE_HDR_PKT.make_struct()
            base.from_s(smb_data)
            return ErrorCode().get_error(base["SMB"]["ErrorClass"])

        response_pkt = Constants.SMB_TRANS_RES_HDR_PKT.make_struct()
        response_pkt.from_s(smb_data)
        return ErrorCode().get_error(response_pkt["SMB"]["ErrorClass"])

    def do_smb_doublepulsar_probe(self, conn):
        """Send a TRANS2 knock and return (multiplex_id, signature1, signature2)."""
        packet = self.make_smb_trans2_doublepulsar(conn)

        smb_socket = conn.get_socket()
        smb_socket.sendall(packet)
        bytes_received = smb_socket.recv(4096)

        # Raw socket receive includes 4-byte NetBIOS session header — strip it.
        smb_data = bytes_received[4:]

        smb_trans_res_min = Constants.SMB_TRANS_RES_PKT_LENGTH

        if len(smb_data) < smb_trans_res_min:
            base = Constants.SMB_BASE_HDR_PKT.make_struct()
            base.from_s(smb_data)
            return base["SMB"]["MultiplexID"], base["SMB"]["Signature1"], base["SMB"]["Signature2"]

        response_pkt = Constants.SMB_TRANS_RES_HDR_PKT.make_struct()
        response_pkt.from_s(smb_data)
        return (
            response_pkt["SMB"]["MultiplexID"],
            response_pkt["SMB"]["Signature1"],
            response_pkt["SMB"]["Signature2"],
        )

    def make_smb_trans2_doublepulsar(self, conn):
        """Build a raw TRANS2 SESSION_SETUP packet for the DoublePulsar knock."""
        packet = Constants.SMB_TRANS2_PKT.make_struct()

        # Pull UID, TID, PID, MID from the established session.
        conn.smb_defaults(packet["Payload"]["SMB"])

        # opcode 0x0e = SESSION_SETUP
        setup = b"\x0e\x00\x00\x00"
        setup_count = 1
        trans = b"\x00" * 12

        packet["Payload"]["SMB"]["Command"] = Constants.SMB_COM_TRANSACTION2
        packet["Payload"]["SMB"]["Flags1"] = 0x18
        packet["Payload"]["SMB"]["MultiplexID"] = 65
        packet["Payload"]["SMB"]["Flags2"] = 0xC007
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

    def make_smb_trans_ms17_010(self, conn):
        """Build a raw TRANS PeekNamedPipe packet targeting FID=0 on \\PIPE\\."""
        packet = Constants.SMB_TRANS_PKT.make_struct()

        # Pull UID, TID, PID, MID from the established session.
        conn.smb_defaults(packet["Payload"]["SMB"])

        # PeekNamedPipe opcode 0x23, FID=0
        setup = b"\x23\x00\x00\x00"
        setup_count = 2
        trans = b"\x5c\x50\x49\x50\x45\x5c\x00"  # \PIPE\<null>

        base_offset = len(packet.to_bytes()) + len(setup) - 4
        param_offset = base_offset + len(trans)
        data_offset = param_offset

        packet["Payload"]["SMB"]["Command"] = Constants.SMB_COM_TRANSACTION
        packet["Payload"]["SMB"]["Flags1"] = 0x18
        packet["Payload"]["SMB"]["Flags2"] = 0x2801
        packet["Payload"]["SMB"]["WordCount"] = 14 + setup_count

        packet["Payload"]["ParamCountMax"] = 0xFFFF
        packet["Payload"]["DataCountMax"] = 0xFFFF
        packet["Payload"]["ParamOffset"] = param_offset
        packet["Payload"]["DataOffset"] = data_offset
        packet["Payload"]["SetupCount"] = setup_count
        packet["Payload"]["SetupData"] = setup
        packet["Payload"]["Payload"] = trans

        return packet.to_bytes()
