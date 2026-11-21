import contextlib
import os
import random
import struct

from impacket import smb, smbconnection
from impacket.dcerpc.v5 import transport as dcerpc_transport
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory

from teralibs.tsf.pex.smb import transaction
from teralibs.tsf.pex.smb.constants import Constants
from teralibs.tsf.pex.text import Text


ORIGINAL_SMB_ADD_COMMAND = smb.NewSMBPacket.addCommand


class SMBClient(smb.SMB):
    """SMB client tailored for exploitation."""

    def __init__(self, remote_name, remote_host, use_ntlmv2=False, timeout=8):
        self._use_ntlmv2 = use_ntlmv2

        # The default tree_id
        self.default_tid = None

        # Process ID
        self.pid = os.getpid() & 0xFFFF

        # Last multiplex id
        self.last_mid = random.randint(1000, 20000)
        if 0x4000 <= self.last_mid <= 0x4110:
            self.last_mid += 0x120

        # Packet flags2
        self.packet_flags2 = 0

        # last tid from connect_tree()
        self.last_tid = 0

        # last fid from nt_create_andx()
        self.last_fid = 0

        self.max_buffer_size = 61440

        smb.SMB.__init__(self, remote_name, remote_host, timeout=timeout)

        self.smb_connection = None

    # By the design of some api's, I will disable too-many-arguments(R0913) and too-many-positional-argument(R0917)
    # I disabled this because I do not want to make things more complicated.
    # pylint: disable=R0913, R0917

    def get_smbconnection(self):
        """Return the existing SMB session as an SMBConnection instance."""
        if self.smb_connection is None:
            self.smb_connection = smbconnection.SMBConnection(
                self.get_remote_host(),
                self.get_remote_host(),
                existingConnection=self,
                manualNegotiate=True,
            )
        return self.smb_connection

    def get_dce_rpc(self, named_pipe):
        """Create a DCE/RPC transport over the existing SMB session."""

        # For some reason, I dont know why linter think smb_connection argument
        # only accepts int and not SMBConnection when both is accepted.
        rpc_transport = dcerpc_transport.SMBTransport(
            self.get_remote_host(),
            self.get_remote_host(),
            filename=f"\\{named_pipe.lstrip('\\')}",
            smb_connection=self.get_smbconnection(),  # type: ignore[arg-type]
        )
        return rpc_transport.get_dce_rpc()

    def disconnect(self):
        """Disconnect active SMB trees, log off, and close the connection."""
        tids = {self.last_tid, self.default_tid} - {None, 0}

        for tid in tids:
            with contextlib.suppress(Exception):
                self.disconnect_tree(tid)

        with contextlib.suppress(Exception):
            self.logoff()

        self.last_tid = 0
        self.default_tid = None

        with contextlib.suppress(Exception):
            self.get_socket().close()

    def do_smb_echo(self, tid=None, uid=None, pid=None, mid=None, data=None):
        """Send an SMB1 echo request and receive the response."""

        if data is None:
            data = Text.rand_text_alpha(1)  # "\x41"

        pkt = smb.NewSMBPacket()

        pkt["Tid"] = tid if tid is not None else self.last_tid
        pkt["Uid"] = uid if uid is not None else self.get_uid()
        pkt["Pid"] = pid if pid is not None else self.pid
        pkt["Mid"] = mid if mid is not None else self.next_mid()

        pkt["Flags1"] = 0x18
        pkt["Flags2"] = 0x0001

        echo = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
        echo["Parameters"] = smb.SMBEcho_Parameters()
        echo["Parameters"]["EchoCount"] = 1
        echo["Data"] = data

        pkt.addCommand(echo)

        self.sendSMB(pkt)
        return self.recvSMB()

    def smb_send_recv_raw(self, raw):
        """Send a raw SMB packet and receive the response."""
        self.send_raw(raw)
        data = self.recvSMB()

        smb_bytes = data.getData()
        # recvSMB() strips the 4-byte NBSS session header before returning.
        # SMB_BASE_PKT (via make_nbs) expects NBSS framing, so reconstruct it
        # from the SMB body length before parsing.
        nbt_framed = b"\x00\x00" + struct.pack(">H", len(smb_bytes)) + smb_bytes

        pkt = Constants.SMB_BASE_PKT.make_struct()
        pkt.from_s(nbt_framed)

        return pkt

    def do_write_andx_raw_pipe(
        self,
        fid=None,
        data=b"",
        tid=None,
        pid=None,
        mid=None,
    ):
        """Construct and send an SMB1 raw named-pipe WriteAndX request."""
        write_andx = smb.SMBCommand(smb.SMB.SMB_COM_WRITE_ANDX)

        write_andx["Parameters"] = smb.SMBWriteAndX_Parameters_Short()
        write_andx["Parameters"]["Fid"] = fid
        write_andx["Parameters"]["Offset"] = 0
        write_andx["Parameters"]["WriteMode"] = 4  # SMB_WMODE_WRITE_RAW_NAMED_PIPE
        write_andx["Parameters"]["Remaining"] = 0x1337  # can be any. raw named pipe does not use it
        write_andx["Parameters"]["DataLength"] = len(data)
        write_andx["Parameters"]["DataOffset"] = 32 + len(write_andx["Parameters"]) + 1 + 2 + 1  # WordCount(1), ByteCount(2), Padding(1)

        write_andx["Data"] = b"\x00" + data  # pad 1 byte

        self.send_raw(self.create_smb_packet(write_andx, mid, pid, tid))
        return self.recvSMB()

    def connect_tree(self, path, password=None, service=smb.SERVICE_ANY, smb_packet=None):
        """Connect to a remote tree (share) via SMB_COM_TREE_CONNECT_ANDX and cache the resulting TID."""
        self.last_tid = smb.SMB.tree_connect_andx(self, path, password, service, smb_packet)
        return self.last_tid

    def create_smb_packet(self, smbpkt, mid=None, pid=None, tid=None):
        """Set common SMB1 header values."""
        if mid is None:
            mid = self.next_mid()

        pkt = smb.NewSMBPacket()
        pkt.addCommand(smbpkt)
        pkt["Tid"] = self.default_tid if tid is None else tid
        pkt["Uid"] = self.get_uid()
        pkt["Pid"] = self.pid if pid is None else pid
        pkt["Mid"] = mid

        flags1, flags2 = self.get_flags()

        pkt["Flags1"] = flags1
        pkt["Flags2"] = self.packet_flags2 if self.packet_flags2 != 0 else flags2

        if self.signing_enabled:
            pkt["Flags2"] |= smb.SMB.FLAGS2_SMB_SECURITY_SIGNATURE
            self.signSMB(pkt, self.signing_session_key, self.signing_challenge_response)

        req = pkt.getData()
        return b"\x00" * 2 + struct.pack(">H", len(req)) + req  # assume length is <65536

    def nt_create_andx(
        self,
        tid,
        filename,
        smb_packet=None,
        cmd=None,
        shareAccessMode=smb.FILE_SHARE_READ | smb.FILE_SHARE_WRITE,
        disposition=smb.FILE_OPEN,
        accessMask=0x2019F,
    ):
        self.last_fid = smb.SMB.nt_create_andx(self, tid, filename, smb_packet, cmd, shareAccessMode, disposition, accessMask)
        return self.last_fid

    def next_mid(self):
        """Return the next multiplex ID."""
        self.last_mid += random.randint(1, 20)
        if 0x4000 <= self.last_mid <= 0x4110:
            self.last_mid += 0x120
        return self.last_mid

    def send_echo(self, data: bytes) -> smb.NewSMBPacket:
        """Send an SMB echo and wait for the response."""
        pkt = smb.NewSMBPacket()
        pkt["Tid"] = self.default_tid

        echo_cmd = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
        echo_cmd["Parameters"] = smb.SMBEcho_Parameters()
        echo_cmd["Data"] = smb.SMBEcho_Data()
        echo_cmd["Parameters"]["EchoCount"] = 1
        echo_cmd["Data"]["Data"] = data
        pkt.addCommand(echo_cmd)

        self.sendSMB(pkt)
        return self.recvSMB()

    def setup_login_packet_hook(self, max_buffer_size):
        """Setup hook for next NewSMBPacket.addCommand if max_buffer_size is not None."""
        if max_buffer_size is None:
            return

        self.max_buffer_size = max_buffer_size

        def add_command_hook(self, command):
            """Set preferred MaxBufferSize."""
            smb.NewSMBPacket.addCommand = ORIGINAL_SMB_ADD_COMMAND

            if isinstance(command["Parameters"], smb.SMBSessionSetupAndX_Extended_Parameters):
                command["Parameters"]["MaxBufferSize"] = max_buffer_size

            elif isinstance(command["Parameters"], smb.SMBSessionSetupAndX_Parameters):
                command["Parameters"]["MaxBuffer"] = max_buffer_size

            ORIGINAL_SMB_ADD_COMMAND(self, command)

        smb.NewSMBPacket.addCommand = add_command_hook

    # To use any login method, SMB must not be used from multiple threads.
    def login(
        self,
        user,
        password,
        domain="",
        lmhash="",
        nthash="",
        ntlm_fallback=True,
        maxBufferSize=None,
    ):
        """Authenticate using the preferred SMB login method."""
        self.setup_login_packet_hook(maxBufferSize)
        smb.SMB.login(
            self,
            user,
            password,
            domain,
            lmhash,
            nthash,
            ntlm_fallback,
        )

    def login_standard(
        self,
        user,
        password,
        domain="",
        lmhash="",
        nthash="",
        maxBufferSize=None,
    ):
        """Authenticate using standard SMB authentication."""
        self.setup_login_packet_hook(maxBufferSize)
        return smb.SMB.login_standard(
            self,
            user,
            password,
            domain,
            lmhash,
            nthash,
        )

    def login_extended(
        self,
        user,
        password,
        domain="",
        lmhash="",
        nthash="",
        use_ntlmv2=True,
        maxBufferSize=None,
    ):
        """Authenticate using extended SMB authentication."""
        self.setup_login_packet_hook(maxBufferSize)
        smb.SMB.login_extended(
            self,
            user,
            password,
            domain,
            lmhash,
            nthash,
            use_ntlmv2,
        )

    @property
    def signing_enabled(self):
        """Return whether SMB signing is enabled."""
        return self._SignatureEnabled

    @property
    def signing_session_key(self):
        """Return the SMB signing session key."""
        return self._SigningSessionKey

    @property
    def signing_challenge_response(self):
        """Return the SMB signing challenge response."""
        return self._SigningChallengeResponse

    def recv_transaction_data(self, mid, min_length):
        """Receive SMB transaction response data."""
        data = b""
        while len(data) < min_length:
            recv_pkt = self.recvSMB()
            if recv_pkt["Mid"] != mid:
                continue

            resp = smb.SMBCommand(recv_pkt["Data"][0])
            data += resp["Data"][1:]  # skip padding

        return data

    def smb_defaults_impacket(self, packet):
        """Set default SMB1 packet header values for impacket."""

        packet["Mid"] = self.last_mid
        packet["Tid"] = self.last_tid
        packet["Uid"] = self.get_uid()
        packet["Pid"] = self.pid

    def smb_defaults(self, packet):
        """Set default SMB1 packet header values."""

        packet["MultiplexID"] = self.last_mid
        packet["TreeID"] = self.last_tid
        packet["UserID"] = self.get_uid()
        packet["ProcessID"] = self.pid

    def get_pipes_on_host(self, ctx, tree_id):
        """Scan for available pipes on the host and return the ones that connected successfully."""
        named_pipes = ctx.datastore["NAMED_PIPES"]

        if not ctx.datastore["PIPE_NAME"]:
            try:
                with open(named_pipes, encoding="utf-8", errors="ignore") as file:
                    pipes = [pipe.strip() for pipe in file if pipe.strip()]

            except OSError as exc:
                ctx.error(f"Could not open {named_pipes}: {exc}")
                return []

            if not pipes:
                ctx.error(f"No named pipes found in {named_pipes}")
                return []

            ctx.info("Fetching available named pipes...")

            found_pipes = []
            for pipe in pipes:
                pipe_path = pipe if pipe.startswith("\\") else f"\\{pipe}"
                fid = None

                with contextlib.suppress(Exception):
                    fid = self.nt_create_andx(tree_id, pipe_path, accessMask=0x00020089)
                    ctx.debug(f"{ctx.get_option('RHOST')} - connected to pipe: {pipe_path}")
                    found_pipes.append(pipe_path)

                if fid is not None:
                    with contextlib.suppress(Exception):
                        self.close(tree_id, fid)

            return found_pipes

        path = ctx.datastore["PIPE_NAME"]
        with contextlib.suppress(Exception):
            fid = self.nt_create_andx(tree_id, path, accessMask=0x00020089)
            ctx.success(f"{ctx.get_option('RHOST')} - connected to pipe: {path}")
            return [path]

        return []

    def neg_session(self, extended_security=True, negPacket=None):
        """Override SMB.neg_session() to allow forcing ntlm authentication."""
        return smb.SMB.neg_session(
            self,
            extended_security=self._use_ntlmv2,
            negPacket=negPacket,
        )

    def get_nt_status(self, smb_recv):
        """Get the SMB1 error code from the response."""
        return (smb_recv["ErrorCode"] << 16) | (smb_recv["_reserved"] << 8) | smb_recv["ErrorClass"]

    def send_raw(self, data):
        """Send raw data through the connection socket."""
        self.get_socket().sendall(data)

    @staticmethod
    def dcerpc_getarch(target_ip, timeout=5):
        """Detect target OS architecture (x86 vs x64) via DCERPC bind."""
        string_binding = f"ncacn_ip_tcp:{target_ip}[135]"

        transport = DCERPCTransportFactory(string_binding)
        transport.set_connect_timeout(int(timeout))

        # NDR64 Transfer Syntax UUID; a bind success/failure here signals arch.
        ndr64_syntax = ("71710533-BEBA-4937-8319-B5DBEF9CCC36", "1.0")

        try:
            dce = transport.get_dce_rpc()
            dce.connect()

            try:
                dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=ndr64_syntax)

            except DCERPCException as e:
                if "syntaxes_not_supported" in str(e):
                    return "x86 (32-bit)"
                return f"RPC Bind Error: {e}"

            else:
                return "x64 (64-bit)"

            finally:
                dce.disconnect()

        except DCERPCException as e:
            return f"Connection Failed: {e}"

    def put_trans_data(self, trans, param=b"", data=b"", no_pad=False):
        """Set SMB transaction parameter and data offsets."""

        trans["Parameters"]["ParameterOffset"] = 0
        trans["Parameters"]["DataOffset"] = 0

        # SMB header: 32 bytes
        # WordCount: 1 bytes
        # ByteCount: 2 bytes
        # Note: Setup length is included when len(param) is called
        offset = 32 + 1 + len(trans["Parameters"]) + 2

        trans_data = b""
        if param:
            pad_len = 0 if no_pad else (4 - offset % 4) % 4
            trans["Parameters"]["ParameterOffset"] = offset + pad_len
            trans_data += (b"\x00" * pad_len) + param
            offset += pad_len + len(param)

        if data:
            pad_len = 0 if no_pad else (4 - offset % 4) % 4
            trans["Parameters"]["DataOffset"] = offset + pad_len
            trans_data += (b"\x00" * pad_len) + data

        trans["Data"] = trans_data
        return trans

    def create_trans_packet(
        self,
        setup=b"",
        param=b"",
        data=b"",
        mid=None,
        max_setup_count=None,
        total_parameter_count=None,
        total_data_count=None,
        max_parameter_count=None,
        max_data_count=None,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Build an SMB_COM_TRANSACTION request packet with the given setup/parameter/data payload."""
        if max_setup_count is None:
            max_setup_count = len(setup)
        if total_parameter_count is None:
            total_parameter_count = len(param)
        if total_data_count is None:
            total_data_count = len(data)
        if max_parameter_count is None:
            max_parameter_count = total_parameter_count
        if max_data_count is None:
            max_data_count = total_data_count

        trans_cmd = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION)

        trans_cmd["Parameters"] = smb.SMBTransaction_Parameters()
        trans_cmd["Parameters"]["TotalParameterCount"] = total_parameter_count
        trans_cmd["Parameters"]["TotalDataCount"] = total_data_count
        trans_cmd["Parameters"]["MaxParameterCount"] = max_parameter_count
        trans_cmd["Parameters"]["MaxDataCount"] = max_data_count
        trans_cmd["Parameters"]["MaxSetupCount"] = max_setup_count
        trans_cmd["Parameters"]["Flags"] = 0
        trans_cmd["Parameters"]["Timeout"] = 0xFFFFFFFF
        trans_cmd["Parameters"]["ParameterCount"] = len(param)
        trans_cmd["Parameters"]["DataCount"] = len(data)
        trans_cmd["Parameters"]["Setup"] = setup

        self.put_trans_data(trans_cmd, param, data, no_pad)
        return self.create_smb_packet(trans_cmd, mid, pid, tid)

    def send_transaction(
        self,
        setup,
        param=b"",
        data=b"",
        mid=None,
        max_setup_count=None,
        total_parameter_count=None,
        total_data_count=None,
        max_parameter_count=None,
        max_data_count=None,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Send an SMB_COM_TRANSACTION request and return the server's response."""
        self.send_raw(
            self.create_trans_packet(
                setup,
                param,
                data,
                mid,
                max_setup_count,
                total_parameter_count,
                total_data_count,
                max_parameter_count,
                max_data_count,
                pid,
                tid,
                no_pad,
            )
        )
        return self.recvSMB()

    def create_trans_secondary_packet(
        self,
        mid,
        param=b"",
        data=b"",
        param_displacement=0,
        data_displacement=0,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Build an SMB_COM_TRANSACTION_SECONDARY packet to continue a multi-part transaction."""
        trans_cmd = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION_SECONDARY)

        trans_cmd["Parameters"] = transaction.SMBTransactionSecondaryParameters()
        trans_cmd["Parameters"]["TotalParameterCount"] = len(param)
        trans_cmd["Parameters"]["TotalDataCount"] = len(data)
        trans_cmd["Parameters"]["ParameterCount"] = len(param)
        trans_cmd["Parameters"]["ParameterDisplacement"] = param_displacement
        trans_cmd["Parameters"]["DataCount"] = len(data)
        trans_cmd["Parameters"]["DataDisplacement"] = data_displacement

        self.put_trans_data(trans_cmd, param, data, no_pad)
        return self.create_smb_packet(trans_cmd, mid, pid, tid)

    def send_transaction_secondary(
        self,
        mid,
        param=b"",
        data=b"",
        param_displacement=0,
        data_displacement=0,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Send an SMB_COM_TRANSACTION_SECONDARY packet (no response expected)."""
        self.send_raw(
            self.create_trans_secondary_packet(
                mid,
                param,
                data,
                param_displacement,
                data_displacement,
                pid,
                tid,
                no_pad,
            )
        )

    def create_trans2_packet(
        self,
        setup,
        param=b"",
        data=b"",
        mid=None,
        max_setup_count=None,
        total_parameter_count=None,
        total_data_count=None,
        max_parameter_count=None,
        max_data_count=None,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Build an SMB_COM_TRANSACTION2 request packet with the given setup/parameter/data payload."""
        if total_parameter_count is None:
            total_parameter_count = len(param)
        if total_data_count is None:
            total_data_count = len(data)
        if max_parameter_count is None:
            max_parameter_count = total_parameter_count
        if max_data_count is None:
            max_data_count = total_data_count

        trans_cmd = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2)

        trans_cmd["Parameters"] = smb.SMBTransaction2_Parameters()
        trans_cmd["Parameters"]["TotalParameterCount"] = total_parameter_count
        trans_cmd["Parameters"]["TotalDataCount"] = total_data_count
        trans_cmd["Parameters"]["MaxParameterCount"] = max_parameter_count
        trans_cmd["Parameters"]["MaxDataCount"] = max_data_count
        trans_cmd["Parameters"]["MaxSetupCount"] = len(setup) if max_setup_count is None else max_setup_count
        trans_cmd["Parameters"]["Flags"] = 0
        trans_cmd["Parameters"]["Timeout"] = 0xFFFFFFFF
        trans_cmd["Parameters"]["ParameterCount"] = len(param)
        trans_cmd["Parameters"]["DataCount"] = len(data)
        trans_cmd["Parameters"]["Setup"] = setup

        self.put_trans_data(trans_cmd, param, data, no_pad)
        return self.create_smb_packet(trans_cmd, mid, pid, tid)

    def send_transaction2(
        self,
        setup,
        param=b"",
        data=b"",
        mid=None,
        max_setup_count=None,
        total_parameter_count=None,
        total_data_count=None,
        max_parameter_count=None,
        max_data_count=None,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Send an SMB_COM_TRANSACTION2 request and return the server's response."""
        self.send_raw(
            self.create_trans2_packet(
                setup,
                param,
                data,
                mid,
                max_setup_count,
                total_parameter_count,
                total_data_count,
                max_parameter_count,
                max_data_count,
                pid,
                tid,
                no_pad,
            )
        )
        return self.recvSMB()

    def create_trans2_secondary_packet(
        self,
        mid,
        param=b"",
        data=b"",
        param_displacement=0,
        data_displacement=0,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Build an SMB_COM_TRANSACTION2_SECONDARY packet to continue a multi-part TRANS2 transaction."""
        trans_cmd = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2_SECONDARY)

        trans_cmd["Parameters"] = transaction.SMBTransaction2SecondaryParameters()
        trans_cmd["Parameters"]["TotalParameterCount"] = len(param)
        trans_cmd["Parameters"]["TotalDataCount"] = len(data)
        trans_cmd["Parameters"]["ParameterCount"] = len(param)
        trans_cmd["Parameters"]["ParameterDisplacement"] = param_displacement
        trans_cmd["Parameters"]["DataCount"] = len(data)
        trans_cmd["Parameters"]["DataDisplacement"] = data_displacement

        self.put_trans_data(trans_cmd, param, data, no_pad)
        return self.create_smb_packet(trans_cmd, mid, pid, tid)

    def send_transaction2_secondary(
        self,
        mid,
        param=b"",
        data=b"",
        param_displacement=0,
        data_displacement=0,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Send an SMB_COM_TRANSACTION2_SECONDARY packet (no response expected)."""
        self.send_raw(
            self.create_trans2_secondary_packet(
                mid,
                param,
                data,
                param_displacement,
                data_displacement,
                pid,
                tid,
                no_pad,
            )
        )

    def create_nt_trans_packet(
        self,
        function,
        setup=b"",
        param=b"",
        data=b"",
        mid=None,
        max_setup_count=None,
        total_parameter_count=None,
        total_data_count=None,
        max_parameter_count=None,
        max_data_count=None,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Build an SMB_COM_NT_TRANSACT request packet for the given NT transact function."""
        if max_setup_count is None:
            max_setup_count = len(setup)
        if total_parameter_count is None:
            total_parameter_count = len(param)
        if total_data_count is None:
            total_data_count = len(data)
        if max_parameter_count is None:
            max_parameter_count = total_parameter_count
        if max_data_count is None:
            max_data_count = total_data_count

        trans_cmd = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT)

        trans_cmd["Parameters"] = smb.SMBNTTransaction_Parameters()
        trans_cmd["Parameters"]["MaxSetupCount"] = max_setup_count
        trans_cmd["Parameters"]["TotalParameterCount"] = total_parameter_count
        trans_cmd["Parameters"]["TotalDataCount"] = total_data_count
        trans_cmd["Parameters"]["MaxParameterCount"] = max_parameter_count
        trans_cmd["Parameters"]["MaxDataCount"] = max_data_count
        trans_cmd["Parameters"]["ParameterCount"] = len(param)
        trans_cmd["Parameters"]["DataCount"] = len(data)
        trans_cmd["Parameters"]["Function"] = function
        trans_cmd["Parameters"]["Setup"] = setup

        self.put_trans_data(trans_cmd, param, data, no_pad)
        return self.create_smb_packet(trans_cmd, mid, pid, tid)

    def send_nt_transaction(
        self,
        function,
        setup=b"",
        param=b"",
        data=b"",
        mid=None,
        max_setup_count=None,
        total_parameter_count=None,
        total_data_count=None,
        max_parameter_count=None,
        max_data_count=None,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Send an SMB_COM_NT_TRANSACT request and return the server's response."""
        self.send_raw(
            self.create_nt_trans_packet(
                function,
                setup,
                param,
                data,
                mid,
                max_setup_count,
                total_parameter_count,
                total_data_count,
                max_parameter_count,
                max_data_count,
                pid,
                tid,
                no_pad,
            )
        )
        return self.recvSMB()

    def create_nt_trans_secondary_packet(
        self,
        mid,
        param=b"",
        data=b"",
        param_displacement=0,
        data_displacement=0,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Build an SMB_COM_NT_TRANSACT_SECONDARY packet to continue a multi-part NT transaction."""
        trans_cmd = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT_SECONDARY)

        trans_cmd["Parameters"] = transaction.SMBNTTransactionSecondaryParameters()
        trans_cmd["Parameters"]["TotalParameterCount"] = len(param)
        trans_cmd["Parameters"]["TotalDataCount"] = len(data)
        trans_cmd["Parameters"]["ParameterCount"] = len(param)
        trans_cmd["Parameters"]["ParameterDisplacement"] = param_displacement
        trans_cmd["Parameters"]["DataCount"] = len(data)
        trans_cmd["Parameters"]["DataDisplacement"] = data_displacement

        self.put_trans_data(trans_cmd, param, data, no_pad)
        return self.create_smb_packet(trans_cmd, mid, pid, tid)

    def send_nt_transaction_secondary(
        self,
        mid,
        param=b"",
        data=b"",
        param_displacement=0,
        data_displacement=0,
        pid=None,
        tid=None,
        no_pad=False,
    ):
        """Send an SMB_COM_NT_TRANSACT_SECONDARY packet (no response expected)."""
        self.send_raw(
            self.create_nt_trans_secondary_packet(
                mid,
                param,
                data,
                param_displacement,
                data_displacement,
                pid,
                tid,
                no_pad,
            )
        )
        return self.recvSMB()
