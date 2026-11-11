import contextlib
import random
from dataclasses import dataclass

from impacket import smb, smb3
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory


SMBSession = smb.SMB | smb3.SMB3


@dataclass
class SMBConnectConfig:
    """Connection parameters and credentials for an SMB session."""

    port: int = 445
    timeout: int = 60
    username: str = ""
    password: str = ""
    domain: str = ""
    ntlm_hash: str = ""


class SMBClient:
    """SMB client."""

    def __init__(self, tree_id, user_id):
        self.multiplex_id = random.randint(0, 0xFFFF)
        self.process_id = random.randint(0, 0xFFFF)
        self.tree_id = tree_id
        self.user_id = user_id

    def smb_defaults(self, packet):
        """Set defaults in packet's SMB header fields."""
        packet["Payload"]["SMB"]["MultiplexID"] = self.multiplex_id
        packet["Payload"]["SMB"]["TreeID"] = self.tree_id
        packet["Payload"]["SMB"]["UserID"] = self.user_id
        packet["Payload"]["SMB"]["ProcessID"] = self.process_id

    def _apply_login(self, conn: SMBSession, config: SMBConnectConfig) -> None:
        """Authenticate an open SMB connection using password or NTLM hash."""
        if config.ntlm_hash:
            lm, nt = config.ntlm_hash.split(":", 1) if ":" in config.ntlm_hash else ("", config.ntlm_hash)
            conn.login(config.username, "", config.domain, lm, nt)
        else:
            conn.login(config.username, config.password, config.domain)

    def _smb1_connect(self, target: str, config: SMBConnectConfig) -> smb.SMB:
        """Open and authenticate a raw SMB1 session."""
        conn = smb.SMB(target, target, sess_port=config.port, timeout=config.timeout)
        self._apply_login(conn, config)
        return conn

    def _smb3_connect(self, target: str, dialect, config: SMBConnectConfig) -> smb3.SMB3:
        """Open and authenticate a raw SMB2/3 session."""
        conn = smb3.SMB3(target, target, sess_port=config.port, timeout=config.timeout, preferredDialect=dialect)
        self._apply_login(conn, config)
        return conn

    def connect(self, target: str, config: SMBConnectConfig) -> SMBSession:
        """Connect with auto-negotiated dialect; prefers SMB2/3, falls back to SMB1."""
        with contextlib.suppress(Exception):
            return self._smb3_connect(target, None, config)

        return self._smb1_connect(target, config)

    def connect_smb1(self, target: str, config: SMBConnectConfig) -> smb.SMB:
        """Connect forcing SMB1 (CIFS) dialect."""
        return self._smb1_connect(target, config)

    def connect_smb2(self, target: str, config: SMBConnectConfig) -> smb3.SMB3:
        """Connect forcing SMB 2.0.2 dialect."""
        return self._smb3_connect(target, smb3.SMB2_DIALECT_002, config)

    def connect_smb21(self, target: str, config: SMBConnectConfig) -> smb3.SMB3:
        """Connect forcing SMB 2.1 dialect."""
        return self._smb3_connect(target, smb3.SMB2_DIALECT_21, config)

    def connect_smb3(self, target: str, config: SMBConnectConfig) -> smb3.SMB3:
        """Connect forcing SMB 3.0 dialect."""
        return self._smb3_connect(target, smb3.SMB2_DIALECT_30, config)

    def connect_smb302(self, target: str, config: SMBConnectConfig) -> smb3.SMB3:
        """Connect forcing SMB 3.0.2 dialect."""
        return self._smb3_connect(target, smb3.SMB2_DIALECT_302, config)

    def connect_smb311(self, target: str, config: SMBConnectConfig) -> smb3.SMB3:
        """Connect forcing SMB 3.1.1 dialect."""
        return self._smb3_connect(target, smb3.SMB2_DIALECT_311, config)

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
