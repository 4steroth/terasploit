import random

from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory


class Client:
    """PEX's SMB client."""

    def __init__(self, tree_id, user_id):
        self.multiplex_id = random.randint(0, 0xFFFF)
        self.process_id = random.randint(0, 0xFFFF)
        self.tree_id = tree_id
        self.user_id = user_id

    def smb_defaults(self, packet):
        """Set the defaults in SMB parameters."""
        packet["Payload"]["SMB"]["MultiplexID"] = self.multiplex_id
        packet["Payload"]["SMB"]["TreeID"] = self.tree_id
        packet["Payload"]["SMB"]["UserID"] = self.user_id
        packet["Payload"]["SMB"]["ProcessID"] = self.process_id

    @staticmethod
    def dcerpc_getarch(target_ip, timeout=5):
        """Get OS architecture with dcerpc."""
        string_binding = f"ncacn_ip_tcp:{target_ip}[135]"

        # Use the factory class to correctly handle string binding setup
        transport = DCERPCTransportFactory(string_binding)
        transport.set_connect_timeout(int(timeout))

        # Define the standard NDR64 Transfer Syntax UUID
        ndr64_syntax = ("71710533-BEBA-4937-8319-B5DBEF9CCC36", "1.0")

        try:
            dce = transport.get_dce_rpc()
            dce.connect()

            try:
                # Attempting to bind using NDR64 determines if it's 64-bit
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
