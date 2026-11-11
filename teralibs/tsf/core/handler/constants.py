from teralibs.tsf.core.handler import bind_tcp, find_shell, reverse_tcp


#: Handler type reverse tcp.
HANDLER_REVERSE = "reverse"

#: Handler type bind tcp.
HANDLER_BIND = "bind"

#: Handler type find shell.
HANDLER_FIND = "find"


class Handler:
    """Namespace of handler classes for use in payload modules."""

    #: Reverse TCP — target connects back to the framework listener.
    ReverseTCP = reverse_tcp.ReverseTcpHandler

    #: Bind TCP — framework connects out to a listener on the target.
    BindTCP = bind_tcp.BindTcpHandler

    #: Find Shell — exploit produces the socket; framework only verifies it.
    FindShell = find_shell.FindShellHandler

    def __new__(cls):
        raise TypeError(
            f"{cls.__name__} is a namespace and cannot be instantiated. Use Handler.ReverseTCP, Handler.BindTCP, or Handler.FindShell directly."
        )
