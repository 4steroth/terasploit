import base64
import textwrap
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from teralibs.tsf.core.elf.builder import Elf
from teralibs.tsf.core.exe.builder import Exe


INDENT: Final[str] = " " * 4


def _escaped(data: bytes) -> str:
    """Convert bytes into a hexadecimal escaped string."""
    return "".join(f"\\x{byte:02x}" for byte in data)


def _wrap_values(values: str, width: int = 76, indent: str = "") -> str:
    """Wrap formatted values into consistently indented lines."""
    return textwrap.fill(values, width=width, initial_indent=indent, subsequent_indent=indent)


def fmt_raw(data: bytes, _arch: str = "") -> bytes:
    """Return the original binary data."""
    return data


def fmt_hex(data: bytes, _arch: str = "") -> bytes:
    """Return a spaced hexadecimal dump with 16 bytes per line."""
    hex_data = data.hex()
    rows = [hex_data[index : index + 32] for index in range(0, len(hex_data), 32)]

    output = "\n".join(" ".join(row[index : index + 2] for index in range(0, len(row), 2)) for row in rows)
    return output.encode()


def fmt_hexdump(data: bytes, _arch: str = "") -> bytes:
    """Return an annotated hexadecimal and ASCII dump."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]

        hex_column = " ".join(f"{byte:02x}" for byte in chunk).ljust(47)
        ascii_column = "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in chunk)
        lines.append(f"{offset:08x}  {hex_column}  |{ascii_column}|")

    return "\n".join(lines).encode()


def fmt_num(data: bytes, _arch: str = "") -> bytes:
    """Return comma-separated decimal byte values."""
    return ", ".join(map(str, data)).encode()


def fmt_hex_escape(data: bytes, _arch: str = "") -> bytes:
    r"""Return a hexadecimal escaped string (e.g. \xfc\x48)."""
    return _escaped(data).encode()


def fmt_base64(data: bytes, _arch: str = "") -> bytes:
    """Return standard Base64 encoded data."""
    return base64.b64encode(data)


def fmt_c(data: bytes, _arch: str = "") -> bytes:
    """Return a C unsigned char array."""
    values = ", ".join(f"0x{byte:02x}" for byte in data)
    body = _wrap_values(values, indent=INDENT)

    output = f"unsigned char buf[] =\n{INDENT}{body};\nunsigned int buf_len = {len(data)};\n"
    return output.encode()


def fmt_c_string(data: bytes, _arch: str = "") -> bytes:
    """Return a C string literal."""
    return f'char buf[] = "{_escaped(data)}";\n'.encode()


def fmt_csharp(data: bytes, _arch: str = "") -> bytes:
    """Return a C# byte array."""
    values = ", ".join(f"0x{byte:02x}" for byte in data)
    body = _wrap_values(values, width=76, indent=INDENT)

    output = f"byte[] buf = new byte[{len(data)}] {{\n{body}\n}};"
    return output.encode()


def fmt_java(data: bytes, _arch: str = "") -> bytes:
    """Return a Java byte array literal."""
    values = ", ".join(f"(byte)0x{byte:02x}" for byte in data)

    lines = textwrap.wrap(values, width=72)
    java_indent = INDENT
    body = ("\n" + java_indent).join(lines)

    output = f"byte[] buf = {{\n{java_indent}{body}\n}};\n"
    return output.encode()


def fmt_delphi(data: bytes, _arch: str = "") -> bytes:
    """Return a Delphi / Pascal byte array."""
    values = ", ".join(f"${byte:02x}" for byte in data)
    body = _wrap_values(values, width=76, indent=INDENT[:3])

    output = f"var buf: Array[0..{len(data) - 1}] of Byte = (\n{body}\n);"
    return output.encode()


def fmt_python(data: bytes, _arch: str = "") -> bytes:
    """Return a Python bytes literal."""
    escaped = _escaped(data)

    chunks = textwrap.wrap(escaped, width=72)
    if len(chunks) <= 1:
        output = f'buf  = b"{escaped}"\n'
    else:
        lines = ('"\n' + INDENT + 'b"').join(chunks)

        output = f'buf  = (\n{INDENT}b"{lines}"\n)\n'

    output += f"buf_len = {len(data)}\n"
    return output.encode()


def fmt_python_list(data: bytes, _arch: str = "") -> bytes:
    """Return a Python list of hexadecimal integers."""
    values = ", ".join(f"0x{byte:02x}" for byte in data)
    body = _wrap_values(values, width=76, indent=INDENT)

    output = f"buf = [\n{body}\n]\n"
    return output.encode()


def fmt_ruby(data: bytes, _arch: str = "") -> bytes:
    """Return a Ruby string literal."""
    escaped = _escaped(data)
    chunks = textwrap.wrap(escaped, width=72)
    if len(chunks) <= 1:
        output = f'buf = "{escaped}"\n'
    else:
        parts = ('" \\\n' + INDENT + '"').join(chunks)
        output = f'buf = "{parts}"\n'

    return output.encode()


def fmt_perl(data: bytes, _arch: str = "") -> bytes:
    """Return a Perl string literal."""
    escaped = _escaped(data)
    chunks = [escaped[index : index + 60] for index in range(0, len(escaped), 60)]

    lines = ['my $buf = ""']
    lines.extend(f'{INDENT[1:]}. "{chunk}"' for chunk in chunks)
    lines[-1] += ";"

    return "\n".join(lines).encode()


def fmt_bash(data: bytes, _arch: str = "") -> bytes:
    """Return a Bash exported ANSI-C quoted byte string."""
    width = 76
    values = [f"\\x{byte:02x}" for byte in data]

    lines = []
    line = ""

    for value in values:
        if line and len(line) + len(value) > width:
            lines.append(line)
            line = value
        else:
            line += value

    if line:
        lines.append(line)

    body = "\\\n".join(f"$'{line}'" for line in lines)
    output = f"export buf=\\\n{body}\n"

    return output.encode()


def fmt_powershell(data: bytes, _arch: str = "") -> bytes:
    """Return a PowerShell byte array."""
    width = 76
    lines = []
    line = ""

    for byte in data:
        value = f"0x{byte:02x}"
        if line and len(line) + len(value) + 2 > width:
            lines.append(line + ",")
            line = value
        else:
            line = f"{line}, {value}" if line else value

    if line:
        lines.append(line)

    body = "\n".join(f"    {line}" for line in lines)
    output = f"[Byte[]] $buf = @(\n{body}\n)\n"

    return output.encode()


def fmt_asp(data: bytes, _arch: str = "") -> bytes:
    """Return a Classic ASP / VBScript array declaration."""
    width = 76
    lines = []
    line = ""

    for byte in data:
        value = str(byte)
        if line and len(line) + len(value) + 1 > width:
            lines.append(line + ",")
            line = value
        else:
            line = f"{line}, {value}" if line else value

    if line:
        lines.append(line)

    body = "\n".join(f"    {line}" for line in lines)
    output = f"Dim buf\nbuf = Array(\n{body}\n)\nDim size : size = {len(data)}"

    return output.encode()


def fmt_elf(data: bytes, arch: str = "x64") -> bytes:
    """Build a Linux ELF executable."""
    elf = Elf(arch)
    return elf.build(data)


def fmt_exe(data: bytes, arch: str = "x86") -> bytes:
    """Build a Windows PE executable."""
    exe = Exe(arch)
    return exe.build(data)


@dataclass(frozen=True, slots=True)
class Formatter:
    """Immutable definition of an output formatter."""

    name: str
    function: Callable[[bytes, str], bytes]
    output_type: str
    description: str
    aliases: tuple[str, ...] = ()


FORMATTERS: Final[tuple[Formatter, ...]] = (
    # Basic / Raw Formats
    Formatter("raw", fmt_raw, "binary", "Raw binary data"),
    Formatter("hex", fmt_hex, "text", "Spaced hexadecimal dump"),
    Formatter("hexdump", fmt_hexdump, "text", "Annotated hex + ASCII dump"),
    Formatter("num", fmt_num, "text", "Comma-separated decimal byte values"),
    Formatter("hex-escape", fmt_hex_escape, "text", r"\xNN escaped byte string"),
    Formatter("base64", fmt_base64, "text", "Standard Base64 encoded string"),
    # C / Native Languages
    Formatter("c", fmt_c, "text", "C unsigned char array"),
    Formatter("c-string", fmt_c_string, "text", "C string literal"),
    Formatter("csharp", fmt_csharp, "text", "C# byte array"),
    Formatter("java", fmt_java, "text", "Java byte array"),
    Formatter("delphi", fmt_delphi, "text", "Delphi / Pascal byte array"),
    # Scripting Languages
    Formatter("python", fmt_python, "text", "Python bytes literal", ("py",)),
    Formatter("python-list", fmt_python_list, "text", "Python integer list"),
    Formatter("ruby", fmt_ruby, "text", "Ruby string literal", ("rb",)),
    Formatter("perl", fmt_perl, "text", "Perl string literal", ("pl",)),
    Formatter("bash", fmt_bash, "text", r"Bash $'\xNN' variable", ("sh",)),
    Formatter("powershell", fmt_powershell, "text", "PowerShell Byte array", ("ps1",)),
    Formatter("asp", fmt_asp, "text", "Classic ASP / VBScript array"),
    # Executable Formats
    Formatter("elf", fmt_elf, "binary", "Linux ELF executable"),
    Formatter("exe", fmt_exe, "binary", "Windows PE executable"),
)
