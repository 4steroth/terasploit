import argparse
import shutil
import sys

from teralibs.terasploit.framework.services.printf import error


class CompactHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """RawDescriptionHelpFormatter with terminal-aware column width."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_help_position", 50)
        kwargs.setdefault("width", shutil.get_terminal_size(fallback=(80, 24)).columns)
        super().__init__(*args, **kwargs)


class TeraxCLI:
    """CLI argument parsing and override handling for terax."""

    @staticmethod
    def build_parser():
        """Construct and return the terax CLI argument parser."""
        p = argparse.ArgumentParser(
            prog="terax",
            formatter_class=CompactHelpFormatter,
            add_help=True,
            color=False,
        )
        p.add_argument("-p", "--payload", default=None, help="payload path  (e.g. payload/stagers/windows/x86/reverse_tcp)")
        p.add_argument("-e", "--encoder", default=None, help="encoder to use  (e.g. encoder/x86/shikata_ga_nai)")
        p.add_argument("-i", "--iterations", default=1, type=int, help="encoding iterations (default: 1)")
        p.add_argument("-b", "--bad-chars", default="", dest="bad_chars", help=r"bad chars in \xNN notation  (e.g. '\x00\x0a\x0d')")
        p.add_argument(
            "-n", "--nop-sled", default=0, type=int, dest="nop", help="prepend number of nop bytes to the payload (0x90 would be 144 bytes)"
        )
        p.add_argument("-s", "--space", default=0, type=int, help="maximum payload size in bytes  (0 = unlimited)")
        p.add_argument("-f", "--format", default="raw", help="output format  (default: raw, see -l formats)")
        p.add_argument("-o", "--out", default=None, help="output file  (default: stdout)")
        p.add_argument("--list-options", action="store_true", help="show payload options then exit  (requires -p)")
        p.add_argument(
            "-l",
            "--list",
            default=None,
            dest="list_type",
            choices=["payloads", "encoders", "formats", "all"],
            help="list payloads, encoders, formats, all",
        )
        p.add_argument("-v", "--verbose", action="store_true", help="enable module level verbosity")
        p.add_argument("var_overrides", nargs="*", help="option overrides (e.g. LHOST=10.0.0.1)")
        return p

    @staticmethod
    def parse_overrides(tokens):
        """Parse VAR=value CLI tokens into an uppercase-keyed option dict."""
        out = {}
        for tok in tokens:
            if "=" not in tok:
                error(f"unrecognised argument (expected VAR=value): {tok!r}")
                sys.exit(1)

            k, _, v = tok.partition("=")
            out[k.strip().upper()] = v.strip()

        return out
