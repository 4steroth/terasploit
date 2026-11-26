from pathlib import Path

from terasploit.metadata import VERSION
from terasploit.ui.printf import print_line


CATEGORIES = ("exploit", "auxiliary", "payload", "encoder", "post")


def count_artifacts(directory="session", ext="*.json") -> int:
    """Count stored artifacts from a specified directory."""
    session_dir = Path(__file__).resolve().parents[2] / "data" / directory
    if not session_dir.is_dir():
        return 0
    return sum(1 for f in session_dir.rglob(ext) if f.is_file())


def display_banner(module_list, silent=False):
    """Print the ASCII banner and per-category module counts."""
    if silent:
        return

    counts = {cat: 0 for cat in CATEGORIES}
    for name in module_list:
        category = next((cat for cat in CATEGORIES if name == cat or name.startswith(f"{cat}.")), None)
        if category is not None:
            counts[category] += 1

    modules = (
        f"{counts['exploit']} exploit · {counts['auxiliary']} auxiliary · {counts['payload']} payload · ",
        f"{counts['encoder']} encoder · {counts['post']} post",
    )

    print_line(
        "",
        "   __                                 __         __ __",
        "  |  |_.-----.----.---.-.-----.-----.|  |.-----.|__|  |_",
        "  |   _|  -__|   _|  _  |__ --|  _  ||  ||  _  ||  |   _|",
        "  |____|_____|__| |___._|_____|   __||__||_____||__|____|",
        "                              |__|",
        "\n",
        "  Exploitation Framework for Red Team Operations",
        "  ──────────────────────────────────────────────",
        "",
        f"  Version   {VERSION}",
        f"  Modules   {''.join(modules)}",
        "",
        f"  Session opened: {count_artifacts(directory='session', ext='*.json')}",
        f"  Looted session artifacts: {count_artifacts(directory='loot', ext='*')}",
        "\n",
        sep="\n",
    )
