from terasploit.metadata import VERSION
from terasploit.ui.printf import print_line


CATEGORIES = ("exploit", "auxiliary", "payload", "encoder", "post")
BANNER = f"""
   __                                 __         __ __
  |  |_.-----.----.---.-.-----.-----.|  |.-----.|__|  |_
  |   _|  -__|   _|  _  |__ --|  _  ||  ||  _  ||  |   _|
  |____|_____|__| |___._|_____|   __||__||_____||__|____|
                              |__|

  Exploitation Framework for Cross-Platform Red Team Operations
  Version: {VERSION}
"""


def display_banner(module_list, silent=False):
    """Print the ASCII banner and per-category module counts."""
    if silent:
        return

    counts = {cat: 0 for cat in CATEGORIES}
    for name in module_list:
        category = next((cat for cat in CATEGORIES if name == cat or name.startswith(f"{cat}.")), None)
        if category is not None:
            counts[category] += 1

    print_line(BANNER)
    print_line(
        " ",
        f"{counts['exploit']} exploit - {counts['auxiliary']} auxiliary - {counts['payload']} payload -",
        f"{counts['encoder']} encoder - {counts['post']} post\n\n",
    )
