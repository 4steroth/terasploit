from teralibs.terasploit.framework.services.printf import print_line
from teralibs.terasploit.metadata import VERSION


# Module category
CATEGORIES = ("exploit", "auxiliary", "payload", "encoder", "post", "nop")

# Terasploit ASCII banner
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
    """Print the ASCII banner, legal disclaimer, and per-category module counts."""
    if silent:
        return

    counts = {cat: 0 for cat in CATEGORIES}

    for name in module_list:
        for cat in CATEGORIES:
            if name == cat or name.startswith(f"{cat}."):
                counts[cat] += 1
                break

    print_line(BANNER)
    print_line(
        " ",
        f"{counts['exploit']} Exploit - {counts['auxiliary']} Auxiliary - {counts['payload']} Payload",
    )
    print_line(" ", f"{counts['encoder']} Encoder - {counts['post']} Post - {counts['nop']} Nop\n\n")
