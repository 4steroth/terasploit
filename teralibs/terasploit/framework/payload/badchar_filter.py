from teralibs.terasploit.framework.payload.badchars import BadCharFilter


def parse_badchars(args) -> frozenset:
    """Parse a BADCHARS string into a frozenset of byte integers."""
    return BadCharFilter.parse(args)
