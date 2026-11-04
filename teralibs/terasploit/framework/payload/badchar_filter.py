from teralibs.terasploit.framework.payload.badchars import BadCharFilter


def parse_badchars(args) -> frozenset:
    """
    Parse a BADCHARS string into a frozenset of byte integers.

    Accepts \\xNN escape notation, space-separated two-digit hex
    pairs, or any mixture of the two.
    """
    return BadCharFilter.parse(args)
