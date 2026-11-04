import random
from typing import ClassVar


class UserAgent:
    """Provides user agents for HTTP requests."""

    # Common agents list.
    COMMON_AGENTS: ClassVar = [
        # Chrome Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        # Chrome MacOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        # Edge Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.2903.86",
        # Safari iPad
        "Mozilla/5.0 (iPad; CPU OS 17_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
        # Safari MacOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        # Firefox Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        # Firefox MacOS
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:133.0) Gecko/20100101 Firefox/133.0",
    ]

    _session_agent = None
    _shortest_agent = None

    @classmethod
    def session_agent(cls):
        """
        Returns a randomly-selected agent that remains consistent
        for the duration of the program running.
        """
        if cls._session_agent is None:
            cls._session_agent = cls.random()
        return cls._session_agent

    @classmethod
    def random(cls):
        """Picks a random agent from the common agent list."""
        return random.choice(cls.COMMON_AGENTS)

    @classmethod
    def shortest(cls):
        """Chooses the agent with the shortest string (for use in payloads)."""
        if cls._shortest_agent is None:
            # Python's min() with a key argument replaces the Ruby block comparison
            cls._shortest_agent = min(cls.COMMON_AGENTS, key=len)
        return cls._shortest_agent

    @classmethod
    def most_common(cls):
        """Chooses the most frequent user agent."""
        return cls.COMMON_AGENTS[0]
