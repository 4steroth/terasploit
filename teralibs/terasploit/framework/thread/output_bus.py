import threading
import time


class OutputBus:
    """
    Thread-safe single-producer / single-consumer event buffer.

    Any number of worker threads may call :meth:emit concurrently.
    The console thread calls :meth:drain from its main loop.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._events = []

    def emit(self, job_id, level, message):
        """Append one log event to the buffer."""
        event = {
            "ts": time.time(),
            "job_id": job_id,
            "level": level,
            "message": message,
        }
        with self._lock:
            self._events.append(event)

    def drain(self):
        """Atomically retrieve and clear all buffered events."""
        with self._lock:
            events = list(self._events)
            self._events = []
        return events

    def pending(self):
        """Return the number of events currently waiting in the buffer."""
        with self._lock:
            return len(self._events)
