"""Bounded reuse of public evidence pages; never stores assessment answers."""

from collections import OrderedDict
from concurrent.futures import Future
import threading


class PublicPages:
    """One builder per key, shared immutable HTML, fixed entry and byte limits."""

    def __init__(self, max_entries=16, max_bytes=2 * 1024 * 1024):
        self.max_entries, self.max_bytes = max_entries, max_bytes
        self._pages = OrderedDict()
        self._pending = {}
        self._bytes = 0
        self._lock = threading.Lock()

    def get(self, key, build):
        with self._lock:
            if key in self._pages:
                value, size = self._pages.pop(key)
                self._pages[key] = value, size
                return value
            pending = self._pending.get(key)
            owner = pending is None
            if owner:
                pending = self._pending[key] = Future()
        if not owner:
            return pending.result()
        try:
            value = build()
            size = len(value.encode("utf-8"))
            with self._lock:
                if size <= self.max_bytes and self.max_entries > 0:
                    while self._pages and (
                            len(self._pages) >= self.max_entries
                            or self._bytes + size > self.max_bytes):
                        _, (_, removed) = self._pages.popitem(last=False)
                        self._bytes -= removed
                    self._pages[key] = value, size
                    self._bytes += size
            pending.set_result(value)
            return value
        except BaseException as error:
            pending.set_exception(error)
            raise
        finally:
            with self._lock:
                del self._pending[key]
