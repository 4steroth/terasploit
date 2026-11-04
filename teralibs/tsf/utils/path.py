import contextlib
import importlib.util
import os
import threading
from pathlib import Path


class ModuleIndex:
    """Lazily-refreshed directory scan that maps dotted names to file paths."""

    def __init__(self, base_dir=None):

        # Derive the project root from this file's location so the framework
        # works when launched via symlink, `python -m`, or from any cwd.
        # path.py lives at teralibs/tsf/utils/path.py - three parents up = project root.
        _here = os.path.dirname(os.path.abspath(__file__))
        _project_root = os.path.dirname(os.path.dirname(os.path.dirname(_here)))

        self.base_dir = base_dir or os.path.join(_project_root, "modules")
        self._modules = {}
        self._mtime = 0.0
        self._load_cache = {}  # dotted name -> loaded module
        self._load_cache_lock = threading.Lock()
        self._warm_thread = None  # background pre-load thread
        self.refresh(force=True)
        self._warm_cache()

    # Scanning

    def _scan(self):
        """Walk base_dir recursively and build a name -> path dict."""
        result = {}
        base = Path(self.base_dir)

        if not base.exists():
            return result

        for filepath in base.rglob("*.py"):
            if filepath.name == "__init__.py":
                continue
            relative = filepath.relative_to(base).with_suffix("")
            name = ".".join(relative.parts)
            # Stage modules are excluded from the index intentionally.
            # They are not user-selectable via "use" or "show payloads";
            # instead they are loaded on-demand by StageAssembler when
            # a stager establishes a connection and requests its stage.
            if "payload.stages." in name:
                continue
            result[name] = str(filepath)

        return result

    def _max_mtime(self):
        """Return the latest mtime across the base dir and all subdirectories."""
        latest = 0.0
        try:
            for dirpath, _, _ in os.walk(self.base_dir):
                with contextlib.suppress(OSError):
                    latest = max(latest, os.path.getmtime(dirpath))
        except OSError:
            pass
        return latest

    def refresh(self, force=False):
        """Rebuild the index if any subdirectory under base_dir has been modified."""
        mtime = self._max_mtime()

        if force or mtime != self._mtime:
            self._modules = self._scan()
            self._mtime = mtime
            # Evict cache entries for modules that no longer exist.
            with self._load_cache_lock:
                for name in list(self._load_cache):
                    if name not in self._modules:
                        self._load_cache.pop(name, None)

    # Public interface

    def list(self):
        """Return a sorted list of all known dotted module names."""
        self.refresh()
        return sorted(self._modules.keys())

    def search(self, query, fuzzy=False):
        """Search module names for *query* and return matching names."""
        self.refresh()

        q = query.lower()
        words = q.split()
        found = []

        for name in self._modules:
            lower = name.lower()

            matched = all(word in lower for word in words) if fuzzy else q in lower

            if matched:
                found.append(name)

        return sorted(found)

    def get_path(self, name):
        """Return the absolute file path for *name*, or None if not indexed."""
        self.refresh()
        return self._modules.get(name)

    def load(self, name):
        """Dynamically import and return the Python module object for *name*."""
        with self._load_cache_lock:
            if name in self._load_cache:
                return self._load_cache[name]

        path = self.get_path(name)
        if path is None:
            return None

        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            return None

        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        with self._load_cache_lock:
            self._load_cache[name] = mod
        return mod

    def _warm_cache(self):
        """Pre-load all indexed modules into the cache in a background thread."""
        if not self._modules:
            return

        names = list(self._modules.keys())

        def _worker():
            for name in names:
                self.load(name)

        self._warm_thread = threading.Thread(
            target=_worker,
            name="tsf-module-cache-warm",
            daemon=True,
        )
        self._warm_thread.start()

    def __len__(self):
        """Return the total number of indexed modules."""
        return len(self._modules)

    def __contains__(self, name):
        """Support membership tests: "exploit.multi.handler" in index."""
        return name in self._modules
