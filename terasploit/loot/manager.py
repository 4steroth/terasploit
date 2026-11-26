import hashlib
import io
import mimetypes
import os
import shutil
import uuid
from pathlib import Path, PurePosixPath

from terasploit.database.loot import LootDatabase


class LootManager:
    """Store, catalog, inspect, export, and remove collected artifacts."""

    def __init__(self, intelligence, root=None):
        self.intelligence = intelligence

        project_root = Path(__file__).resolve().parents[2]
        self.root = Path(root) if root else project_root / "data" / "loot"
        self.root.mkdir(parents=True, exist_ok=True)

        os.chmod(self.root, 0o700)
        self.database = LootDatabase(intelligence.database.path, intelligence.database)

    @property
    def workspace(self):
        """Return the currently selected workspace."""
        return self.intelligence.workspace

    @staticmethod
    def _filename(value):
        """Normalize an artifact name to a safe basename."""
        raw = str(value or "").replace("\\", "/")

        name = PurePosixPath(raw).name.strip()
        if name in {"", ".", ".."} or "\x00" in name:
            raise ValueError("A valid artifact filename is required.")
        return name

    def store_bytes(
        self,
        content,
        filename,
        *,
        host=None,
        session_id=None,
        module=None,
        source="module",
        content_type=None,
        description=None,
        platform=None,
        workspace=None,
    ):
        """Persist bytes as a workspace-scoped artifact and catalog its metadata."""
        if not isinstance(content, (bytes, bytearray, memoryview)):
            raise TypeError("Artifact content must be bytes-like.")

        return self._store_stream(
            io.BytesIO(bytes(content)),
            filename,
            host=host,
            session_id=session_id,
            module=module,
            source=source,
            content_type=content_type,
            description=description,
            platform=platform,
            workspace=workspace,
        )

    def store_file(
        self,
        source_path,
        *,
        filename=None,
        host=None,
        session_id=None,
        module=None,
        source="module",
        content_type=None,
        description=None,
        platform=None,
        workspace=None,
    ):
        """Copy a local file into managed storage and catalog its metadata."""
        path = Path(source_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"Artifact source file does not exist: {path}")

        with path.open("rb") as stream:
            return self._store_stream(
                stream,
                filename or path.name,
                host=host,
                session_id=session_id,
                module=module,
                source=source,
                content_type=content_type,
                description=description,
                platform=platform,
                workspace=workspace,
            )

    def _store_stream(
        self,
        stream,
        filename,
        *,
        host,
        session_id,
        module,
        source,
        content_type,
        description,
        platform,
        workspace,
    ):
        """Write an artifact atomically, calculate its digest, and register it."""
        name = self._filename(filename)

        workspace = str(workspace or self.workspace).strip() or "default"
        workspace_id = self.intelligence.database.ensure_workspace(workspace)

        directory = self.root / str(workspace_id)
        directory.mkdir(parents=True, exist_ok=True)

        os.chmod(directory, 0o700)

        token = uuid.uuid4().hex
        stored_name = f"{token}_{name}"

        destination = directory / stored_name
        temporary = directory / f".{token}.tmp"

        digest = hashlib.sha256()

        size = 0
        try:
            with temporary.open("xb") as output:
                while chunk := stream.read(1024 * 1024):
                    output.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)

            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)

            relative_path = destination.relative_to(self.root).as_posix()
            row = self.database.add(
                workspace=workspace,
                host=host,
                session_id=session_id,
                module=module,
                source=source,
                filename=name,
                relative_path=relative_path,
                content_type=content_type or mimetypes.guess_type(name)[0] or "application/octet-stream",
                size=size,
                sha256=digest.hexdigest(),
                description=description,
                platform=platform,
            )
            return row

        except Exception:
            temporary.unlink(missing_ok=True)
            destination.unlink(missing_ok=True)
            raise

    def get_all(self, *, host=None, session_id=None, workspace=None, limit=200):
        """List cataloged artifacts in the selected workspace."""
        return self.database.get_all(
            workspace or self.workspace,
            host=host,
            session_id=session_id,
            limit=limit,
        )

    def get_artifact(self, identifier, *, workspace=None):
        """Retrieve one artifact record by ID."""
        try:
            return self.database.get_artifact(workspace or self.workspace, identifier)
        except TypeError, ValueError:
            return None

    def path_for(self, record):
        """Resolve a catalog record to a path inside managed storage."""
        path = (self.root / record["relative_path"]).resolve()

        root = self.root.resolve()
        if not path.is_relative_to(root):
            raise ValueError("Artifact path is outside the managed loot directory.")
        return path

    def export(self, identifier, destination, *, workspace=None):
        """Copy an artifact to a caller-selected destination."""
        record = self.get_artifact(identifier, workspace=workspace)
        if record is None:
            raise ValueError(f"Loot record {identifier!r} was not found.")

        source = self.path_for(record)
        if not source.is_file():
            raise FileNotFoundError(f"Stored artifact is missing: {source}")

        target = Path(destination).expanduser()
        if target.exists() and target.is_dir():
            target = target / record["filename"]
        if target.exists():
            raise FileExistsError(f"Export destination already exists: {target}")

        target.parent.mkdir(parents=True, exist_ok=True)
        if target.resolve() == source.resolve():
            raise ValueError("Export destination is the same as the stored artifact.")

        shutil.copy2(source, target)
        return target

    def delete(self, identifier, *, workspace=None):
        """Remove an artifact from the catalog and managed storage."""
        workspace = workspace or self.workspace
        record = self.get_artifact(identifier, workspace=workspace)
        if record is None:
            return False

        path = self.path_for(record)

        removed = self.database.delete(workspace, identifier)
        if removed is None:
            return False

        path.unlink(missing_ok=True)
        return True
