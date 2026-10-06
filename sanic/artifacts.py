"""Immutable artifact versions.

A *publication* seals a visible slice of a file into a private,
content-addressed store together with its digest, byte length and the
source offsets it was taken from. Aliases point at exactly one sealed
version; repointing an alias is an atomic pointer swap. In-flight
requests pin the resolved version for their whole lifetime, so an alias
switch, a concurrent revocation or an external replacement of the source
file can never mix bytes from different versions.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from email.utils import formatdate, parsedate_to_datetime
from os import PathLike
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

from sanic.compat import open_async, stat_async
from sanic.exceptions import (
    ArtifactConflict,
    ArtifactCorrupted,
    ArtifactNotFound,
    ArtifactPreconditionFailed,
    ArtifactRevoked,
    RangeNotSatisfiable,
)
from sanic.response.convenience import guess_content_type
from sanic.response.types import HTTPResponse, ResponseStream

if TYPE_CHECKING:
    from sanic.compat import Header
    from sanic.request import Request


DEFAULT_CHUNK_SIZE = 1024 * 1024
# Retain a few bytes of the digest in log lines without dumping all of it.
LOG_DIGEST_LEN = 12
_INDEX_NAME = "artifact-index.json"


class ByteRange(NamedTuple):
    start: int
    end: int  # inclusive, HTTP style
    size: int
    total: int


@dataclass(frozen=True)
class ArtifactVersion:
    """A sealed, immutable view of published bytes."""

    alias: str
    version: str
    digest_algorithm: str
    digest: str
    size: int
    start: int
    end: int  # exclusive source offset
    content_type: str
    published_at: float
    source: str
    revoked: bool = False
    etag: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "etag", f'"{self.version}"')

    def basis_for(self, alias: str) -> str:
        """Stable ``alias@digest-prefix`` descriptor used in access logs."""
        return f"{alias}@{self.digest[:LOG_DIGEST_LEN]}"

    @property
    def basis(self) -> str:
        return self.basis_for(self.alias)

    @property
    def last_modified(self) -> str:
        return formatdate(self.published_at, usegmt=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alias": self.alias,
            "version": self.version,
            "digest_algorithm": self.digest_algorithm,
            "digest": self.digest,
            "size": self.size,
            "start": self.start,
            "end": self.end,
            "content_type": self.content_type,
            "published_at": self.published_at,
            "source": self.source,
            "revoked": self.revoked,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArtifactVersion":
        return cls(
            alias=data["alias"],
            version=data["version"],
            digest_algorithm=data["digest_algorithm"],
            digest=data["digest"],
            size=data["size"],
            start=data["start"],
            end=data["end"],
            content_type=data["content_type"],
            published_at=data["published_at"],
            source=data["source"],
            revoked=data.get("revoked", False),
        )


def parse_etag_list(value: str | None) -> list[str] | None:
    """Parse an ETag list header, returning ``["*"]`` for the wildcard."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return []
    if value == "*":
        return ["*"]
    etags: list[str] = []
    for part in value.split(","):
        token = part.strip()
        if token.startswith("W/"):
            token = token[2:].strip()
        if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
            etags.append(token[1:-1])
    return etags


def parse_byte_ranges(header_value: str, total: int) -> list[ByteRange]:
    """Parse a ``Range: bytes=…`` header into coalesced byte ranges."""

    def unsatisfiable(message: str) -> RangeNotSatisfiable:
        return RangeNotSatisfiable(message, _RangeTotal(total))

    unit, _, value = header_value.partition("=")
    if unit.strip() != "bytes" or not value:
        raise unsatisfiable(
            f"Unsupported or invalid range unit: {unit!r}"
        )

    raw_specs: list[tuple[int, int]] = []
    for spec in value.split(","):
        spec = spec.strip()
        if not spec:
            continue
        start_b, sep, end_b = spec.partition("-")
        if not sep:
            raise unsatisfiable(f"Invalid byte range: {spec!r}")
        try:
            if start_b == "":
                if end_b == "":
                    raise unsatisfiable(f"Invalid byte range: {spec!r}")
                # Suffix range: last N bytes.
                length = int(end_b)
                if length <= 0:
                    raise unsatisfiable(f"Invalid suffix length: {spec!r}")
                start = max(total - length, 0)
                end = total - 1
            else:
                start = int(start_b)
                end = int(end_b) if end_b else total - 1
        except ValueError:
            raise unsatisfiable(f"Invalid byte range: {spec!r}")

        if start < 0:
            raise unsatisfiable(
                f"Byte range starts before the artifact: {spec!r}"
            )
        if start >= total:
            raise unsatisfiable(
                f"Byte range starts beyond the artifact: {spec!r}"
            )
        end = min(end, total - 1)
        if end < start:
            raise unsatisfiable(
                f"Invalid byte range ordering: {spec!r}"
            )
        raw_specs.append((start, end))

    if not raw_specs:
        raise unsatisfiable("Range header contained no valid specs")

    # Sort and coalesce overlapping/adjacent intervals.
    raw_specs.sort()
    coalesced: list[list[int]] = []
    for start, end in raw_specs:
        if coalesced and start <= coalesced[-1][1] + 1:
            if end > coalesced[-1][1]:
                coalesced[-1][1] = end
        else:
            coalesced.append([start, end])

    return [
        ByteRange(start=s, end=e, size=e - s + 1, total=total)
        for s, e in coalesced
    ]


class _RangeTotal:
    """Minimal object carrying ``total`` for the 416 Content-Range."""

    __slots__ = ("total",)

    def __init__(self, total: int) -> None:
        self.total = total


class ArtifactRegistry:
    """Holds sealed artifact versions and the alias → version map."""

    def __init__(
        self,
        store_dir: PathLike | str,
        *,
        index_file: PathLike | str | None = None,
        digest_algorithm: str = "sha256",
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        stream_threshold: int | bool = True,
    ) -> None:
        if digest_algorithm not in hashlib.algorithms_available:
            raise ValueError(f"Unknown digest algorithm: {digest_algorithm}")
        self.store_dir = Path(store_dir)
        self.index_file = (
            Path(index_file)
            if index_file
            else self.store_dir / _INDEX_NAME
        )
        self.digest_algorithm = digest_algorithm
        self.chunk_size = chunk_size
        if stream_threshold is True:
            self.stream_threshold = DEFAULT_CHUNK_SIZE
        elif stream_threshold is False:
            self.stream_threshold = None
        else:
            self.stream_threshold = int(stream_threshold)
        self._versions: dict[str, ArtifactVersion] = {}
        self._aliases: dict[str, str] = {}
        self._index_mtime: float | None = None
        self._lock = None
        self._lock_loop = None

    def _ensure_lock(self):
        import asyncio

        loop = asyncio.get_running_loop()
        # The registry can outlive the loop it was created in (e.g. eager
        # publication in a throwaway loop before the server starts); a lock bound to
        # a dead loop is unusable, so rebind it to the current one.
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    # ------------------------------------------------------------------
    # Store layout
    # ------------------------------------------------------------------
    def _blob_path(self, digest: str) -> Path:
        return self.store_dir / digest[:2] / digest

    def _ensure_store(self) -> None:
        self.store_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Persistence / recovery
    # ------------------------------------------------------------------
    async def restore(self) -> None:
        """Rebuild the in-memory index from the persisted state file."""
        self._ensure_store()
        await self._load_index(force=True)

    async def sync_from_disk(self) -> bool:
        """Reload the index if another process rewrote it.

        One ``stat`` per request; the index itself is only read when the
        mtime changed. This is how a publish/revoke performed in another worker
        becomes visible atomically here.
        """
        try:
            stats = await stat_async(self.index_file)
        except FileNotFoundError:
            return False
        if self._index_mtime is not None and stats.st_mtime <= self._index_mtime:
            return False
        await self._load_index(force=True)
        return True

    async def _load_index(self, *, force: bool = False) -> None:
        if not self.index_file.exists():
            self._index_mtime = None
            return
        index_stats = self.index_file.stat()
        if (
            not force
            and self._index_mtime is not None
            and index_stats.st_mtime <= self._index_mtime
        ):
            return
        async with await open_async(self.index_file, mode="rb") as f:
            raw = await f.read()
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ArtifactCorrupted(
                f"Artifact index is not valid JSON: {self.index_file}"
            )

        versions: dict[str, ArtifactVersion] = {}
        for item in data.get("versions", []):
            artifact = ArtifactVersion.from_dict(item)
            if not artifact.revoked:
                # Eager length check; the digest itself is re-verified
                # while serving (and on publish).
                blob = self._blob_path(artifact.digest)
                if not blob.exists():
                    raise ArtifactCorrupted(
                        f"Artifact blob missing on restore: {artifact.basis}"
                    )
                stats = await stat_async(blob)
                if stats.st_size != artifact.size:
                    raise ArtifactCorrupted(
                        f"Artifact blob length changed on restore: "
                        f"{artifact.basis}"
                    )
            versions[artifact.version] = artifact

        aliases: dict[str, str] = {}
        for alias, version_id in data.get("aliases", {}).items():
            if version_id not in versions:
                raise ArtifactCorrupted(
                    f"Alias {alias!r} points at missing version {version_id}"
                )
            aliases[alias] = version_id

        self._versions = versions
        self._aliases = aliases
        self._index_mtime = index_stats.st_mtime

    async def _persist(self) -> None:
        """Atomically rewrite the index file."""
        self._ensure_store()
        payload = {
            "digest_algorithm": self.digest_algorithm,
            "aliases": dict(self._aliases),
            "versions": [v.to_dict() for v in self._versions.values()],
        }
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        fd, tmp_name = tempfile.mkstemp(
            prefix=".artifact-index-", dir=str(self.store_dir)
        )
        try:
            with os.fdopen(fd, "wb") as tmp:
                tmp.write(data)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_name, self.index_file)
            self._index_mtime = self.index_file.stat().st_mtime
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------------
    # Publication / revocation
    # ------------------------------------------------------------------
    async def publish(
        self,
        alias: str,
        location: PathLike | str,
        *,
        start: int = 0,
        end: int | None = None,
        content_type: str | None = None,
        version: str | None = None,
    ) -> ArtifactVersion:
        """Seal the visible slice of ``location`` and atomically alias it."""
        lock = self._ensure_lock()
        async with lock:
            # Pick up publications/revocations performed by peer workers first so the
            # atomic rewrite never clobbers them.
            await self.sync_from_disk()
            source = Path(location)
            stats = await stat_async(source)
            total = stats.st_size
            if end is None:
                end = total
            if start < 0 or end < start or end > total:
                raise ArtifactConflict(
                    f"Visible window [{start}, {end}) is outside "
                    f"{source} (size={total})"
                )

            length = end - start
            digest = await self._hash_window(source, start, end)
            version_id = version or digest

            existing = self._versions.get(version_id)
            if existing and existing.digest != digest:
                raise ArtifactConflict(
                    f"Version {version_id!r} is already sealed to "
                    "different bytes"
                )
            if existing and existing.size != length:
                raise ArtifactConflict(
                    f"Version {version_id!r} is already sealed at a "
                    "different length"
                )

            # A revoked version may be republished with identical bytes: the blob
            # was unlinked at revoke time, so reseal it and replace the
            # tombstone with a live artifact.
            if existing is None or existing.revoked:
                await self._snapshot_window(
                    source, start, end, digest, length
                )
                artifact = ArtifactVersion(
                    alias=alias,
                    version=version_id,
                    digest_algorithm=self.digest_algorithm,
                    digest=digest,
                    size=length,
                    start=start,
                    end=end,
                    content_type=content_type
                    or guess_content_type(str(source)),
                    published_at=_now(),
                    source=os.fspath(source.resolve()),
                )
                self._versions[version_id] = artifact
            else:
                artifact = existing

            # Atomic pointer swap: the alias now resolves to one version.
            self._aliases[alias] = version_id
            await self._persist()
            return artifact

    async def _hash_window(
        self, source: Path, start: int, end: int
    ) -> str:
        hasher = hashlib.new(self.digest_algorithm)
        remaining = end - start
        async with await open_async(source, mode="rb") as f:
            await f.seek(start)
            while remaining > 0:
                chunk = await f.read(min(self.chunk_size, remaining))
                if not chunk:
                    raise ArtifactCorrupted(
                        f"Source {source} shrank while sealing "
                        f"[{start}, {end})"
                    )
                hasher.update(chunk)
                remaining -= len(chunk)
        return hasher.hexdigest()

    async def _snapshot_window(
        self,
        source: Path,
        start: int,
        end: int,
        digest: str,
        length: int,
    ) -> None:
        """Copy the visible bytes into the content-addressed store."""
        target = self._blob_path(digest)
        if target.exists():
            stats = await stat_async(target)
            if stats.st_size == length:
                return
            raise ArtifactCorrupted(
                f"Artifact store collision at {target}: wrong length"
            )

        self._ensure_store()
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=".artifact-blob-", dir=str(target.parent)
        )
        hasher = hashlib.new(self.digest_algorithm)
        written = 0
        remaining = end - start
        try:
            with os.fdopen(fd, "wb") as out:
                async with await open_async(source, mode="rb") as f:
                    await f.seek(start)
                    while remaining > 0:
                        chunk = await f.read(
                            min(self.chunk_size, remaining)
                        )
                        if not chunk:
                            raise ArtifactCorrupted(
                                f"Source {source} shrank while snapshotting"
                            )
                        out.write(chunk)
                        hasher.update(chunk)
                        written += len(chunk)
                        remaining -= len(chunk)
                out.flush()
                os.fsync(out.fileno())
            if written != length or hasher.hexdigest() != digest:
                raise ArtifactCorrupted(
                    f"Snapshot of {source} does not match sealed digest"
                )
            os.chmod(tmp_name, 0o444)
            os.replace(tmp_name, target)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    async def revoke(
        self,
        alias: str | None = None,
        *,
        version: str | None = None,
    ) -> list[ArtifactVersion]:
        """Withdraw aliases/versions atomically.

        Revoking an alias drops that one pointer; the backing blob is only
        unlinked once *no* live alias references the version anymore. Revoking a
        version id withdraws every alias pointing at it and then unlinks the
        blob. Already-open responses keep serving pinned bytes: unlinking keeps the
        inode alive for open descriptors, while new opens get a clean 410/404.
        """
        if alias is None and version is None:
            raise ValueError("revoke() requires an alias or a version")

        lock = self._ensure_lock()
        revoked: list[ArtifactVersion] = []
        async with lock:
            await self.sync_from_disk()

            target_ids: set[str] = set()
            if version is not None:
                target_ids.add(version)
            if alias is not None:
                current = self._aliases.get(alias)
                if current is None and version is None:
                    raise ArtifactNotFound(
                        f"No artifact published as {alias!r}"
                    )
                if current:
                    target_ids.add(current)
                self._aliases.pop(alias, None)

            # Version-id revocation withdraws every alias pointing at it.
            if version is not None:
                for name in list(self._aliases):
                    if self._aliases[name] == version:
                        del self._aliases[name]

            for version_id in target_ids:
                artifact = self._versions.get(version_id)
                if artifact is None:
                    raise ArtifactNotFound(
                        f"Unknown artifact version: {version_id}"
                    )
                # Still referenced by another live alias? Then keep the bytes
                # alive; only this one pointer was withdrawn.
                if version_id in self._aliases.values():
                    continue

                blob = self._blob_path(artifact.digest)
                try:
                    os.chmod(blob, 0o600)
                    os.unlink(blob)
                except FileNotFoundError:
                    pass
                tombstone = ArtifactVersion(
                    **{**artifact.to_dict(), "revoked": True}
                )
                self._versions[version_id] = tombstone
                revoked.append(tombstone)

            await self._persist()
        return revoked

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------
    def current(self, alias: str) -> ArtifactVersion | None:
        version_id = self._aliases.get(alias)
        return self._versions.get(version_id) if version_id else None

    def get_version(self, version_id: str) -> ArtifactVersion | None:
        return self._versions.get(version_id)

    def resolve(self, alias: str) -> ArtifactVersion:
        """Resolve an alias to the one version it atomically points at."""
        artifact = self.current(alias)
        if artifact is None:
            raise ArtifactNotFound(f"No artifact published as {alias!r}")
        if artifact.revoked:
            raise ArtifactRevoked(
                f"Artifact version {artifact.basis} was revoked"
            )
        return artifact

    # ------------------------------------------------------------------
    # HTTP serving
    # ------------------------------------------------------------------
    async def handle(
        self, request: "Request", __artifact_alias__: str
    ) -> HTTPResponse:
        """Sanic handler for GET/HEAD against a pinned artifact version."""
        alias = __artifact_alias__.lstrip("/")

        # Atomic cross-worker visibility: one cheap stat, reload only when the
        # index was rewritten by a publish/revoke elsewhere.
        await self.sync_from_disk()

        pinned, early = await self._preconditions(request, alias)
        # The version basis is what access logs must carry - never the
        # absolute filesystem path of the source or blob.
        try:
            request.ctx._artifact_basis = pinned.basis_for(alias)
        except Exception:  # pragma: no cover - ctx is a SimpleNamespace
            pass
        if early is not None:
            return early

        return await self._respond(request, pinned, alias)

    async def _preconditions(
        self, request: "Request", alias: str
    ) -> tuple[ArtifactVersion, HTTPResponse | None]:
        """Evaluate RFC 7232 preconditions and pin one sealed version.

        Returns the pinned version plus an optional early response (304).

        Order follows RFC 7232 §6: If-Match, If-Unmodified-Since,
        If-None-Match, If-Modified-Since. If-Range (RFC 7233) may pin the
        exact resumable version before the Range is applied.
        """
        headers = request.headers
        if_match = parse_etag_list(headers.get("if-match"))
        if_none_match = parse_etag_list(headers.get("if-none-match"))
        if_range = headers.get("if-range")
        range_header = headers.get("range")

        pinned: ArtifactVersion | None = None
        honor_range = bool(range_header)

        # 1. If-Match: one of the listed versions must exist and be live.
        if if_match is not None:
            if if_match == ["*"]:
                pinned = self.current(alias)
            else:
                for candidate in if_match:
                    artifact = self._versions.get(candidate)
                    if artifact is not None and not artifact.revoked:
                        pinned = artifact
                        break
            if pinned is None:
                raise ArtifactPreconditionFailed(
                    "If-Match did not match any available version"
                )

        # 2. If-Range (RFC 7233): "give me the slice only if the
        #    representation I already have is still current; otherwise send the
        #    whole current representation." When If-Match already selected a
        #    representation (step 1), that pinned one is the comparison
        #    target; otherwise it is the version the alias currently points at.
        #    Comparing against the current representation - never an arbitrary old
        #    version - is exactly what prevents stitching an old-ETag resume
        #    onto newer bytes.
        if range_header and if_range:
            target = pinned or self.current(alias)
            if target is None or target.revoked:
                raise ArtifactNotFound(f"No artifact published as {alias!r}")
            if not self._if_range_matches(if_range, target):
                range_header = None
                honor_range = False
            pinned = target

        # 3. Default pin: the version the alias atomically points at now.
        if pinned is None:
            pinned = self.resolve(alias)

        # 4. If-Unmodified-Since.
        ius = headers.get("if-unmodified-since")
        if ius and not self._date_at_least(ius, pinned.published_at):
            raise ArtifactPreconditionFailed(
                "Artifact was modified after If-Unmodified-Since"
            )
        # 5. If-None-Match -> 304 (GET/HEAD).
        if (
            if_none_match is not None
            and request.method in ("GET", "HEAD")
            and (if_none_match == ["*"] or pinned.version in if_none_match)
        ):
            return pinned, await self._not_modified(pinned, request)

        # 6. If-Modified-Since (ignored when If-None-Match is present).
        ims = headers.get("if-modified-since")
        if (
            ims
            and if_none_match is None
            and request.method in ("GET", "HEAD")
        ):
            try:
                since_dt = parsedate_to_datetime(ims)
                # HTTP-date has 1-second resolution; compare on whole seconds.
                if int(pinned.published_at) <= int(since_dt.timestamp()):
                    return pinned, await self._not_modified(pinned, request)
            except (TypeError, ValueError):
                pass

        request.ctx._artifact_range_header = (
            range_header if honor_range else None
        )
        return pinned, None

    @staticmethod
    def _if_range_matches(value: str, artifact: ArtifactVersion) -> bool:
        """Whether an If-Range precondition still selects this representation."""
        token = value.strip()
        if token.startswith("W/"):
            token = token[2:].strip()
        if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
            return token[1:-1] == artifact.version and not artifact.revoked
        # HTTP-date form: matches when the artifact has not changed since.
        try:
            since_dt = parsedate_to_datetime(token)
            return artifact.published_at <= since_dt.timestamp()
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _date_at_least(header_value: str, timestamp: float) -> bool:
        try:
            since_dt = parsedate_to_datetime(header_value)
            return int(timestamp) <= int(since_dt.timestamp())
        except (TypeError, ValueError):
            return True

    async def _not_modified(
        self, artifact: ArtifactVersion, request: "Request"
    ) -> HTTPResponse:
        headers = {
            "ETag": artifact.etag,
            "Last-Modified": artifact.last_modified,
            "Cache-Control": "no-cache",
            "X-Artifact-Version": artifact.version,
        }
        return HTTPResponse(status=304, headers=headers)

    def _base_headers(self, artifact: ArtifactVersion) -> dict[str, str]:
        return {
            "ETag": artifact.etag,
            "Last-Modified": artifact.last_modified,
            "Accept-Ranges": "bytes",
            "X-Artifact-Version": artifact.version,
            # Sealed versions never change under their ETag.
            "Cache-Control": "max-age=0, must-revalidate",
        }

    async def _respond(
        self,
        request: "Request",
        artifact: ArtifactVersion,
        alias: str,
    ) -> HTTPResponse:
        range_header = getattr(
            request.ctx, "_artifact_range_header", None
        )
        headers = self._base_headers(artifact)
        total = artifact.size

        if not range_header:
            headers["Content-Length"] = str(total)
            if request.method == "HEAD":
                return HTTPResponse(
                    status=200,
                    headers=headers,
                    content_type=artifact.content_type,
                )
            return await self._full_response(request, artifact, headers)

        ranges = parse_byte_ranges(range_header, total)

        if request.method == "HEAD":
            if len(ranges) == 1:
                byte_range = ranges[0]
                headers["Content-Type"] = artifact.content_type
                headers["Content-Range"] = (
                    f"bytes {byte_range.start}-{byte_range.end}/{total}"
                )
                headers["Content-Length"] = str(byte_range.size)
                return HTTPResponse(status=206, headers=headers)
            # Multipart: mirror the framing that a GET would send without bytes.
            boundary = f"sanic-artifact-{artifact.digest[:24]}"
            content_type = f"multipart/byteranges; boundary={boundary}"
            part_headers = [
                self._part_header(boundary, artifact, byte_range)
                for byte_range in ranges
            ]
            length = (
                sum(
                    len(head) + byte_range.size + 2
                    for head, byte_range in zip(part_headers, ranges)
                )
                + len(f"--{boundary}--\r\n")
            )
            headers["Content-Type"] = content_type
            headers["Content-Length"] = str(length)
            return HTTPResponse(status=206, headers=headers)

        if len(ranges) == 1:
            return await self._single_range_response(
                request, artifact, ranges[0], headers
            )
        return await self._multi_range_response(
            request, artifact, ranges, headers
        )

    async def _open_blob(self, artifact: ArtifactVersion):
        """Open the sealed blob, pinning the inode for the whole request.

        Revocation unlinks the blob; an already-open descriptor keeps
        serving the exact sealed bytes, while a request that arrives after
        the unlink gets a clean 410 instead of partial data. The length is
        checked at open time so an externally modified store blob can never
        leak inconsistent bytes.
        """
        if artifact.revoked:
            raise ArtifactRevoked(
                f"Artifact version {artifact.basis} was revoked"
            )
        blob = self._blob_path(artifact.digest)
        try:
            stats = await stat_async(blob)
        except FileNotFoundError:
            raise ArtifactRevoked(
                f"Artifact version {artifact.basis} was revoked"
            )
        if stats.st_size != artifact.size:
            raise ArtifactCorrupted(
                f"Artifact blob {artifact.basis} length changed: "
                f"sealed={artifact.size} actual={stats.st_size}"
            )
        return await open_async(blob, mode="rb")

    async def _pin_handle(self, artifact: ArtifactVersion):
        """Enter the blob's async context manager up-front.

        Opening and entering happens before response headers are emitted, so a
        concurrent revoke between pinning and first byte becomes either a fully
        successful old-version response or a clean 410/500, never a partial body.
        """
        manager = await self._open_blob(artifact)
        handle = await manager.__aenter__()
        return manager, handle

    async def _full_response(
        self,
        request: "Request",
        artifact: ArtifactVersion,
        headers: dict[str, str],
    ) -> HTTPResponse:
        headers["Content-Type"] = artifact.content_type
        stream = (
            self.stream_threshold is not None
            and artifact.size >= self.stream_threshold
        )

        if not stream:
            async with await self._open_blob(artifact) as f:
                body = await f.read()
            self._verify_inline(artifact, body, 0, artifact.size)
            return HTTPResponse(
                body=body,
                status=200,
                headers=headers,
                content_type=artifact.content_type,
            )

        # Pin the descriptor before headers go out so a concurrent revoke
        # cannot turn into a half-sent body.
        manager, handle = await self._pin_handle(artifact)
        chunk_size = self.chunk_size
        total = artifact.size

        async def streaming_fn(response: ResponseStream) -> None:
            import hashlib as _h

            hasher = _h.new(artifact.digest_algorithm)
            seen = 0
            try:
                while seen < total:
                    chunk = await handle.read(
                        min(chunk_size, total - seen)
                    )
                    if not chunk:
                        raise ArtifactCorrupted(
                            f"Artifact blob {artifact.basis} ended early"
                        )
                    hasher.update(chunk)
                    seen += len(chunk)
                    await response.write(chunk)
                if seen != total or hasher.hexdigest() != artifact.digest:
                    raise ArtifactCorrupted(
                        f"Artifact blob {artifact.basis} failed digest check"
                    )
            finally:
                await manager.__aexit__(None, None, None)

        return ResponseStream(
            streaming_fn=streaming_fn,
            status=200,
            headers=headers,
            content_type=artifact.content_type,
        )

    def _verify_inline(
        self,
        artifact: ArtifactVersion,
        body: bytes,
        offset: int,
        expected_length: int,
    ) -> None:
        if len(body) != expected_length:
            raise ArtifactCorrupted(
                f"Artifact {artifact.basis}: read {len(body)} bytes at "
                f"offset {offset}, expected {expected_length}"
            )
        # Full-body reads are checked against the sealed digest. Range
        # slices come from the read-only, content-addressed store blob, so
        # their length and offsets are the contract.
        if offset == 0 and expected_length == artifact.size:
            hasher = hashlib.new(artifact.digest_algorithm)
            hasher.update(body)
            if hasher.hexdigest() != artifact.digest:
                raise ArtifactCorrupted(
                    f"Artifact {artifact.basis} failed digest check"
                )

    async def _single_range_response(
        self,
        request: "Request",
        artifact: ArtifactVersion,
        byte_range: ByteRange,
        headers: dict[str, str],
    ) -> HTTPResponse:
        headers["Content-Type"] = artifact.content_type
        headers["Content-Range"] = (
            f"bytes {byte_range.start}-{byte_range.end}/{byte_range.total}"
        )
        headers["Content-Length"] = str(byte_range.size)

        stream = (
            self.stream_threshold is not None
            and byte_range.size >= self.stream_threshold
        )
        if not stream:
            async with await self._open_blob(artifact) as f:
                await f.seek(byte_range.start)
                body = await f.read(byte_range.size)
            self._verify_inline(
                artifact, body, byte_range.start, byte_range.size
            )
            return HTTPResponse(
                body=body,
                status=206,
                headers=headers,
                content_type=artifact.content_type,
            )

        manager, handle = await self._pin_handle(artifact)
        chunk_size = self.chunk_size

        async def streaming_fn(response: ResponseStream) -> None:
            remaining = byte_range.size
            try:
                await handle.seek(byte_range.start)
                while remaining > 0:
                    chunk = await handle.read(min(chunk_size, remaining))
                    if not chunk:
                        raise ArtifactCorrupted(
                            f"Artifact blob {artifact.basis} ended early"
                        )
                    remaining -= len(chunk)
                    await response.write(chunk)
            finally:
                await manager.__aexit__(None, None, None)

        return ResponseStream(
            streaming_fn=streaming_fn,
            status=206,
            headers=headers,
            content_type=artifact.content_type,
        )

    async def _multi_range_response(
        self,
        request: "Request",
        artifact: ArtifactVersion,
        ranges: list[ByteRange],
        headers: dict[str, str],
    ) -> HTTPResponse:
        boundary = f"sanic-artifact-{artifact.digest[:24]}"
        content_type = f"multipart/byteranges; boundary={boundary}"

        part_headers = [
            self._part_header(boundary, artifact, byte_range)
            for byte_range in ranges
        ]
        # Every framing byte is known up front, so Content-Length is exact
        # even though the bytes themselves are streamed.
        length = (
            sum(len(head) + byte_range.size + 2 for head, byte_range in zip(
                part_headers, ranges
            ))
            + len(f"--{boundary}--\r\n")
        )

        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(length)

        manager, handle = await self._pin_handle(artifact)
        chunk_size = self.chunk_size
        closing = f"--{boundary}--\r\n".encode("ascii")

        async def streaming_fn(response: ResponseStream) -> None:
            try:
                for head, byte_range in zip(part_headers, ranges):
                    await response.write(head)
                    remaining = byte_range.size
                    await handle.seek(byte_range.start)
                    while remaining > 0:
                        chunk = await handle.read(min(chunk_size, remaining))
                        if not chunk:
                            raise ArtifactCorrupted(
                                f"Artifact blob {artifact.basis} ended early"
                            )
                        remaining -= len(chunk)
                        await response.write(chunk)
                    await response.write(b"\r\n")
                await response.write(closing)
            finally:
                await manager.__aexit__(None, None, None)

        return ResponseStream(
            streaming_fn=streaming_fn,
            status=206,
            headers=headers,
            content_type=content_type,
        )

    @staticmethod
    def _part_header(
        boundary: str,
        artifact: ArtifactVersion,
        byte_range: ByteRange,
    ) -> bytes:
        return (
            f"--{boundary}\r\n"
            f"Content-Type: {artifact.content_type}\r\n"
            f"Content-Range: bytes "
            f"{byte_range.start}-{byte_range.end}/{byte_range.total}\r\n\r\n"
        ).encode("ascii")


def _now() -> float:
    import time

    return time.time()
