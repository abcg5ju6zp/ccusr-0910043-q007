"""Immutable artifact publication API on the Sanic application."""

from __future__ import annotations

import asyncio
from functools import partial, wraps
from os import PathLike
from pathlib import Path, PurePath
from typing import TYPE_CHECKING

from sanic.artifacts import ArtifactRegistry, ArtifactVersion
from sanic.base.meta import SanicMeta
from sanic.compat import clear_function_annotate

if TYPE_CHECKING:
    from sanic.request import Request


class ArtifactMixin(metaclass=SanicMeta):
    def artifact_registry(
        self,
        name: str = "default",
        store_dir: PathLike | str | None = None,
        *,
        digest_algorithm: str = "sha256",
        index_file: PathLike | str | None = None,
        stream_threshold: int | bool = True,
    ) -> ArtifactRegistry:
        """Return (creating once) the named immutable-artifact registry."""
        registries: dict[str, ArtifactRegistry]
        try:
            registries = self._artifact_registries
        except AttributeError:
            registries = self._artifact_registries = {}
        if name in registries:
            return registries[name]
        if store_dir is None:
            raise ValueError(
                f"Artifact registry {name!r} does not exist and no "
                "store_dir was provided"
            )
        registry = ArtifactRegistry(
            store_dir,
            index_file=index_file,
            digest_algorithm=digest_algorithm,
            stream_threshold=stream_threshold,
        )
        registries[name] = registry
        return registry

    def artifact(
        self,
        uri: str,
        store_dir: PathLike | str,
        *,
        name: str = "artifacts",
        digest_algorithm: str = "sha256",
        index_file: PathLike | str | None = None,
        host: str | None = None,
        strict_slashes: bool | None = None,
        stream_threshold: int | bool = True,
        registry_name: str = "default",
        index_restore: bool = True,
    ) -> ArtifactRegistry:
        """Mount an immutable-artifact store at ``uri``.

        Creates the registry, recovers any persisted index and registers the alias
        route. Versions are sealed later with :meth:`publish_artifact`.
        """
        if not isinstance(store_dir, (str, bytes, PurePath)):
            raise ValueError(
                f"Artifact store must be a valid path, not {store_dir}"
            )
        store_dir = Path(store_dir).resolve()
        registry = self.artifact_registry(
            registry_name,
            store_dir,
            digest_algorithm=digest_algorithm,
            index_file=index_file,
            stream_threshold=stream_threshold,
        )

        if index_restore:
            # Best effort for setup code running without a loop; the startup listener
            # below is the authority inside real server (and worker) processes.
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                asyncio.run(registry.restore())

            async def _restore_artifacts(app) -> None:
                await registry.restore()

            self.register_listener(
                _restore_artifacts, "before_server_start"
            )

        full_name = self.generate_name(name)
        route_uri = uri.rstrip("/") + "/<__artifact_alias__:path>"
        handler = wraps(_artifact_dispatch)(
            partial(_artifact_dispatch, registry=registry)
        )
        self.route(  # type: ignore
            uri=route_uri,
            methods=["GET", "HEAD"],
            name=full_name,
            host=host,
            strict_slashes=strict_slashes,
            static=True,
        )(handler)
        return registry

    async def publish_artifact(
        self,
        alias: str,
        location: PathLike | str,
        *,
        start: int = 0,
        end: int | None = None,
        content_type: str | None = None,
        version: str | None = None,
        registry_name: str = "default",
    ) -> ArtifactVersion:
        """Seal a visible slice of a file and atomically point an alias at it."""
        registry = self._artifact_registries[registry_name]
        return await registry.publish(
            alias,
            location,
            start=start,
            end=end,
            content_type=content_type,
            version=version,
        )

    async def revoke_artifact(
        self,
        alias: str | None = None,
        *,
        version: str | None = None,
        registry_name: str = "default",
    ) -> list[ArtifactVersion]:
        """Withdraw an alias/version; in-flight requests keep pinned bytes."""
        registry = self._artifact_registries[registry_name]
        return await registry.revoke(alias, version=version)


async def _artifact_dispatch(
    request: "Request",
    *,
    registry: ArtifactRegistry,
    __artifact_alias__: str,
):
    """Route handler entrypoint for sealed artifacts."""
    return await registry.handle(request, __artifact_alias__)


clear_function_annotate(_artifact_dispatch)
