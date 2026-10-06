import asyncio

from pathlib import Path
from unittest.mock import Mock

import pytest

import sanic.http.http1 as http1

from sanic import Sanic
from sanic.artifacts import ArtifactRegistry, parse_byte_ranges
from sanic.exceptions import (
    ArtifactCorrupted,
    ArtifactRevoked,
)
from sanic.response import empty


V1 = b"RULES-V1-" + b"0123456789" * 4  # 49 bytes


def _make_app(name: str, tmp_path: Path, **artifact_kwargs):
    src = Path(tmp_path) / "rules.sig"
    src.write_bytes(V1)
    app = Sanic(name)
    app.config.ACCESS_LOG = True
    registry = app.artifact(
        "/dist", Path(tmp_path) / "store", index_restore=False, **artifact_kwargs
    )
    # Seal eagerly in a throwaway loop; later server runs use other loops and the
    # registry's in-memory + persisted state survives.
    asyncio.run(registry.restore())
    asyncio.run(registry.publish("rules.sig", src))

    @app.post("/__republish__")
    async def _republish(request):
        request.app.ctx.src.write_bytes(request.body)
        await request.app.publish_artifact(
            "rules.sig", request.app.ctx.src
        )
        return empty()

    @app.post("/__revoke__")
    async def _revoke(request):
        await request.app.revoke_artifact("rules.sig")
        return empty()

    app.ctx.src = src
    return app, registry


@pytest.fixture
def app(tmp_path):
    app, registry = _make_app("artifacts_app", tmp_path)
    yield app


@pytest.fixture
def app_and_registry(tmp_path):
    app, registry = _make_app("artifacts_app_reg", tmp_path)
    yield app, registry


@pytest.fixture
def streaming_app(tmp_path):
    app, registry = _make_app(
        "artifacts_stream", tmp_path, stream_threshold=8
    )
    yield app


# ---------------------------------------------------------------------------
# Full responses / headers
# ---------------------------------------------------------------------------
def test_full_get_returns_sealed_bytes(app):
    _, resp = app.test_client.get("/dist/rules.sig")
    assert resp.status == 200
    assert resp.body == V1
    etag = resp.headers["ETag"]
    assert etag.startswith('"') and etag.endswith('"')
    assert "W/" not in etag  # strong validator
    assert resp.headers["X-Artifact-Version"] == etag.strip('"')
    assert resp.headers["Accept-Ranges"] == "bytes"
    assert resp.headers["Content-Length"] == str(len(V1))
    assert resp.headers["Last-Modified"]
    assert resp.headers["Cache-Control"]


def test_head_has_headers_no_body(app):
    _, resp = app.test_client.head("/dist/rules.sig")
    assert resp.status == 200
    assert resp.body == b""
    assert resp.headers["Content-Length"] == str(len(V1))
    assert resp.headers["ETag"]


def test_head_range_is_headers_only(app):
    _, resp = app.test_client.head(
        "/dist/rules.sig", headers={"Range": "bytes=10-19"}
    )
    assert resp.status == 206
    assert resp.body == b""
    assert resp.headers["Content-Range"] == "bytes 10-19/49"
    assert resp.headers["Content-Length"] == "10"


def test_unknown_alias_is_404(app):
    _, resp = app.test_client.get("/dist/missing.sig")
    assert resp.status == 404


# ---------------------------------------------------------------------------
# Conditional requests
# ---------------------------------------------------------------------------
def test_if_none_match_304(app):
    _, first = app.test_client.get("/dist/rules.sig")
    etag = first.headers["ETag"]
    _, resp = app.test_client.get(
        "/dist/rules.sig", headers={"If-None-Match": etag}
    )
    assert resp.status == 304
    assert resp.headers["ETag"] == etag

    _, other = app.test_client.get(
        "/dist/rules.sig", headers={"If-None-Match": '"nope"'}
    )
    assert other.status == 200
    assert other.body == V1

    _, wildcard = app.test_client.get(
        "/dist/rules.sig", headers={"If-None-Match": "*"}
    )
    assert wildcard.status == 304


def test_if_modified_since(app):
    _, first = app.test_client.get("/dist/rules.sig")
    lm = first.headers["Last-Modified"]
    _, fresh = app.test_client.get(
        "/dist/rules.sig", headers={"If-Modified-Since": lm}
    )
    assert fresh.status == 304
    _, old = app.test_client.get(
        "/dist/rules.sig",
        headers={"If-Modified-Since": "Mon, 01 Jan 2001 00:00:00 GMT"},
    )
    assert old.status == 200


def test_if_match_precondition_failed(app):
    _, resp = app.test_client.get(
        "/dist/rules.sig", headers={"If-Match": '"deadbeef"'}
    )
    assert resp.status == 412


def test_if_unmodified_since(app):
    _, resp = app.test_client.get(
        "/dist/rules.sig",
        headers={"If-Unmodified-Since": "Mon, 01 Jan 2001 00:00:00 GMT"},
    )
    assert resp.status == 412


# ---------------------------------------------------------------------------
# Ranges
# ---------------------------------------------------------------------------
def test_single_range(app):
    _, resp = app.test_client.get(
        "/dist/rules.sig", headers={"Range": "bytes=10-19"}
    )
    assert resp.status == 206
    assert resp.body == V1[10:20]
    assert resp.headers["Content-Range"] == "bytes 10-19/49"
    assert resp.headers["Content-Length"] == "10"


def test_open_ended_and_suffix_ranges(app):
    _, tail = app.test_client.get(
        "/dist/rules.sig", headers={"Range": "bytes=40-"}
    )
    assert tail.status == 206
    assert tail.body == V1[40:]
    assert tail.headers["Content-Range"] == "bytes 40-48/49"

    _, suffix = app.test_client.get(
        "/dist/rules.sig", headers={"Range": "bytes=-9"}
    )
    assert suffix.status == 206
    assert suffix.body == V1[40:]


def test_unsatisfiable_range_is_416(app):
    _, resp = app.test_client.get(
        "/dist/rules.sig", headers={"Range": "bytes=999-"}
    )
    assert resp.status == 416
    assert resp.headers["Content-Range"] == "bytes */49"


def test_multi_range_framing(app):
    _, resp = app.test_client.get(
        "/dist/rules.sig", headers={"Range": "bytes=0-4,40-44"}
    )
    assert resp.status == 206
    ct = resp.headers["Content-Type"]
    assert ct.startswith("multipart/byteranges; boundary=")
    boundary = ct.split("boundary=")[1]
    body = resp.body
    assert body.startswith(f"--{boundary}\r\n".encode())
    assert body.endswith(f"--{boundary}--\r\n".encode())
    assert b"Content-Range: bytes 0-4/49" in body
    assert b"Content-Range: bytes 40-44/49" in body
    assert V1[0:5] in body
    assert V1[40:45] in body
    # Exact declared length equals actual framing length.
    assert int(resp.headers["Content-Length"]) == len(body)


def test_overlapping_ranges_coalesce():
    ranges = parse_byte_ranges("bytes=0-10,5-15", 49)
    assert len(ranges) == 1
    assert ranges[0] == (0, 15, 16, 49)


# ---------------------------------------------------------------------------
# Streaming paths (small threshold forces ResponseStream)
# ---------------------------------------------------------------------------
def test_streaming_full_and_range(streaming_app):
    _, resp = streaming_app.test_client.get("/dist/rules.sig")
    assert resp.status == 200
    assert resp.body == V1
    assert int(resp.headers["Content-Length"]) == len(V1)

    _, part = streaming_app.test_client.get(
        "/dist/rules.sig", headers={"Range": "bytes=10-19"}
    )
    assert part.status == 206
    assert part.body == V1[10:20]


def test_streaming_multirange(streaming_app):
    _, resp = streaming_app.test_client.get(
        "/dist/rules.sig", headers={"Range": "bytes=0-4,40-44"}
    )
    assert resp.status == 206
    assert V1[0:5] in resp.body
    assert V1[40:45] in resp.body
    assert int(resp.headers["Content-Length"]) == len(resp.body)


# ---------------------------------------------------------------------------
# Atomic alias switching / stale ETag resume - the core regression
# ---------------------------------------------------------------------------
def test_switch_serves_consistent_versions(app):
    _, first = app.test_client.get("/dist/rules.sig")
    old_etag = first.headers["ETag"]

    v2 = b"RULES-V2-" + b"Z" * 100
    app.test_client.post("/__republish__", data=v2)

    _, current = app.test_client.get("/dist/rules.sig")
    assert current.status == 200
    assert current.body == v2
    assert current.headers["ETag"] != old_etag

    # Stale If-Range: must NOT stitch old ETag + new bytes.
    _, stitched = app.test_client.get(
        "/dist/rules.sig",
        headers={"Range": "bytes=0-9", "If-Range": old_etag},
    )
    assert stitched.status == 200
    assert stitched.body == v2

    # Explicit If-Match pins the old sealed object for an honest resume.
    _, old_slice = app.test_client.get(
        "/dist/rules.sig",
        headers={
            "Range": "bytes=40-48",
            "If-Range": old_etag,
            "If-Match": old_etag,
        },
    )
    assert old_slice.status == 206
    assert old_slice.body == V1[40:]
    assert old_slice.headers["Content-Range"] == "bytes 40-48/49"

    _, old_full = app.test_client.get(
        "/dist/rules.sig", headers={"If-Match": old_etag}
    )
    assert old_full.status == 200
    assert old_full.body == V1


def test_repeated_gets_after_switch_never_mix(app):
    v2 = b"RULES-V2-" + b"A" * 50
    app.test_client.post("/__republish__", data=v2)
    for _ in range(5):
        _, resp = app.test_client.get(
            "/dist/rules.sig", headers={"Range": "bytes=0-9"}
        )
        assert resp.status == 206
        assert resp.body == v2[0:10]
        assert resp.headers["Content-Range"].endswith(f"/{len(v2)}")


# ---------------------------------------------------------------------------
# External replacement of the source path cannot affect sealed bytes
# ---------------------------------------------------------------------------
def test_external_source_replacement_ignored(app, tmp_path):
    app.ctx.src.write_bytes(b"outsider-overwrote-the-file" * 10)
    _, resp = app.test_client.get("/dist/rules.sig")
    assert resp.status == 200
    assert resp.body == V1


def test_tampered_store_blob_is_detected(app_and_registry):
    app, registry = app_and_registry
    version = registry.current("rules.sig")
    blob = registry._blob_path(version.digest)
    blob.chmod(0o644)
    blob.write_bytes(b"x" * (version.size + 5))

    _, resp = app.test_client.get("/dist/rules.sig")
    assert resp.status == 500


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------
def test_revoke_removes_alias(app):
    app.test_client.post("/__revoke__", data=b"")
    _, resp = app.test_client.get("/dist/rules.sig")
    assert resp.status == 404


def test_revoke_if_match_old_etag_is_412(app):
    _, first = app.test_client.get("/dist/rules.sig")
    etag = first.headers["ETag"]
    app.test_client.post("/__revoke__", data=b"")
    _, resp = app.test_client.get(
        "/dist/rules.sig", headers={"If-Match": etag}
    )
    assert resp.status == 412


def test_republish_after_revoke(app):
    app.test_client.post("/__revoke__", data=b"")
    _, gone = app.test_client.get("/dist/rules.sig")
    assert gone.status == 404

    app.test_client.post(
        "/__republish__", data=V1  # identical bytes
    )
    _, resp = app.test_client.get("/dist/rules.sig")
    assert resp.status == 200
    assert resp.body == V1


def test_distinct_aliases_distinct_log_basis(monkeypatch, app_and_registry):
    app, registry = app_and_registry
    # Same bytes under a second alias: content-addressed blob is shared but the
    # served version must report the requested alias in its access-log basis.
    asyncio.run(
        registry.publish("copy.sig", app.ctx.src)
    )
    access = Mock()
    monkeypatch.setattr(http1, "access_logger", access)
    app.test_client.get("/dist/copy.sig")
    request_line = access.info.call_args.kwargs["extra"]["request"]
    assert "artifact=copy.sig@" in request_line
    assert "rules.sig@" not in request_line


@pytest.mark.asyncio
async def test_inflight_request_survives_concurrent_revoke(app_and_registry):
    app, registry = app_and_registry
    version = registry.current("rules.sig")
    # Pin the descriptor (response headers about to be sent), then revoke.
    manager, handle = await registry._pin_handle(version)
    await registry.revoke("rules.sig")
    body = await handle.read()
    await manager.__aexit__(None, None, None)
    assert body == V1

    # A fresh open of the same version is a clean 410.
    with pytest.raises(ArtifactRevoked):
        await registry._open_blob(version)


def test_revoke_one_alias_keeps_shared_blob(app_and_registry):
    app, registry = app_and_registry
    asyncio.run(registry.publish("copy.sig", app.ctx.src))
    digest = registry.current("rules.sig").digest

    asyncio.run(registry.revoke("rules.sig"))
    _, gone = app.test_client.get("/dist/rules.sig")
    assert gone.status == 404
    # The other alias shares the content-addressed blob and stays live.
    _, alive = app.test_client.get("/dist/copy.sig")
    assert alive.status == 200
    assert alive.body == V1
    assert registry._blob_path(digest).exists()

    asyncio.run(registry.revoke(version=registry.current("copy.sig").version))
    assert not registry._blob_path(digest).exists()
    _, gone2 = app.test_client.get("/dist/copy.sig")
    assert gone2.status == 404


# ---------------------------------------------------------------------------
# Visible window sealing
# ---------------------------------------------------------------------------
def test_visible_window_publish(tmp_path):
    src = Path(tmp_path) / "big.bin"
    src.write_bytes(b"PREFIX-SECRET-SUFFIX")
    store = Path(tmp_path) / "store"
    app = Sanic("artifacts_window")
    app.config.ACCESS_LOG = True
    registry = app.artifact(
        "/dist", store, index_restore=False
    )

    @app.before_server_start
    async def _publish(app):
        await app.publish_artifact(
            "slice.bin", src, start=7, end=13
        )

    _, resp = app.test_client.get("/dist/slice.bin")
    assert resp.status == 200
    assert resp.body == b"SECRET"
    assert int(resp.headers["Content-Length"]) == 6


# ---------------------------------------------------------------------------
# Restart index recovery
# ---------------------------------------------------------------------------
def test_index_recovery_after_restart(tmp_path):
    store = Path(tmp_path) / "store"
    app1 = Sanic("artifacts_restart_1")
    app1.config.ACCESS_LOG = True
    reg1 = app1.artifact("/dist", store, index_restore=False)

    import asyncio

    src = Path(tmp_path) / "rules.sig"
    src.write_bytes(V1)
    asyncio.run(reg1.publish("rules.sig", src))

    app2 = Sanic("artifacts_restart_2")
    app2.config.ACCESS_LOG = True
    # Default index_restore=True registers a before_server_start recovery listener.
    reg2 = app2.artifact("/dist", store)

    _, resp = app2.test_client.get("/dist/rules.sig")
    assert resp.status == 200
    assert resp.body == V1
    assert resp.headers["X-Artifact-Version"] == reg1.current("rules.sig").version


def test_restore_missing_blob_raises(tmp_path):
    store = Path(tmp_path) / "store"
    reg = ArtifactRegistry(store)
    import asyncio

    src = Path(tmp_path) / "f"
    src.write_bytes(b"abc")
    asyncio.run(reg.restore())
    version = asyncio.run(reg.publish("a", src))
    reg._blob_path(version.digest).unlink()
    reg2 = ArtifactRegistry(store)
    with pytest.raises(ArtifactCorrupted):
        asyncio.run(reg2.restore())


def test_cross_registry_publish_visibility(tmp_path):
    import asyncio

    store = Path(tmp_path) / "store"
    src = Path(tmp_path) / "f"
    src.write_bytes(b"one")
    r1 = ArtifactRegistry(store)
    r2 = ArtifactRegistry(store)
    asyncio.run(r1.restore())
    asyncio.run(r2.restore())
    asyncio.run(r1.publish("a", src))
    assert asyncio.run(r2.sync_from_disk()) is True
    assert r2.current("a").size == 3
    src.write_bytes(b"four-four")
    asyncio.run(r1.publish("a", src))
    assert asyncio.run(r2.sync_from_disk()) is True
    assert r2.current("a").size == 9


# ---------------------------------------------------------------------------
# Access log records the version basis, never a local absolute path
# ---------------------------------------------------------------------------
def test_access_log_records_version_basis(monkeypatch, app_and_registry, tmp_path):
    app, registry = app_and_registry
    access = Mock()
    monkeypatch.setattr(http1, "access_logger", access)
    request, _ = app.test_client.get("/dist/rules.sig")
    assert access.info.called
    extra = access.info.call_args.kwargs["extra"]
    request_line = extra["request"]
    version = registry.current("rules.sig")
    assert f"artifact={version.basis}" in request_line
    assert str(tmp_path) not in request_line
    assert str(registry.store_dir) not in request_line


def test_access_log_basis_on_range(monkeypatch, app_and_registry):
    app, registry = app_and_registry
    access = Mock()
    monkeypatch.setattr(http1, "access_logger", access)
    app.test_client.get(
        "/dist/rules.sig", headers={"Range": "bytes=0-4"}
    )
    extra = access.info.call_args.kwargs["extra"]
    assert f"artifact={registry.current('rules.sig').basis}" in extra["request"]
