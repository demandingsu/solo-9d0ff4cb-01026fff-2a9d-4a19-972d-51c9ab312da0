"""ZIP verification and manifest behaviour.

Covers the happy path, every rejection class, idempotency, concurrency,
fingerprint staleness and the interleaving of verification with new captures.
"""
from __future__ import annotations

import hashlib
import io
import threading
import zipfile

import pytest

from app.capture import CaptureService
from app.domain import (
    AttachmentFingerprintMismatch,
    CorruptZip,
    EncryptedZipEntry,
    ManifestNotFound,
    NotZipAttachment,
    UnsafeZipEntry,
    ZipLimitExceeded,
    sha256_bytes,
)
from app.source import HttpSourceClient
from app.verifier import (
    ManifestService,
    compute_manifest_hash,
    normalize_member_name,
    verify_zip_blob,
)

NUMBER = "ZFCG-2026-0001"


# ------------------------------------------------------------- zip fixtures

def make_zip(members: dict[str, bytes], *, raw_names: dict[str, str] | None = None) -> bytes:
    """Build an in-memory ZIP. ``raw_names`` maps stored path -> on-disk name."""
    raw_names = raw_names or {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in members.items():
            zf.writestr(raw_names.get(path, path), data)
    return buf.getvalue()


def flip_encrypted_flag(blob: bytes) -> bytes:
    """Turn a valid ZIP into one whose every entry claims to be encrypted."""
    data = bytearray(blob)
    local_sig = b"PK\x03\x04"
    central_sig = b"PK\x01\x02"
    start = 0
    while True:
        idx = data.find(local_sig, start)
        if idx < 0:
            break
        flag_pos = idx + 6
        data[flag_pos] |= 0x01
        start = idx + 4
    start = 0
    while True:
        idx = data.find(central_sig, start)
        if idx < 0:
            break
        flag_pos = idx + 8
        data[flag_pos] |= 0x01
        start = idx + 4
    return bytes(data)


def corrupt_zip_payload(blob: bytes) -> bytes:
    """Flip bytes inside the first local file's compressed data."""
    data = bytearray(blob)
    idx = data.find(b"PK\x03\x04")
    assert idx >= 0
    # Local header is 30 bytes + name + extra; mutate well past it.
    target = idx + 60
    data[target] ^= 0xFF
    data[target + 1] ^= 0xAA
    return bytes(data)


# ------------------------------------------------------- path normalization

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("a/b.txt", "a/b.txt"),
        ("./a/b.txt", "a/b.txt"),
        ("a/./b.txt", "a/b.txt"),
        ("a//b.txt", "a/b.txt"),
        ("./a/./b/", "a/b/"),
        ("dir/", "dir/"),
        ("a\\b\\c.txt", "a/b/c.txt"),
        (".\\a\\b.txt", "a/b.txt"),
        ("图纸/总图.dwg", "图纸/总图.dwg"),
    ],
)
def test_normalize_member_name_folds_separators_and_dot(raw, expected):
    assert normalize_member_name(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "/etc/passwd",
        "/a.txt",
        "../a.txt",
        "a/../../b.txt",
        "a/../b/../../c",
        "..",
        "../",
        "C:/Windows/a.txt",
        "c:windows",
        "a/\x00b",
        "a/\tb",
        "",
        "./",
        ".",
    ],
)
def test_normalize_member_name_rejects_unsafe(raw):
    with pytest.raises(UnsafeZipEntry):
        normalize_member_name(raw)


# ----------------------------------------------------------------- verifier

def test_verify_happy_path_lists_entries_with_size_and_sha():
    members = {
        "图纸/总图.dwg": b"drawing-one" * 100,
        "清单.xlsx": b"spreadsheet-bytes",
        "readme.txt": "中文说明".encode(),
    }
    blob = make_zip(members)
    entries, total = verify_zip_blob(blob)

    assert [e.path for e in entries] == list(members.keys())
    assert total == sum(len(v) for v in members.values())
    for entry, (path, data) in zip(entries, members.items()):
        assert entry.path == path
        assert entry.size == len(data)
        assert entry.sha256 == hashlib.sha256(data).hexdigest()


def test_verify_folds_dot_slash_and_backslash_in_stored_paths():
    blob = make_zip(
        {"a/b.txt": b"x", "c/d.txt": b"y"},
        raw_names={"a/b.txt": "./a/b.txt", "c/d.txt": ".\\c\\d.txt"},
    )
    entries, _ = verify_zip_blob(blob)
    assert [e.path for e in entries] == ["a/b.txt", "c/d.txt"]


def test_verify_directory_entries_are_validated_but_not_listed():
    # Add an explicit directory entry.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("dir/", "")
        zf.writestr("dir/note.txt", b"x")
    entries, total = verify_zip_blob(buf.getvalue())
    assert [e.path for e in entries] == ["dir/note.txt"]
    assert total == 1


def test_verify_rejects_non_zip_by_magic():
    with pytest.raises(NotZipAttachment):
        verify_zip_blob(b"this is plain text, not a zip")
    with pytest.raises(NotZipAttachment):
        verify_zip_blob(b"")
    with pytest.raises(NotZipAttachment):
        verify_zip_blob(b"PK")  # too short


def test_verify_rejects_absolute_and_parent_paths():
    blob = make_zip({"/tmp/evil.txt": b"x"})
    with pytest.raises(UnsafeZipEntry):
        verify_zip_blob(blob)

    blob2 = make_zip({"../escape.txt": b"x"})
    with pytest.raises(UnsafeZipEntry):
        verify_zip_blob(blob2)


def test_verify_rejects_duplicate_names_after_normalization():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a/b.txt", b"one")
        zf.writestr("./a/b.txt", b"two")
    with pytest.raises(UnsafeZipEntry, match="重名"):
        verify_zip_blob(buf.getvalue())


def test_verify_rejects_backslash_duplicate_after_folding():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a/b.txt", b"one")
        zf.writestr("a\\b.txt", b"two")
    with pytest.raises(UnsafeZipEntry):
        verify_zip_blob(buf.getvalue())


def test_verify_rejects_encrypted_entry():
    encrypted_blob = flip_encrypted_flag(make_zip({"secret.txt": b"topsecret"}))
    with pytest.raises(EncryptedZipEntry):
        verify_zip_blob(encrypted_blob)


def test_verify_rejects_corrupt_entry_bad_crc():
    blob = corrupt_zip_payload(make_zip({"a.txt": b"payload" * 50}))
    with pytest.raises(CorruptZip):
        verify_zip_blob(blob)


def test_verify_rejects_truncated_archive():
    blob = make_zip({"a.txt": b"payload" * 50})
    with pytest.raises((CorruptZip, NotZipAttachment)):
        verify_zip_blob(blob[: len(blob) // 2])


def test_verify_rejects_too_many_files():
    members = {f"f{i}.txt": b"x" for i in range(5)}
    blob = make_zip(members)
    with pytest.raises(ZipLimitExceeded, match="500|上限"):
        verify_zip_blob(blob, max_files=4)
    # Exactly the limit passes.
    entries, _ = verify_zip_blob(blob, max_files=5)
    assert len(entries) == 5


def test_verify_rejects_uncompressed_total_over_limit():
    members = {"big.bin": b"x" * 1000, "small.txt": b"y"}
    blob = make_zip(members)
    with pytest.raises(ZipLimitExceeded, match="64 MiB|上限"):
        verify_zip_blob(blob, max_total_bytes=500)


def test_verify_empty_zip_is_valid_manifest_with_no_entries():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    entries, total = verify_zip_blob(buf.getvalue())
    assert entries == []
    assert total == 0


def test_verify_rejects_spoofed_huge_declared_size():
    """A header claiming >64 MiB uncompressed must be rejected pre-read."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("bomb.bin", b"small")
    blob = bytearray(buf.getvalue())
    huge = (64 * 1024 * 1024 + 10).to_bytes(4, "little")
    central = blob.find(b"PK\x01\x02")
    blob[central + 24 : central + 28] = huge
    local = blob.find(b"PK\x03\x04")
    blob[local + 18 : local + 22] = huge
    with pytest.raises(ZipLimitExceeded):
        verify_zip_blob(bytes(blob))


def test_manifest_hash_binds_number_revision_and_attachment():
    entries, total = verify_zip_blob(make_zip({"a.txt": b"x"}))
    h1 = compute_manifest_hash(
        number="N1", revision=1, attachment_sha256="a" * 64,
        attachment_size=10, entries=entries,
    )
    h2 = compute_manifest_hash(
        number="N2", revision=1, attachment_sha256="a" * 64,
        attachment_size=10, entries=entries,
    )
    h3 = compute_manifest_hash(
        number="N1", revision=2, attachment_sha256="a" * 64,
        attachment_size=10, entries=entries,
    )
    h4 = compute_manifest_hash(
        number="N1", revision=1, attachment_sha256="b" * 64,
        attachment_size=10, entries=entries,
    )
    assert len({h1, h2, h3, h4}) == 4


# ------------------------------------------------------- service + storage

@pytest.fixture()
def service(store, demo) -> ManifestService:
    CaptureService(
        store, HttpSourceClient("http://demo.test", client=demo)
    ).capture(NUMBER)
    return ManifestService(store)


def _replace_demo_attachment(demo, blob: bytes, filename: str = "图纸.zip"):
    response = demo.post(
        f"/notice/{NUMBER}/attachment",
        files={"attachment": (filename, blob, "application/zip")},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_service_verify_creates_persisted_manifest(store, service, demo):
    capture = CaptureService(
        store, HttpSourceClient("http://demo.test", client=demo)
    )
    _replace_demo_attachment(
        demo, make_zip({"图纸/总图.dwg": b"abc", "清单.txt": b"123"})
    )
    record_rev = capture.capture(NUMBER).revision
    record = store.get_version(NUMBER, record_rev)

    result = service.verify(NUMBER, record.revision)
    assert result.entry_count == 2
    assert result.attachment_sha256 == record.attachment_sha256
    assert result.manifest_sha256

    # Reopen from a brand-new service instance: it is durable and rebinds.
    again = ManifestService(store).open_manifest(NUMBER, record.revision)
    assert again.manifest_sha256 == result.manifest_sha256
    assert [e.path for e in again.entries] == ["图纸/总图.dwg", "清单.txt"]
    assert again.entries[0].sha256 == hashlib.sha256(b"abc").hexdigest()


def test_unknown_version_raises(store, service):
    with pytest.raises(ManifestNotFound):
        service.verify(NUMBER, 999)
    with pytest.raises(ManifestNotFound):
        service.open_manifest(NUMBER, 1)


def test_non_zip_attachment_is_unsupported(store, service, demo):
    # The service fixture already archived r1; publish a non-ZIP attachment.
    _replace_demo_attachment(demo, b"not a zip at all", filename="说明.txt")
    capture = CaptureService(
        store, HttpSourceClient("http://demo.test", client=demo)
    )
    result = capture.capture(NUMBER)
    with pytest.raises(NotZipAttachment, match="不是 ZIP"):
        service.verify(NUMBER, result.revision)
    # No manifest row was created.
    assert store.get_manifest(NUMBER, result.revision) is None


def test_repeated_verify_returns_same_single_manifest(store, service, demo):
    _replace_demo_attachment(demo, make_zip({"a.txt": b"x"}))
    capture = CaptureService(
        store, HttpSourceClient("http://demo.test", client=demo)
    )
    result = capture.capture(NUMBER)

    first = service.verify(NUMBER, result.revision)
    second = service.verify(NUMBER, result.revision)
    third = service.verify(NUMBER, result.revision)
    assert first.manifest_sha256 == second.manifest_sha256 == third.manifest_sha256
    assert first.verified_at == second.verified_at

    import sqlite3
    conn = sqlite3.connect(store.db_path)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM zip_manifests WHERE announcement_number = ?",
            (NUMBER,),
        ).fetchone()[0]
        entry_rows = conn.execute(
            "SELECT COUNT(*) FROM zip_manifest_entries"
        ).fetchone()[0]
    finally:
        conn.close()
    assert count == 1
    assert entry_rows == 1


def test_concurrent_verify_keeps_one_manifest(store, demo):
    capture = CaptureService(
        store, HttpSourceClient("http://demo.test", client=demo)
    )
    capture.capture(NUMBER)
    _replace_demo_attachment(demo, make_zip({f"f{i}.txt": b"x" for i in range(20)}))
    result = capture.capture(NUMBER)

    errors: list[Exception] = []
    results: list = []
    barrier = threading.Barrier(4)

    def worker():
        local_service = ManifestService(store)
        barrier.wait()
        try:
            results.append(local_service.verify(NUMBER, result.revision))
        except Exception as exc:  # pragma: no cover - surfaced via assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(results) == 4
    assert len({r.manifest_sha256 for r in results}) == 1

    import sqlite3
    conn = sqlite3.connect(store.db_path)
    try:
        count = conn.execute(
            "SELECT COUNT(*) FROM zip_manifests WHERE announcement_number = ? "
            "AND revision = ?",
            (NUMBER, result.revision),
        ).fetchone()[0]
    finally:
        conn.close()
    assert count == 1


def test_new_revision_does_not_change_old_manifest(store, service, demo):
    capture = CaptureService(
        store, HttpSourceClient("http://demo.test", client=demo)
    )
    _replace_demo_attachment(demo, make_zip({"v1/a.txt": b"one"}))
    r1 = capture.capture(NUMBER)
    first = service.verify(NUMBER, r1.revision)

    _replace_demo_attachment(demo, make_zip({"v2/b.txt": b"two"}))
    r2 = capture.capture(NUMBER)
    second = service.verify(NUMBER, r2.revision)

    assert r1.revision != r2.revision
    old = service.open_manifest(NUMBER, r1.revision)
    assert old.manifest_sha256 == first.manifest_sha256
    assert [e.path for e in old.entries] == ["v1/a.txt"]
    assert [e.path for e in second.entries] == ["v2/b.txt"]


def test_stale_manifest_when_attachment_bytes_change_under_fingerprint(
    store, service, demo
):
    capture = CaptureService(
        store, HttpSourceClient("http://demo.test", client=demo)
    )
    _replace_demo_attachment(demo, make_zip({"a.txt": b"original"}))
    rev = capture.capture(NUMBER).revision
    service.verify(NUMBER, rev)

    # Simulate storage tampering: overwrite the immutable blob with different
    # bytes while leaving the recorded fingerprint row untouched.
    import sqlite3
    conn = sqlite3.connect(store.db_path)
    conn.execute(
        "UPDATE versions SET attachment_blob = ? WHERE announcement_number = ? "
        "AND revision = ?",
        (sqlite3.Binary(b"tampered bytes"), NUMBER, rev),
    )
    conn.commit()
    conn.close()

    with pytest.raises(AttachmentFingerprintMismatch, match="失效|不符"):
        service.open_manifest(NUMBER, rev)
    with pytest.raises(AttachmentFingerprintMismatch):
        service.verify(NUMBER, rev)


def test_manifest_rejection_leaves_no_partial_rows(store, service, demo):
    capture = CaptureService(
        store, HttpSourceClient("http://demo.test", client=demo)
    )
    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("ok.txt", b"fine")
        zf.writestr("../escape.txt", b"nope")
    _replace_demo_attachment(demo, bad.getvalue())
    rev = capture.capture(NUMBER).revision

    with pytest.raises(UnsafeZipEntry):
        service.verify(NUMBER, rev)
    assert store.get_manifest(NUMBER, rev) is None

    import sqlite3
    conn = sqlite3.connect(store.db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM zip_manifests").fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM zip_manifest_entries"
        ).fetchone()[0] == 0
    finally:
        conn.close()


def test_interleaved_capture_and_verify(store, service, demo):
    """Verification of an old revision stays valid while new revisions land."""
    capture = CaptureService(
        store, HttpSourceClient("http://demo.test", client=demo)
    )
    _replace_demo_attachment(demo, make_zip({"r1/a.txt": b"1"}))
    r1 = capture.capture(NUMBER).revision
    manifest_r1 = service.verify(NUMBER, r1)

    # A new revision with a non-ZIP attachment: its verification must fail,
    # while the r1 manifest remains fully openable and unchanged.
    _replace_demo_attachment(demo, b"plain text, definitely not zip", "说明.txt")
    r2 = capture.capture(NUMBER).revision
    with pytest.raises(NotZipAttachment):
        service.verify(NUMBER, r2)

    reopened = service.open_manifest(NUMBER, r1)
    assert reopened.manifest_sha256 == manifest_r1.manifest_sha256
    assert reopened.attachment_sha256 == manifest_r1.attachment_sha256

    # And a third revision with a valid ZIP gets its own independent manifest.
    _replace_demo_attachment(demo, make_zip({"r3/c.txt": b"3"}))
    r3 = capture.capture(NUMBER).revision
    manifest_r3 = service.verify(NUMBER, r3)
    assert manifest_r3.manifest_sha256 != manifest_r1.manifest_sha256
    assert service.open_manifest(NUMBER, r1).entries[0].path == "r1/a.txt"


def test_manifest_hash_matches_recomputed_value(store, service, demo):
    capture = CaptureService(
        store, HttpSourceClient("http://demo.test", client=demo)
    )
    _replace_demo_attachment(demo, make_zip({"a.txt": b"hello"}))
    rev = capture.capture(NUMBER).revision
    result = service.verify(NUMBER, rev)

    record = store.get_version(NUMBER, rev)
    expected = compute_manifest_hash(
        number=NUMBER,
        revision=rev,
        attachment_sha256=record.attachment_sha256,
        attachment_size=record.attachment_size,
        entries=result.entries,
    )
    assert result.manifest_sha256 == expected
    assert sha256_bytes(record.attachment_blob) == result.attachment_sha256
