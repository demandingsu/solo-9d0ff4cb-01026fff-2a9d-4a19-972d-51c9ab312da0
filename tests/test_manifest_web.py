"""Web UI for ZIP verification: forms, manifest page, errors, staleness."""
from __future__ import annotations

import io
import sqlite3
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app

NUMBER = "ZFCG-2026-0001"


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _client(tmp_path: Path, demo):
    app = create_app(
        db_path=str(tmp_path / "web.db"),
        source_base_url="http://demo.test",
        source_client=demo,
    )
    return app, TestClient(app)


def test_verify_zip_via_web_shows_manifest(tmp_path, demo):
    app, client = _client(tmp_path, demo)
    client.post("/capture", data={"number": NUMBER})

    demo.post(
        f"/notice/{NUMBER}/attachment",
        files={"attachment": ("图纸.zip", _zip({"a/b.txt": b"hello"}),
                              "application/zip")},
        follow_redirects=False,
    )
    client.post("/capture", data={"number": NUMBER})

    resp = client.post(
        f"/notice/{NUMBER}/version/2/verify", follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"].endswith(
        f"/notice/{NUMBER}/version/2/manifest"
    )

    page = client.get(resp.headers["location"])
    assert page.status_code == 200
    text = page.text
    assert "附件核验目录" in text
    assert "a/b.txt" in text
    assert "核验通过" in text
    # Original attachment fingerprint is bound and shown.
    record = app.state.store.get_version(NUMBER, 2)
    assert record.attachment_sha256 in text


def test_verify_repeated_keeps_one_manifest_and_reuses(tmp_path, demo):
    app, client = _client(tmp_path, demo)
    client.post("/capture", data={"number": NUMBER})
    demo.post(
        f"/notice/{NUMBER}/attachment",
        files={"attachment": ("p.zip", _zip({"a.txt": b"x"}), "application/zip")},
        follow_redirects=False,
    )
    client.post("/capture", data={"number": NUMBER})

    first = client.post(f"/notice/{NUMBER}/version/2/verify")
    second = client.post(f"/notice/{NUMBER}/version/2/verify")
    assert first.status_code == second.status_code == 200

    conn = sqlite3.connect(app.state.store.db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM zip_manifests").fetchone()[0]
    finally:
        conn.close()
    assert count == 1


def test_non_zip_attachment_shows_unsupported_message(tmp_path, demo):
    app, client = _client(tmp_path, demo)
    client.post("/capture", data={"number": NUMBER})
    demo.post(
        f"/notice/{NUMBER}/attachment",
        files={"attachment": ("说明.txt", b"plain text not zip", "text/plain")},
        follow_redirects=False,
    )
    client.post("/capture", data={"number": NUMBER})

    resp = client.post(
        f"/notice/{NUMBER}/version/2/verify", follow_redirects=False
    )
    assert resp.status_code == 303
    page = client.get(resp.headers["location"])
    assert "不是 ZIP" in page.text or "不支持" in page.text

    # Manifest page reports no manifest rather than crashing.
    page = client.get(f"/notice/{NUMBER}/version/2/manifest")
    assert page.status_code == 404
    assert "尚无通过核验的目录" in page.text


def test_unsafe_zip_entry_is_rejected_without_partial_manifest(tmp_path, demo):
    app, client = _client(tmp_path, demo)
    client.post("/capture", data={"number": NUMBER})

    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as zf:
        zf.writestr("ok.txt", b"fine")
        zf.writestr("../escape.txt", b"bad")
    demo.post(
        f"/notice/{NUMBER}/attachment",
        files={"attachment": ("bad.zip", bad.getvalue(), "application/zip")},
        follow_redirects=False,
    )
    client.post("/capture", data={"number": NUMBER})

    resp = client.post(
        f"/notice/{NUMBER}/version/2/verify", follow_redirects=False
    )
    page = client.get(resp.headers["location"])
    assert ".. 路径段" in page.text

    conn = sqlite3.connect(app.state.store.db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM zip_manifests").fetchone()[0] == 0
        assert conn.execute(
            "SELECT COUNT(*) FROM zip_manifest_entries"
        ).fetchone()[0] == 0
    finally:
        conn.close()


def test_manifest_page_flags_stale_fingerprint(tmp_path, demo):
    app, client = _client(tmp_path, demo)
    client.post("/capture", data={"number": NUMBER})
    demo.post(
        f"/notice/{NUMBER}/attachment",
        files={"attachment": ("p.zip", _zip({"a.txt": b"x"}), "application/zip")},
        follow_redirects=False,
    )
    client.post("/capture", data={"number": NUMBER})
    client.post(f"/notice/{NUMBER}/version/2/verify")

    # Tamper with the stored blob behind the recorded fingerprint's back.
    conn = sqlite3.connect(app.state.store.db_path)
    conn.execute(
        "UPDATE versions SET attachment_blob = ? WHERE announcement_number = ? "
        "AND revision = 2",
        (sqlite3.Binary(b"tampered"), NUMBER),
    )
    conn.commit()
    conn.close()

    page = client.get(f"/notice/{NUMBER}/version/2/manifest")
    assert page.status_code == 409
    assert "失效" in page.text

    # Re-verification also refuses and keeps the old, now-invalid row.
    resp = client.post(
        f"/notice/{NUMBER}/version/2/verify", follow_redirects=False
    )
    page = client.get(resp.headers["location"])
    assert "不符" in page.text


def test_notice_page_links_to_manifests_and_version_page_has_verify(tmp_path, demo):
    _, client = _client(tmp_path, demo)
    client.post("/capture", data={"number": NUMBER})
    demo.post(
        f"/notice/{NUMBER}/attachment",
        files={"attachment": ("p.zip", _zip({"a.txt": b"x"}), "application/zip")},
        follow_redirects=False,
    )
    client.post("/capture", data={"number": NUMBER})
    client.post(f"/notice/{NUMBER}/version/2/verify")

    notice = client.get(f"/notice/{NUMBER}").text
    assert "核验目录" in notice
    assert "已核验 · 1 项" in notice
    assert f"/notice/{NUMBER}/version/2/manifest" in notice

    version = client.get(f"/notice/{NUMBER}/version/2").text
    assert "核验 ZIP 附件" in version
    assert f"/notice/{NUMBER}/version/2/manifest" in version


def test_verify_unknown_version_404(tmp_path, demo):
    _, client = _client(tmp_path, demo)
    client.post("/capture", data={"number": NUMBER})
    resp = client.post(
        f"/notice/{NUMBER}/version/99/verify", follow_redirects=False
    )
    # Redirects back to the notice with an error because the version is missing.
    page = client.get(resp.headers["location"])
    assert "该版本不存在" in page.text


def test_download_and_capture_still_work_alongside_manifest(tmp_path, demo):
    _, client = _client(tmp_path, demo)
    client.post("/capture", data={"number": NUMBER})
    demo.post(
        f"/notice/{NUMBER}/attachment",
        files={"attachment": ("p.zip", _zip({"a.txt": b"x"}), "application/zip")},
        follow_redirects=False,
    )
    client.post("/capture", data={"number": NUMBER})
    client.post(f"/notice/{NUMBER}/version/2/verify")

    download = client.get(f"/notice/{NUMBER}/version/1/attachment")
    assert download.status_code == 200
    assert download.headers["x-content-sha256"]
    # Health and home remain fine.
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/").status_code == 200
