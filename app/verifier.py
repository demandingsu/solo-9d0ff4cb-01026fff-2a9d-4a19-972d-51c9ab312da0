"""ZIP verification and auditable manifest building.

The verifier never extracts files to disk. It reads each entry in memory in
chunks, validates its name, size and integrity, and computes a per-entry
SHA-256. A manifest is only returned when every entry passes; otherwise the
caller gets an exception and no partial manifest can be stored.

Security rules (all enforced before any entry is trusted):

* the attachment is only accepted when it is really a ZIP (magic bytes);
* entry names must not be absolute, contain ``..`` segments, drive letters,
  NUL/control characters, or normalize to a duplicate of another entry;
* backslashes are folded to forward slashes and leading ``./`` is removed, so
  every recorded path uses one separator and one canonical spelling;
* encrypted entries (including ZipCrypto and AES extra fields) are rejected;
* CRC failures, truncated data and any other zipfile error are rejected;
* more than ``max_files`` file entries or more than ``max_total_bytes`` of
  uncompressed data reject the whole archive.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile

from .domain import (
    AttachmentFingerprintMismatch,
    CorruptZip,
    EncryptedZipEntry,
    ManifestEntry,
    ManifestNotFound,
    ManifestResult,
    NotZipAttachment,
    UnsafeZipEntry,
    ZipLimitExceeded,
    sha256_bytes,
    utc_now_iso,
)
from .store import ArchiveStore

ZIP_MAGIC = b"PK\x03\x04"
EMPTY_ZIP_MAGIC = b"PK\x05\x06"  # empty/spanned archives start with EOCD
SPAN_MAGIC = b"PK\x07\x08"
MAX_MANIFEST_FILES = 500
MAX_MANIFEST_TOTAL_BYTES = 64 * 1024 * 1024  # 64 MiB
_READ_CHUNK = 1024 * 1024

# General purpose bit flag: bit 0 = encrypted; bit 6 = strong encryption.
_ENCRYPTED_FLAGS = 0b1 | 0b1000000
# WinZip AES marker in the extra field header (0x9901, little-endian id).
_AES_EXTRA_ID = b"\x01\x99"


def _quote_name(name: str) -> str:
    """Wrap an untrusted entry name in Chinese quotes for display."""
    return f"「{name}」"


def normalize_member_name(raw_name: str) -> str:
    """Fold separators and ``./`` away, or reject an unsafe entry name.

    Directory entries keep a single trailing slash. File entries never end
    with a slash. The returned spelling is what gets stored in the manifest.
    """
    if not raw_name or "\x00" in raw_name:
        raise UnsafeZipEntry("ZIP 条目名为空或包含 NUL 字符，已拒绝。")
    if any(ord(ch) < 32 for ch in raw_name):
        raise UnsafeZipEntry(
            f"ZIP 条目名 {_quote_name(raw_name)} 含控制字符，已拒绝。"
        )

    name = raw_name.replace("\\", "/")

    # Windows drive prefixes (C: or C:/).
    drive, rest = name[:1], name[1:2]
    if drive.isalpha() and rest == ":":
        raise UnsafeZipEntry(
            f"ZIP 条目名 {_quote_name(raw_name)} 含盘符，已拒绝。"
        )

    is_directory = name.endswith("/")
    segments = [segment for segment in name.split("/") if segment not in ("", ".")]

    if any(segment == ".." for segment in segments):
        raise UnsafeZipEntry(
            f"ZIP 条目名 {_quote_name(raw_name)} 含 .. 路径段，已拒绝。"
        )
    if not segments:
        raise UnsafeZipEntry(
            f"ZIP 条目名 {_quote_name(raw_name)} 规范化后为空，已拒绝。"
        )

    # A leading slash made the first real segment look normal; reject it
    # explicitly because absolute paths must never appear in a manifest.
    if name.startswith("/"):
        raise UnsafeZipEntry(
            f"ZIP 条目名 {_quote_name(raw_name)} 是绝对路径，已拒绝。"
        )

    normalized = "/".join(segments)
    if is_directory:
        return normalized + "/"
    return normalized


def _is_encrypted(info: zipfile.ZipInfo) -> bool:
    if info.flag_bits & _ENCRYPTED_FLAGS:
        return True
    extra = info.extra
    if isinstance(extra, (bytes, bytearray)) and _AES_EXTRA_ID in extra:
        return True
    return False


def verify_zip_blob(
    blob: bytes,
    *,
    max_files: int = MAX_MANIFEST_FILES,
    max_total_bytes: int = MAX_MANIFEST_TOTAL_BYTES,
) -> tuple[list[ManifestEntry], int]:
    """Validate a ZIP blob and return its entries plus uncompressed total.

    Raises a :class:`ManifestError` subclass for every rejection. Nothing is
    written to disk and no partial result is returned.
    """
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 4:
        raise NotZipAttachment("附件不是 ZIP 压缩包（缺少 ZIP 签名），不支持核验。")
    prefix = bytes(blob[:4])
    if not (
        prefix.startswith(ZIP_MAGIC)
        or prefix.startswith(EMPTY_ZIP_MAGIC)
        or prefix.startswith(SPAN_MAGIC)
    ):
        raise NotZipAttachment("附件不是 ZIP 压缩包（魔数不符），不支持核验。")

    try:
        zf = zipfile.ZipFile(io.BytesIO(bytes(blob)))
    except (zipfile.BadZipFile, OSError) as exc:
        raise CorruptZip(f"ZIP 结构损坏，无法打开：{exc}；已拒绝。") from exc

    entries: list[ManifestEntry] = []
    seen_paths: set[str] = set()
    total = 0
    try:
        infos = zf.infolist()
        for info in infos:
            normalized = normalize_member_name(info.filename)

            if info.is_dir():
                # Directories are structural entries: validate the name but do
                # not count them against the file limit and do not hash them.
                if normalized in seen_paths:
                    raise UnsafeZipEntry(
                        f"ZIP 目录条目规范化后重名：{normalized}，已拒绝。"
                    )
                seen_paths.add(normalized)
                continue

            if normalized in seen_paths:
                raise UnsafeZipEntry(
                    f"ZIP 条目规范化后路径重名：{normalized}，已拒绝。"
                )
            if len(entries) >= max_files:
                raise ZipLimitExceeded(
                    f"ZIP 文件条目超过 {max_files} 个上限，未生成部分目录。"
                )
            if info.file_size < 0 or info.compress_size < 0:
                raise CorruptZip(
                    f"ZIP 条目 {_quote_name(info.filename)} 大小声明异常，已拒绝。"
                )
            if total + info.file_size > max_total_bytes or (
                info.file_size > max_total_bytes
            ):
                raise ZipLimitExceeded(
                    "ZIP 实际解压总量超过 64 MiB 上限，未生成部分目录。"
                )
            if _is_encrypted(info):
                raise EncryptedZipEntry(
                    f"ZIP 条目 {_quote_name(info.filename)} 已加密，档案员无法读取，已拒绝。"
                )

            digest = hashlib.sha256()
            written = 0
            try:
                with zf.open(info, mode="r") as member:
                    while True:
                        chunk = member.read(_READ_CHUNK)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > max_total_bytes or (
                            total + written > max_total_bytes
                        ):
                            raise ZipLimitExceeded(
                                "ZIP 实际解压总量超过 64 MiB 上限，"
                                "未生成部分目录。"
                            )
                        digest.update(chunk)
            except ZipLimitExceeded:
                raise
            except (zipfile.BadZipFile, RuntimeError, OSError, EOFError) as exc:
                # RuntimeError covers "Compressed size exceeded" / bad CRC
                # surfaces raised by zipfile's own checks.
                raise CorruptZip(
                    f"ZIP 条目 {_quote_name(info.filename)} 已损坏或无法读取：{exc}；"
                    "整包已拒绝。"
                ) from exc

            if written != info.file_size:
                raise CorruptZip(
                    f"ZIP 条目 {_quote_name(info.filename)} 实际大小与声明不符"
                    f"（{written} != {info.file_size}），整包已拒绝。"
                )

            seen_paths.add(normalized)
            total += written
            entries.append(
                ManifestEntry(
                    path=normalized,
                    size=written,
                    sha256=digest.hexdigest(),
                )
            )
    finally:
        zf.close()

    return entries, total


def compute_manifest_hash(
    *,
    number: str,
    revision: int,
    attachment_sha256: str,
    attachment_size: int,
    entries: list[ManifestEntry],
) -> str:
    """Fingerprint the whole directory, binding it to its attachment.

    The hash covers the announcement number, revision, original attachment
    fingerprint and every recorded entry, so a manifest can always be checked
    against the bytes it was built from.
    """
    payload = {
        "announcement_number": number,
        "revision": revision,
        "attachment": {
            "sha256": attachment_sha256,
            "size": attachment_size,
        },
        "entries": [
            {"path": e.path, "size": e.size, "sha256": e.sha256}
            for e in entries
        ],
    }
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256_bytes(encoded)


class ManifestService:
    """Application service: verify a stored attachment and persist its manifest."""

    def __init__(self, store: ArchiveStore):
        self.store = store

    def verify(self, number: str, revision: int) -> ManifestResult:
        record = self.store.get_version(number, revision)
        if record is None:
            raise ManifestNotFound("该版本不存在，无法核验附件。")

        actual_attachment_sha = sha256_bytes(record.attachment_blob)
        if actual_attachment_sha != record.attachment_sha256:
            # The immutable version row no longer matches its own bytes:
            # refuse to build anything and surface the integrity failure.
            raise AttachmentFingerprintMismatch(
                "存档附件字节与其登记的 SHA-256 不符，附件完整性已破坏，"
                "拒绝核验；请检查档案存储。"
            )

        existing = self.store.get_manifest(number, revision)
        if existing is not None:
            if existing.attachment_sha256 != actual_attachment_sha:
                raise AttachmentFingerprintMismatch(
                    "已有目录绑定的附件指纹与当前附件字节不符，旧目录失效，"
                    "未生成新目录。"
                )
            self.store.log_event(
                number,
                "manifest_reused",
                f"r{revision} 附件目录已存在且指纹一致，直接重开同一份目录。",
                revision,
            )
            return existing

        entries, total = verify_zip_blob(record.attachment_blob)
        manifest_hash = compute_manifest_hash(
            number=number,
            revision=revision,
            attachment_sha256=actual_attachment_sha,
            attachment_size=record.attachment_size,
            entries=entries,
        )
        result = ManifestResult(
            number=number,
            revision=revision,
            attachment_sha256=actual_attachment_sha,
            attachment_size=record.attachment_size,
            entry_count=len(entries),
            total_uncompressed=total,
            manifest_sha256=manifest_hash,
            entries=entries,
            verified_at=utc_now_iso(),
        )
        try:
            stored = self.store.insert_manifest(result)
        except Exception:
            # A concurrent verification may have committed the same manifest
            # first. Re-read instead of failing the archivist's request.
            stored = self.store.get_manifest(number, revision)
            if stored is None:
                raise
            if stored.attachment_sha256 != actual_attachment_sha:
                raise AttachmentFingerprintMismatch(
                    "并发核验写入的目录绑定了不同附件指纹，旧目录失效。"
                )
            return stored

        self.store.log_event(
            number,
            "manifest_created",
            f"r{revision} 附件核验通过：{stored.entry_count} 个条目，"
            f"解压总量 {stored.total_uncompressed} 字节，"
            f"目录指纹 {stored.manifest_sha256[:16]}…",
            revision,
        )
        return stored

    def open_manifest(self, number: str, revision: int) -> ManifestResult:
        """Return a stored manifest, flagging it if its bytes no longer match."""
        record = self.store.get_version(number, revision)
        if record is None:
            raise ManifestNotFound("该版本不存在。")
        manifest = self.store.get_manifest(number, revision)
        if manifest is None:
            raise ManifestNotFound("该版本附件尚未核验，暂无目录。")

        actual = sha256_bytes(record.attachment_blob)
        stale_reasons: list[str] = []
        if actual != record.attachment_sha256:
            stale_reasons.append("附件字节与版本登记指纹不符")
        if actual != manifest.attachment_sha256:
            stale_reasons.append("附件字节与目录绑定指纹不符，旧目录已失效")
        if stale_reasons:
            raise AttachmentFingerprintMismatch("；".join(stale_reasons) + "。")
        return manifest
