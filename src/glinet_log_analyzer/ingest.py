from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


TEXT_EXTENSIONS = {
    ".log",
    ".txt",
    ".out",
    ".json",
    ".cfg",
    ".conf",
    ".messages",
}

LIKELY_LOG_NAMES = (
    "log",
    "syslog",
    "messages",
    "dnsmasq",
    "netifd",
    "hostapd",
    "firewall",
    "dropbear",
    "wg",
    "openvpn",
    "modem",
    "mwan3",
    "network",
)


@dataclass(slots=True)
class LogDocument:
    source: str
    text: str


def load_documents_from_path(path: Path) -> list[LogDocument]:
    raw = path.read_bytes()
    return load_documents_from_bytes(path.name, raw)


def load_documents_from_bytes(filename: str, raw: bytes) -> list[LogDocument]:
    suffixes = [part.lower() for part in Path(filename).suffixes]
    normalized = filename.lower()

    if normalized.endswith(".tar.gz") or normalized.endswith(".tgz"):
        return _load_from_tar(raw, mode="r:gz", archive_name=filename)
    if normalized.endswith(".tar"):
        return _load_from_tar(raw, mode="r:", archive_name=filename)
    if suffixes and suffixes[-1] == ".zip":
        return _load_from_zip(raw, archive_name=filename)
    if suffixes and suffixes[-1] == ".gz":
        text = gzip.decompress(raw).decode("utf-8", errors="replace")
        return [LogDocument(source=filename.removesuffix(".gz"), text=text)]
    return [LogDocument(source=filename, text=raw.decode("utf-8", errors="replace"))]


def _load_from_zip(raw: bytes, archive_name: str) -> list[LogDocument]:
    documents: list[LogDocument] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name in archive.namelist():
            if name.endswith("/"):
                continue
            if not _is_likely_log_file(name):
                continue
            text = archive.read(name).decode("utf-8", errors="replace")
            documents.append(LogDocument(source=f"{archive_name}:{name}", text=text))
    return documents or [LogDocument(source=archive_name, text="")]


def _load_from_tar(raw: bytes, mode: str, archive_name: str) -> list[LogDocument]:
    documents: list[LogDocument] = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode=mode) as archive:
        for member in archive.getmembers():
            if not member.isfile() or not _is_likely_log_file(member.name):
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            text = extracted.read().decode("utf-8", errors="replace")
            documents.append(LogDocument(source=f"{archive_name}:{member.name}", text=text))
    return documents or [LogDocument(source=archive_name, text="")]


def _is_likely_log_file(name: str) -> bool:
    lowered = name.lower()
    path = Path(lowered)
    if any(part in lowered for part in LIKELY_LOG_NAMES):
        return True
    return any(lowered.endswith(ext) for ext in TEXT_EXTENSIONS) or path.suffix == ""
