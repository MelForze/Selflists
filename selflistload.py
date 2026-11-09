#!/usr/bin/env python3
"""Organize wordlists and port sets in ~/selflists; prepare admin tools in ~/winbins."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import heapq
import http.client
import io
import itertools
import json
import lzma
import math
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
import zlib
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib import error, request


APP_DIR = Path.home() / "selflists"
WINBINS_DIR = Path.home() / "winbins"
META_FILE = ".selflistload_state.json"
OUT_DNS_FILE = "dns/biggest_dnslist.txt"
OUT_WEB_FILE = "web/biggest_weblist.txt"
USER_AGENT = "selflistload/0.4.0"
HTTP_TIMEOUT = 30
HTTP_RETRIES = 3
RETRY_DELAY_SEC = 2
NCAT_PORTABLE_URL = "https://nmap.org/dist/ncat-portable-5.59BETA1.zip"
BUNDLE_FILE = "bundle.json"
BUNDLE_COMPRESSION_THRESHOLD = 8 * 1024 * 1024
MAX_BUNDLE_FILE_BYTES = 300 * 1024 * 1024
HTTP_CHUNK_BYTES = 1024 * 1024
MAX_WORDLIST_SHRINK = 0.5
MIN_SHRINK_CHECK_LINES = 1_000
MIN_SHRINK_CHECK_BYTES = 64 * 1024
WORDLIST_CHUNK_LINES = 250_000
WORDLIST_CHUNK_BYTES = 16 * 1024 * 1024
WORDLIST_MERGE_FAN_IN = 64
ASSETNOTE_CATALOG_URL = "https://raw.githubusercontent.com/assetnote/wordlists/master/data/automated.json"
CUSTOM_DNS_LENGTHS = (1, 2, 3, 4, 5)
CUSTOM_DNS_ALPHABET = b"0123456789abcdefghijklmnopqrstuvwxyz"
CUSTOM_DNS_GENERATOR = "dns-alnum-v1"


@dataclass(frozen=True)
class DownloadTarget:
    name: str
    url: str
    is_dns_source: bool = False
    assetnote_prefix: str | None = None
    is_web_source: bool = False


TARGETS: tuple[DownloadTarget, ...] = (
    DownloadTarget(
        "web/fuzz.txt",
        "https://github.com/Bo0oM/fuzz.txt/raw/refs/heads/master/fuzz.txt",
        is_web_source=True,
    ),
    DownloadTarget(
        "web/hfuzz.txt",
        "https://github.com/thehlopster/hfuzz/raw/refs/heads/master/hfuzz.txt",
        is_web_source=True,
    ),
    DownloadTarget(
        "web/params.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/burp-parameter-names.txt",
    ),
    DownloadTarget(
        "web/headers.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/BurpSuite-ParamMiner/lowercase-headers",
    ),
    DownloadTarget(
        "web/assetnote-directories.txt",
        "https://wordlists-cdn.assetnote.io/data/automated/httparchive_directories_1m_2026_02_27.txt",
        assetnote_prefix="httparchive_directories_1m_",
        is_web_source=True,
    ),
    DownloadTarget(
        "web/seclists-combined-directories.txt",
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
        "Discovery/Web-Content/combined_directories.txt",
        is_web_source=True,
    ),
    DownloadTarget(
        "web/content_discovery_all.txt",
        "https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10/raw/content_discovery_all.txt",
        is_web_source=True,
    ),
    DownloadTarget(
        "api/endpoints.txt",
        "https://gist.github.com/MelForze/7292bec4a39b0a376cd1acfcc8b6ab85/raw/api-endpoints.txt",
    ),
    DownloadTarget(
        "api/openapi.txt",
        "https://github.com/z5jt/API-documentation-Wordlist/raw/refs/heads/main/"
        "API-Documentation-Wordlist/api-documentation-endpoint.txt",
    ),
    DownloadTarget(
        "web/dodgypass.txt",
        "https://raw.githubusercontent.com/mohemiv/dodgypass/refs/heads/main/dodgypass.txt",
        is_web_source=True,
    ),
    DownloadTarget(
        "dns/best-dns-wordlist.txt",
        "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "dns/assetnote-httparchive-subdomains.txt",
        "https://wordlists-cdn.assetnote.io/data/automated/httparchive_subdomains_2026_02_27.txt",
        is_dns_source=True,
        assetnote_prefix="httparchive_subdomains_",
    ),
    DownloadTarget(
        "dns/trickest-inventory-subdomains.txt",
        "https://raw.githubusercontent.com/trickest/wordlists/main/inventory/subdomains.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "dns/FUZZSUBS_CYFARE_1.txt",
        "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/"
        "Discovery/DNS/FUZZSUBS_CYFARE_1.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "dns/FUZZSUBS_CYFARE_2.txt",
        "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/"
        "Discovery/DNS/FUZZSUBS_CYFARE_2.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "dns/n0kovo_subdomains.txt",
        "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/"
        "Discovery/DNS/n0kovo_subdomains.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "dns/combined_subdomains.txt",
        "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/"
        "Discovery/DNS/combined_subdomains.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "dns/namelist.txt",
        "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/"
        "Discovery/DNS/namelist.txt",
        is_dns_source=True,
    ),
)

DNS_TARGET_NAMES = tuple(t.name for t in TARGETS if t.is_dns_source)
WEB_TARGET_NAMES = tuple(t.name for t in TARGETS if t.is_web_source)


def custom_dns_sources() -> dict[str, int]:
    return {f"dns/custom-alnum-{length}.txt": length for length in CUSTOM_DNS_LENGTHS}


def dns_source_names() -> tuple[str, ...]:
    return (*DNS_TARGET_NAMES, *custom_dns_sources())

NMAP_SERVICES_URL = "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
PORT_TOP_SIZES = tuple(range(1000, 5001, 1000))
PORT_CUSTOM_FILE = "ports/custom-top-2k.txt"
PORT_WEB_FILE = "ports/custom-top-web-1k.txt"
# Curated priorities, followed by Nmap's frequency ranking.
WEB_PRIORITY_PORTS = (
    80, 443, 81, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443,
    3000, 3001, 4000, 4200, 4443, 5000, 5001, 5601, 5800, 6080, 7000, 7001, 7443,
    8001, 8009, 8082, 8083, 8084, 8085, 8086, 8087, 8090, 8091, 8181, 8282, 8383,
    8500, 8800, 8834, 8880, 8881, 8889, 9001, 9043, 9080, 9081, 9091, 9200, 9300,
    10000, 10443, 18080, 18443, 28080,
)
CUSTOM_PRIORITY_PORTS = WEB_PRIORITY_PORTS + (
    1433, 1434, 1521, 2483, 2484, 3050, 3306, 5432, 6379, 7474, 7687, 9042, 9160,
    11211, 15672, 26257, 27017, 27018, 28015, 21, 22, 25, 53, 88, 111, 135, 139,
    389, 445, 464, 465, 587, 636, 873, 993, 995, 2049, 2181, 2375, 2376, 2379,
    2380, 3268, 3269, 3389, 5672, 5900, 5985, 5986, 6443, 9092, 10050, 10051, 10250,
)


class SelfListLoadError(RuntimeError):
    pass


class SourceSyncError(SelfListLoadError):
    def __init__(self, failures: list[tuple[str, str]], changed_count: int):
        self.failures = failures
        self.changed_count = changed_count
        super().__init__(
            f"{len(failures)} update task(s) failed; successful changes were saved. "
            "Repeat the command to retry unfinished tasks."
        )


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def open_wordlist(path: Path, mode: str = "rb", **kwargs: Any) -> Any:
    opener = {".gz": gzip.open, ".xz": lzma.open}.get(path.suffix, open)
    return opener(path, mode, **kwargs)


def ensure_app_dir(dest_dir: Path | None = None) -> Path:
    path = APP_DIR if dest_dir is None else dest_dir
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_winbins_dir() -> Path:
    WINBINS_DIR.mkdir(parents=True, exist_ok=True)
    return WINBINS_DIR


def load_state(dest_dir: Path) -> dict[str, Any]:
    path = dest_dir / META_FILE
    if not path.exists():
        return {"files": {}}
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise SelfListLoadError(f"Не удалось прочитать state-файл: {path}: {exc}") from exc
    if not isinstance(data, dict):
        return {"files": {}}
    data.setdefault("files", {})
    if not isinstance(data["files"], dict):
        data["files"] = {}
    return data


def atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=f"{path.name}.tmp.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def write_bytes_if_changed(path: Path, data: bytes) -> bool:
    new_sha = sha256_bytes(data)
    if path.exists() and path.is_file():
        old_sha = sha256_file(path)
        if old_sha == new_sha:
            return False
    atomic_write_bytes(path, data)
    return True


def write_text_if_changed(path: Path, text: str) -> bool:
    return write_bytes_if_changed(path, text.encode("utf-8"))


def copy_file_if_changed(path: Path, source: Path, *, digest: str | None = None) -> bool:
    digest = digest or sha256_file(source)
    if path.is_file() and sha256_file(path) == digest:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f"{path.name}.tmp.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as target, source.open("rb") as stream:
            shutil.copyfileobj(stream, target, HTTP_CHUNK_BYTES)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def save_state(dest_dir: Path, state: dict[str, Any]) -> None:
    path = dest_dir / META_FILE
    state.setdefault("files", {})
    state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    data = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, data)


def find_bundle_dir() -> Path | None:
    for root in (Path(__file__).resolve().parent, Path(sys.prefix) / "share" / "selflistload"):
        if (root / BUNDLE_FILE).is_file():
            return root
    return None


def bundle_path(root: Path, name: str) -> Path:
    rel = Path(name)
    if rel.is_absolute() or ".." in rel.parts or not rel.parts:
        raise SelfListLoadError(f"Некорректный путь в bundle: {name!r}")
    return root / rel


def install_snapshot(
    dest_dir: Path, state: dict[str, Any], *, overwrite: bool = False,
    bundle_dir: Path | None = None, verify: bool = True,
) -> int:
    root = bundle_dir if bundle_dir is not None else find_bundle_dir()
    if root is None:
        return 0
    manifest = json.loads((root / BUNDLE_FILE).read_text(encoding="utf-8"))
    if manifest.get("version") != 1:
        raise SelfListLoadError("Неизвестная версия bundle.json")
    changed = 0
    copied_custom_dns = False
    for entry in manifest["files"]:
        name = entry["path"]
        path = bundle_path(dest_dir, name)
        source = bundle_path(root, entry["stored_path"])
        if not verify and not source.is_file():
            continue
        if path.exists():
            if not overwrite or sha256_file(path) == entry["sha256"]:
                continue
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f"{path.name}.tmp.", dir=str(path.parent))
        try:
            opener = open_wordlist if entry["compression"] != "none" else open
            digest = hashlib.sha256()
            with os.fdopen(fd, "wb") as dst, opener(source, "rb") as src:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    digest.update(chunk)
                    dst.write(chunk)
            matches = digest.hexdigest() == entry["sha256"]
            if verify and not matches:
                raise SelfListLoadError(f"Не совпадает SHA-256 файла bundle: {name}")
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        # Validators must describe the copied snapshot, not a newer local version.
        source_state = manifest.get("sources", {}).get(name)
        if matches:
            record = dict(source_state) if isinstance(source_state, dict) else {}
            record["sha256"] = digest.hexdigest()
            state.setdefault("files", {})[name] = record
        if not matches and name in (OUT_DNS_FILE, OUT_WEB_FILE):
            state["rebuild_dns" if name == OUT_DNS_FILE else "rebuild_web"] = True
        save_state(dest_dir, state)
        changed += 1
        copied_custom_dns |= name in custom_dns_sources()
        log(f"    installed snapshot: {name}")
    if copied_custom_dns:
        aggregate = next((entry for entry in manifest["files"] if entry["path"] == OUT_DNS_FILE), None)
        path = dest_dir / OUT_DNS_FILE
        if aggregate is None or not path.is_file() or sha256_file(path) != aggregate["sha256"]:
            state["rebuild_dns"] = True
            save_state(dest_dir, state)
    return changed


def nmap_port_file(size: int) -> str:
    return f"ports/nmap-top-{size // 1000}k.txt"


def snapshot_file_names(raw_dir: Path) -> list[str]:
    names = [t.name for t in TARGETS] + list(custom_dns_sources()) + [OUT_DNS_FILE, OUT_WEB_FILE]
    names += [nmap_port_file(size) for size in PORT_TOP_SIZES]
    names += [PORT_CUSTOM_FILE, PORT_WEB_FILE]
    return sorted(set(names))


SNAPSHOT_TRANSACTION_DIR = ".selflistload-refresh"


def snapshot_target(root: Path, name: str) -> Path:
    path = bundle_path(root, name)
    if name != BUNDLE_FILE and Path(name).parts[0] not in {"dns", "web", "api", "ports"}:
        raise SelfListLoadError(f"Unexpected managed snapshot path: {name!r}")
    for parent in [path, *path.parents]:
        if parent == root:
            break
        if parent.is_symlink():
            raise SelfListLoadError(f"Snapshot path is a symbolic link: {parent}")
        if parent != path and parent.exists() and not parent.is_dir():
            raise SelfListLoadError(f"Snapshot parent is not a directory: {parent}")
    if path.exists() and not path.is_file():
        raise SelfListLoadError(f"Snapshot path is not a regular file: {path}")
    return path


def backup_snapshot_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def rollback_snapshot(repo_dir: Path, transaction: Path, journal: dict[str, Any]) -> None:
    if journal.get("phase") == "committed":
        return
    changes = journal.get("changes")
    if journal.get("version") != 1 or not isinstance(changes, list):
        raise SelfListLoadError(f"Invalid snapshot recovery journal: {transaction}")
    # Backups are retained until rollback completes, making recovery repeatable.
    for index, entry in reversed(list(enumerate(changes))):
        target = snapshot_target(repo_dir, entry["path"])
        if entry["existed"]:
            backup = bundle_path(transaction / "old", entry["path"])
            if not backup.is_file() or backup.is_symlink():
                raise SelfListLoadError(f"Missing snapshot backup: {backup}")
            restore = transaction / "restore" / str(index)
            if restore.exists():
                restore.unlink()
            backup_snapshot_file(backup, restore)
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(restore, target)
        elif target.exists():
            target.unlink()
    for name in sorted(journal.get("created_dirs", []), key=lambda name: len(Path(name).parts), reverse=True):
        directory = bundle_path(repo_dir, name)
        if directory.is_symlink() or Path(name).parts[0] not in {"dns", "web", "api", "ports"}:
            raise SelfListLoadError(f"Invalid snapshot recovery directory: {name}")
        try:
            directory.rmdir()
        except OSError:
            pass


def recover_snapshot(repo_dir: Path) -> None:
    transaction = repo_dir / SNAPSHOT_TRANSACTION_DIR
    if not transaction.exists() and not transaction.is_symlink():
        return
    if transaction.is_symlink() or not transaction.is_dir():
        raise SelfListLoadError(f"Invalid snapshot staging directory: {transaction}")
    try:
        owner = json.loads((transaction / "owner.json").read_text())
        pid = owner["pid"]
        if not isinstance(pid, int) or pid <= 0:
            raise ValueError("invalid owner PID")
        if os.name == "posix":
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                pass
            except PermissionError:
                raise SelfListLoadError("Another repository refresh is running")
            else:
                raise SelfListLoadError("Another repository refresh is running")
        elif pid == os.getpid():
            raise SelfListLoadError("Another repository refresh is running")
        journal_path = transaction / "journal.json"
        if journal_path.exists():
            journal = json.loads(journal_path.read_text())
            rollback_snapshot(repo_dir, transaction, journal)
            log("==> Recovered interrupted repository publication")
        shutil.rmtree(transaction)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SelfListLoadError(f"Cannot recover snapshot; backups preserved at {transaction}: {exc}") from exc


@contextmanager
def snapshot_stage(repo_dir: Path) -> Iterator[Path]:
    repo_dir.mkdir(parents=True, exist_ok=True)
    recover_snapshot(repo_dir)
    transaction = repo_dir / SNAPSHOT_TRANSACTION_DIR
    transaction.mkdir(mode=0o700)
    keep_backups = False
    try:
        atomic_write_text(transaction / "owner.json", json.dumps({"pid": os.getpid()}))
        yield transaction
    except BaseException as exc:
        journal_path = transaction / "journal.json"
        if journal_path.exists():
            try:
                rollback_snapshot(repo_dir, transaction, json.loads(journal_path.read_text()))
            except BaseException as rollback_error:
                keep_backups = True
                raise SelfListLoadError(
                    f"Snapshot publication failed ({exc}); rollback failed ({rollback_error}). "
                    f"Backups preserved at {transaction}; repeat refresh to recover."
                ) from exc
        raise
    finally:
        if not keep_backups:
            shutil.rmtree(transaction)


def publish_snapshot(repo_dir: Path, transaction: Path, names: list[str]) -> None:
    changes = []
    created_dirs = set()
    for name in names:
        target = snapshot_target(repo_dir, name)
        existed = target.is_file()
        if existed:
            backup_snapshot_file(target, bundle_path(transaction / "old", name))
        for parent in target.parents:
            if parent == repo_dir:
                break
            if not parent.exists():
                created_dirs.add(parent.relative_to(repo_dir).as_posix())
        changes.append({"path": name, "existed": existed})
    journal = {"version": 1, "phase": "publishing", "changes": changes, "created_dirs": sorted(created_dirs)}
    journal_path = transaction / "journal.json"
    atomic_write_text(journal_path, json.dumps(journal, indent=2) + "\n")
    for entry in changes:
        target = snapshot_target(repo_dir, entry["path"])
        staged = bundle_path(transaction / "new", entry["path"])
        if staged.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staged, target)
        elif target.exists():
            target.unlink()
    journal["phase"] = "committed"
    atomic_write_text(journal_path, json.dumps(journal, indent=2) + "\n")


def write_snapshot(raw_dir: Path, repo_dir: Path, state: dict[str, Any]) -> int:
    with snapshot_stage(repo_dir) as transaction:
        old_manifest_path = repo_dir / BUNDLE_FILE
        old_manifest = json.loads(old_manifest_path.read_text()) if old_manifest_path.exists() else {}
        old_entries = {entry["path"]: entry for entry in old_manifest.get("files", [])}
        entries = []
        sources = {}
        replacements = []
        stage = transaction / "new"
        for name in snapshot_file_names(raw_dir):
            source = raw_dir / name
            digest = sha256_file(source)
            compressed = source.stat().st_size >= BUNDLE_COMPRESSION_THRESHOLD
            compression = ("xz" if name == OUT_DNS_FILE or name in custom_dns_sources() else "gzip") if compressed else "none"
            stored_name = name + {"none": "", "gzip": ".gz", "xz": ".xz"}[compression]
            entry = {"path": name, "stored_path": stored_name, "sha256": digest,
                     "size": source.stat().st_size, "compression": compression}
            target = snapshot_target(repo_dir, stored_name)
            staged = bundle_path(stage, stored_name)
            staged.parent.mkdir(parents=True, exist_ok=True)
            old_entry = old_entries.get(name)
            unchanged = (old_entry is not None and all(old_entry.get(key) == value for key, value in entry.items())
                         and target.is_file() and sha256_file(target) == old_entry.get("stored_sha256"))
            if unchanged:
                backup_snapshot_file(target, staged)
            else:
                with source.open("rb") as src, staged.open("wb") as dst:
                    if compression == "xz":
                        with lzma.LZMAFile(dst, mode="wb", format=lzma.FORMAT_XZ, preset=6) as packed:
                            shutil.copyfileobj(src, packed)
                    elif compression == "gzip":
                        with gzip.GzipFile(filename="", fileobj=dst, mode="wb", mtime=0) as packed:
                            shutil.copyfileobj(src, packed)
                    else:
                        shutil.copyfileobj(src, dst)
                replacements.append(stored_name)
            if staged.stat().st_size > MAX_BUNDLE_FILE_BYTES:
                raise SelfListLoadError(f"Файл слишком большой для snapshot: {stored_name}")
            entry["stored_sha256"] = sha256_file(staged)
            entries.append(entry)
            source_state = state.get("files", {}).get(name)
            if isinstance(source_state, dict):
                sources[name] = {key: value for key, value in source_state.items()
                                 if key == "url" or (key in {"etag", "last_modified", "generator", "length"}
                                                      and source_state.get("sha256") == digest)}
                sources[name]["sha256"] = digest
        manifest = {"version": 1, "files": entries, "sources": sources}
        manifest_text = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        atomic_write_text(stage / BUNDLE_FILE, manifest_text)
        errors = verify_repository(stage, quiet=True)
        if errors:
            raise SelfListLoadError("Snapshot validation failed: " + "; ".join(errors))
        stored_paths = {entry["stored_path"] for entry in entries}
        retired = []
        for previous in old_entries.values():
            name = previous["stored_path"]
            if name not in stored_paths and snapshot_target(repo_dir, name).is_file() and name not in retired:
                retired.append(name)
        changed = len(replacements)
        if not old_manifest_path.exists() or old_manifest_path.read_text() != manifest_text:
            replacements.append(BUNDLE_FILE)
            changed += 1
        # Publish the manifest last, after all replacements and retirements.
        names = [name for name in replacements if name != BUNDLE_FILE] + retired
        if BUNDLE_FILE in replacements:
            names.append(BUNDLE_FILE)
        if names:
            publish_snapshot(repo_dir, transaction, names)
        return changed


def refresh_cache_dir(repo_dir: Path) -> Path:
    key = hashlib.sha256(str(repo_dir.resolve()).encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"selflistload-refresh-{key}"


def run_refresh(repo_dir: Path, *, allow_shrink: bool = False) -> int:
    if not (repo_dir / "pyproject.toml").is_file() or not (repo_dir / "selflistload.py").is_file():
        raise SelfListLoadError("refresh требует путь к исходному репозиторию Selflists (--repo PATH)")
    recover_snapshot(repo_dir)
    raw_dir = refresh_cache_dir(repo_dir)
    if raw_dir.is_symlink():
        raise SelfListLoadError(f"Небезопасный каталог продолжения обновления: {raw_dir}")
    raw_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if hasattr(os, "getuid") and raw_dir.stat().st_uid != os.getuid():
        raise SelfListLoadError(f"Каталог продолжения обновления принадлежит другому пользователю: {raw_dir}")
    state = load_state(raw_dir)
    try:
        prepare_layout(raw_dir, state)
        if (repo_dir / BUNDLE_FILE).exists():
            install_snapshot(raw_dir, state, bundle_dir=repo_dir, verify=False)
        sync_error = None
        try:
            sync_wordlists(raw_dir, state, mode="update", force_dns=bool(state.get("rebuild_dns")),
                           force_web=bool(state.get("rebuild_web")), keep_progress=True, allow_shrink=allow_shrink)
        except SourceSyncError as exc:
            sync_error = exc
        missing = [name for name in snapshot_file_names(raw_dir) if not (raw_dir / name).is_file()]
        if missing and sync_error is not None:
            log(f"==> Repository publication skipped; required files missing: {', '.join(missing)}")
            raise sync_error
        changed = write_snapshot(raw_dir, repo_dir, state)
        if sync_error is not None:
            log(f"==> Repository refreshed with available source versions ({changed} changed files)")
            raise sync_error
    except BaseException:
        log(f"==> Progress preserved: {raw_dir}; repeat refresh to continue")
        raise
    shutil.rmtree(raw_dir)
    log(f"==> Repository snapshot refreshed ({changed} changed files)")
    return changed


def prepare_layout(dest_dir: Path, state: dict[str, Any]) -> None:
    for name in ("dns", "web", "api", "ports"):
        (dest_dir / name).mkdir(parents=True, exist_ok=True)
    state.setdefault("files", {})


def custom_dns_blocks(length: int) -> Iterator[bytes]:
    if length not in range(1, 6):
        raise SelfListLoadError("Custom DNS length must be between 1 and 5")
    words = itertools.product(CUSTOM_DNS_ALPHABET, repeat=length)
    while True:
        batch = tuple(itertools.islice(words, 50_000))
        if not batch:
            return
        yield b"".join(bytes(word) + b"\n" for word in batch)


def sync_custom_dns_lists(dest_dir: Path, state: dict[str, Any]) -> int:
    changed = 0
    files = state.setdefault("files", {})
    for name, length in custom_dns_sources().items():
        path = dest_dir / name
        previous = files.get(name, {})
        old_sha = sha256_file(path) if path.is_file() else None
        if (isinstance(previous, dict) and previous.get("generator") == CUSTOM_DNS_GENERATOR
                and previous.get("length") == length and old_sha is not None
                and previous.get("sha256") == old_sha):
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f"{path.name}.tmp.", dir=str(path.parent))
        try:
            digest = hashlib.sha256()
            with os.fdopen(fd, "wb") as stream:
                for block in custom_dns_blocks(length):
                    stream.write(block)
                    digest.update(block)
            new_sha = digest.hexdigest()
            state["rebuild_dns"] = True
            save_state(dest_dir, state)
            if new_sha != old_sha:
                os.replace(temporary, path)
                changed += 1
            files[name] = {"generator": CUSTOM_DNS_GENERATOR, "length": length, "sha256": new_sha}
            save_state(dest_dir, state)
            log(f"==> Generated {name}: {format_count(len(CUSTOM_DNS_ALPHABET) ** length)} entries")
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return changed


def write_port_list(path: Path, ports: list[int]) -> int:
    return int(write_text_if_changed(path, ",".join(map(str, ports)) + "\n"))


def read_port_list(path: Path) -> list[int]:
    ports: list[int] = []
    seen: set[int] = set()
    text = "\n".join(line.split("#", 1)[0] for line in path.read_text(encoding="utf-8").splitlines())
    for value in re.split(r"[,\s]+", text.strip()):
        if not value:
            continue
        if not value.isascii() or not value.isdigit() or not 1 <= int(value) <= 65535:
            raise SelfListLoadError(f"Некорректный порт в {path}: {value!r}")
        port = int(value)
        if port not in seen:
            ports.append(port)
            seen.add(port)
    return ports


def rank_nmap_ports(data: str) -> list[int]:
    frequencies: dict[int, float] = {}
    for number, raw in enumerate(data.splitlines(), 1):
        fields = raw.split("#", 1)[0].split()
        if not fields:
            continue
        try:
            port_text, protocol = fields[1].split("/")
            if protocol != "tcp":
                continue
            port = int(port_text)
            frequency = float(fields[2]) if len(fields) >= 3 else 0.0
            if not 1 <= port <= 65535 or not math.isfinite(frequency) or not 0 <= frequency <= 1:
                raise ValueError("port or frequency out of range")
        except (IndexError, ValueError) as exc:
            raise SelfListLoadError(f"Некорректная строка nmap-services:{number}: {raw!r}") from exc
        frequencies[port] = max(frequency, frequencies.get(port, 0.0))
    if len(frequencies) < max(PORT_TOP_SIZES):
        raise SelfListLoadError(
            f"В nmap-services только {len(frequencies)} TCP-портов; нужно {max(PORT_TOP_SIZES)}"
        )
    return sorted(frequencies, key=lambda port: (-frequencies[port], port))


def rebuild_custom_port_lists(dest_dir: Path, ranked: list[int], data: str) -> int:
    custom = list(dict.fromkeys([*CUSTOM_PRIORITY_PORTS, *ranked]))[:2000]
    named_web: set[int] = set()
    for raw in data.splitlines():
        fields = raw.split("#", 1)[0].split()
        if len(fields) >= 2 and fields[1].endswith("/tcp") and re.search(r"http|www|web", fields[0], re.I):
            named_web.add(int(fields[1].split("/")[0]))
    alternatives = [*range(8000, 9000), *range(3000, 3100), *range(5000, 5100),
                    *range(9000, 9100), *range(10000, 10100)]
    alternative_set = set(alternatives)
    web = list(dict.fromkeys([
        *WEB_PRIORITY_PORTS,
        *(port for port in ranked if port in named_web),
        *(port for port in ranked if port in alternative_set),
        *alternatives,
    ]))[:1000]
    return (write_port_list(dest_dir / PORT_CUSTOM_FILE, sorted(custom))
            + write_port_list(dest_dir / PORT_WEB_FILE, sorted(web)))


def normalize_port_lists(dest_dir: Path) -> int:
    names = [nmap_port_file(size) for size in PORT_TOP_SIZES] + [PORT_CUSTOM_FILE, PORT_WEB_FILE]
    changed = 0
    for name in names:
        ports = read_port_list(dest_dir / name)
        if name in (PORT_CUSTOM_FILE, PORT_WEB_FILE):
            ports.sort()
        changed += write_port_list(dest_dir / name, ports)
    return changed


def rebuild_port_lists(dest_dir: Path, data: str) -> int:
    ranked = rank_nmap_ports(data)
    changed = 0
    for size in PORT_TOP_SIZES:
        changed += write_port_list(dest_dir / nmap_port_file(size), ranked[:size])
    changed += rebuild_custom_port_lists(dest_dir, ranked, data)
    log(f"==> Port lists ready ({changed} changed files)")
    return changed


def sync_port_lists(dest_dir: Path) -> int:
    # The upstream service database is used in memory and is never stored locally.
    data, _headers = http_get_bytes(NMAP_SERVICES_URL)
    return rebuild_port_lists(dest_dir, data.decode("utf-8"))


def _safe_rel_zip_path(name: str) -> Path:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise SelfListLoadError(f"Небезопасный путь в архиве: {name}")
    parts = [p for p in normalized.split("/") if p not in {"", "."}]
    if any(part == ".." or ":" in part for part in parts):
        raise SelfListLoadError(f"Небезопасный путь в архиве: {name}")
    return Path(*parts)


def _common_zip_root(infos: list[zipfile.ZipInfo]) -> str | None:
    first_parts: set[str] = set()
    for info in infos:
        rel = _safe_rel_zip_path(info.filename)
        if not rel.parts:
            continue
        first_parts.add(rel.parts[0])
        if len(first_parts) > 1:
            return None
    if len(first_parts) != 1:
        return None
    root = next(iter(first_parts))
    return root


def _zip_member_bytes(zip_data: bytes | Path, *, basename: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(zip_data) if isinstance(zip_data, bytes) else zip_data) as zf:
        matches = [
            info
            for info in zf.infolist()
            if not info.is_dir() and Path(info.filename.replace("\\", "/")).name.lower() == basename.lower()
        ]
        if not matches:
            raise SelfListLoadError(f"В архиве не найден файл: {basename}")
        # If there are multiple matches, prefer the shortest path.
        matches.sort(key=lambda info: (len(info.filename), info.filename.lower()))
        return zf.read(matches[0])


def _extract_zip_into_dir(zip_data: bytes | Path, dest_dir: Path) -> None:
    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    stage_dir = Path(tempfile.mkdtemp(prefix=f"{dest_dir.name}.tmp.", dir=str(dest_dir.parent)))
    try:
        with zipfile.ZipFile(io.BytesIO(zip_data) if isinstance(zip_data, bytes) else zip_data) as zf:
            files = [info for info in zf.infolist() if not info.is_dir()]
            root_prefix = _common_zip_root(files)
            seen: set[str] = set()
            for info in files:
                rel = _safe_rel_zip_path(info.filename)
                if not rel.parts:
                    continue
                key = rel.as_posix().casefold()
                if key in seen:
                    raise SelfListLoadError(f"Повторяющийся путь в архиве: {info.filename}")
                seen.add(key)
                if root_prefix and rel.parts[0] == root_prefix:
                    rel = Path(*rel.parts[1:])
                if not rel.parts:
                    continue
                out_path = stage_dir / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src:
                    with out_path.open("wb") as target:
                        shutil.copyfileobj(src, target, HTTP_CHUNK_BYTES)
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        stage_dir.rename(dest_dir)
    except Exception:
        shutil.rmtree(stage_dir, ignore_errors=True)
        raise


def http_get_bytes(url: str) -> tuple[bytes, dict[str, str]]:
    status, body, headers = http_get_with_retries(url)
    if status != 200 or body is None:
        raise SelfListLoadError(f"Не удалось скачать: {url} (status={status})")
    return body, headers


def http_get_json(url: str) -> dict[str, Any]:
    body, _headers = http_get_bytes(url)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SelfListLoadError(f"Некорректный JSON от {url}: {exc}") from exc
    if not isinstance(data, dict):
        raise SelfListLoadError(f"Ожидался JSON object от {url}")
    return data


def github_latest_release_asset_url(
    owner: str,
    repo: str,
    *,
    asset_pattern: str,
) -> tuple[str, str]:
    api_url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    data = http_get_json(api_url)
    assets = data.get("assets")
    if not isinstance(assets, list):
        raise SelfListLoadError(f"GitHub API не вернул assets для {owner}/{repo}")
    rx = re.compile(asset_pattern)
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        name = asset.get("name")
        url = asset.get("browser_download_url")
        if isinstance(name, str) and isinstance(url, str) and rx.search(name):
            return name, url
    raise SelfListLoadError(
        f"Не найден asset по шаблону {asset_pattern!r} в latest release {owner}/{repo}"
    )


def _build_request(url: str, *, conditional: dict[str, str] | None = None) -> request.Request:
    headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
    if conditional:
        headers.update(conditional)
    return request.Request(url, headers=headers, method="GET")


def http_get_with_retries(
    url: str,
    *,
    conditional: dict[str, str] | None = None,
) -> tuple[int, bytes | None, dict[str, str]]:
    last_exc: Exception | None = None
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            req = _build_request(url, conditional=conditional)
            with request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                status = getattr(resp, "status", 200)
                body = resp.read()
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return int(status), body, headers
        except error.HTTPError as exc:
            if exc.code == 304:
                headers = {k.lower(): v for k, v in exc.headers.items()}
                return 304, None, headers
            last_exc = exc
            if attempt == HTTP_RETRIES:
                break
        except (OSError, http.client.HTTPException) as exc:
            last_exc = exc
            if attempt == HTTP_RETRIES:
                break
        time.sleep(RETRY_DELAY_SEC * attempt)
    raise SelfListLoadError(f"Ошибка загрузки {url}: {last_exc}")


@dataclass(frozen=True)
class FileDownload:
    status: int
    headers: dict[str, str]
    sha256: str = ""
    size: int = 0


def http_download_to_file(
    url: str, path: Path, *, conditional: dict[str, str] | None = None,
) -> FileDownload:
    last_error: Exception | None = None
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            try:
                response = request.urlopen(_build_request(url, conditional=conditional), timeout=HTTP_TIMEOUT)
            except (TimeoutError, ConnectionError, http.client.HTTPException) as exc:
                raise error.URLError(exc) from exc
            with response:
                status = int(getattr(response, "status", 200))
                headers = {key.lower(): value for key, value in response.headers.items()}
                if status == 304:
                    return FileDownload(status, headers)
                if status != 200:
                    raise SelfListLoadError(f"Неожиданный HTTP-статус {status} при загрузке {url}")
                digest = hashlib.sha256()
                size = 0
                with path.open("wb") as output:
                    while True:
                        try:
                            chunk = response.read(HTTP_CHUNK_BYTES)
                        except (OSError, http.client.HTTPException) as exc:
                            raise error.URLError(exc) from exc
                        if not chunk:
                            break
                        output.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                length = headers.get("content-length")
                if length is not None:
                    if not length.isdigit():
                        raise SelfListLoadError(f"Некорректный Content-Length от {url}: {length!r}")
                    if size != int(length):
                        raise error.URLError(f"Неполный ответ: получено {size}, ожидалось {length} байт")
                return FileDownload(status, headers, digest.hexdigest(), size)
        except error.HTTPError as exc:
            if exc.code == 304:
                headers = {key.lower(): value for key, value in exc.headers.items()}
                exc.close()
                return FileDownload(304, headers)
            last_error = exc
            exc.close()
        except error.URLError as exc:
            last_error = exc
        if attempt < HTTP_RETRIES:
            time.sleep(RETRY_DELAY_SEC * attempt)
    raise SelfListLoadError(f"Ошибка загрузки {url}: {last_error}")


def _has_wordlist_entries(path: Path, *, compressed: bool = False) -> bool:
    # Inspect lines in bounded chunks, including very long comments/blank runs.
    in_comment = False
    first = True
    opener = open_wordlist if compressed else open
    with opener(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(HTTP_CHUNK_BYTES), b""):
            if first:
                chunk = chunk.removeprefix(b"\xef\xbb\xbf")
                first = False
            pieces = chunk.split(b"\n")
            for index, piece in enumerate(pieces):
                if not in_comment:
                    value = piece.lstrip()
                    if value:
                        if value.startswith(b"#"):
                            in_comment = True
                        else:
                            return True
                if index < len(pieces) - 1:
                    in_comment = False
    return False


def validate_wordlist(
    path: Path, target: DownloadTarget, headers: dict[str, str], *, compressed: bool = False,
) -> None:
    if path.stat().st_size == 0:
        raise SelfListLoadError(f"Источник вернул пустой словарь: {target.name}")
    opener = open_wordlist if compressed else open
    with opener(path, "rb") as stream:
        prefix = stream.read(64 * 1024)
    if not prefix:
        raise SelfListLoadError(f"Источник вернул пустой словарь: {target.name}")
    content = prefix.removeprefix(b"\xef\xbb\xbf").lstrip().lower()
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    html = re.match(br"(?:<!--.*?-->\s*)*(?:<!doctype\s+html\b|<html\b)", content, re.S)
    if content_type in {"text/html", "application/xhtml+xml", "application/json"} or html:
        raise SelfListLoadError(f"Вместо словаря {target.name} получена HTML/JSON-страница")
    if (content.startswith(b"<?xml") and (b"<error" in content or b"<html" in content)):
        raise SelfListLoadError(f"Вместо словаря {target.name} получена страница ошибки")
    if b"\x00" in prefix or prefix.startswith((b"PK\x03\x04", b"\x1f\x8b", b"\x7fELF")):
        raise SelfListLoadError(f"Вместо текстового словаря {target.name} получены бинарные данные")
    if not _has_wordlist_entries(path, compressed=compressed):
        raise SelfListLoadError(f"Словарь {target.name} содержит только пустые строки или комментарии")


def count_file_lines(path: Path) -> int:
    count = 0
    last = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(HTTP_CHUNK_BYTES), b""):
            count += chunk.count(b"\n")
            last = chunk[-1:]
    return count + int(bool(last) and last != b"\n")


def check_wordlist_shrink(old: Path, new: Path, target: DownloadTarget) -> None:
    old_size, new_size = old.stat().st_size, new.stat().st_size
    old_lines, new_lines = count_file_lines(old), count_file_lines(new)
    reasons = []
    remaining = 1 - MAX_WORDLIST_SHRINK
    if old_lines >= MIN_SHRINK_CHECK_LINES and new_lines < old_lines * remaining:
        reasons.append(f"lines {format_count(old_lines)} -> {format_count(new_lines)}")
    if old_size >= MIN_SHRINK_CHECK_BYTES and new_size < old_size * remaining:
        reasons.append(f"size {format_size(old_size)} -> {format_size(new_size)}")
    if reasons:
        raise SelfListLoadError(
            f"Suspicious shrink in {target.name}: {'; '.join(reasons)}. "
            "Previous file preserved. Inspect the source, then repeat with --allow-shrink to accept it."
        )


@contextmanager
def downloaded_zip(url: str) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="selflistload-archive-") as temporary:
        path = Path(temporary) / "download.zip"
        result = http_download_to_file(url, path)
        if result.status != 200 or result.size == 0 or not zipfile.is_zipfile(path):
            raise SelfListLoadError(f"Источник не вернул корректный ZIP-архив: {url}")
        yield path


def _header_value(headers: dict[str, str], key: str) -> str | None:
    value = headers.get(key.lower())
    return value.strip() if isinstance(value, str) and value.strip() else None


def _build_conditional_headers(file_state: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    etag = file_state.get("etag")
    last_modified = file_state.get("last_modified")
    if isinstance(etag, str) and etag:
        headers["If-None-Match"] = etag
    if isinstance(last_modified, str) and last_modified:
        headers["If-Modified-Since"] = last_modified
    return headers


def _set_state_from_response(
    file_state: dict[str, Any],
    *,
    target: DownloadTarget,
    headers: dict[str, str],
    sha256: str | None = None,
) -> None:
    file_state["url"] = target.url
    etag = _header_value(headers, "etag")
    last_modified = _header_value(headers, "last-modified")
    content_length = _header_value(headers, "content-length")
    if etag is not None:
        file_state["etag"] = etag
    elif "etag" in file_state:
        file_state.pop("etag", None)
    if last_modified is not None:
        file_state["last_modified"] = last_modified
    elif "last_modified" in file_state:
        file_state.pop("last_modified", None)
    if content_length is not None:
        file_state["content_length"] = content_length
    elif "content_length" in file_state:
        file_state.pop("content_length", None)
    if sha256 is not None:
        file_state["sha256"] = sha256
    file_state["checked_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _mark_target_dirty(target: DownloadTarget, state: dict[str, Any]) -> None:
    if target.is_dns_source:
        state["rebuild_dns"] = True
    if target.is_web_source:
        state["rebuild_web"] = True


def _finish_download(
    target: DownloadTarget, dest_dir: Path, state: dict[str, Any], record: dict[str, Any],
) -> None:
    state.setdefault("files", {})[target.name] = record
    progress = state.get("sync")
    if isinstance(progress, dict):
        progress.setdefault("completed", {})[target.name] = {"url": target.url, "sha256": record.get("sha256")}
    save_state(dest_dir, state)


def download_target(
    target: DownloadTarget, *, dest_dir: Path, state: dict[str, Any], mode: str, allow_shrink: bool = False,
) -> str:
    previous = state.setdefault("files", {}).get(target.name)
    record = dict(previous) if isinstance(previous, dict) else {}
    path = dest_dir / target.name
    old_sha = sha256_file(path) if path.is_file() else None
    matches = record.get("url") == target.url and old_sha is not None and record.get("sha256") == old_sha
    conditional = _build_conditional_headers(record) if mode == "update" and matches else {}
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f"{path.name}.tmp.download.", dir=str(path.parent))
    os.close(fd)
    staged = Path(temporary)
    log(f"==> Check: {target.name}")
    try:
        response = http_download_to_file(target.url, staged, conditional=conditional or None)
        if response.status == 304 and not matches:
            response = http_download_to_file(target.url, staged, conditional=None)
            if response.status == 304:
                raise SelfListLoadError(f"Источник вернул 304 без подходящей локальной копии: {target.name}")
        if response.status == 304:
            headers = dict(response.headers)
            for header, key in (("etag", "etag"), ("last-modified", "last_modified")):
                if header not in headers and isinstance(record.get(key), str):
                    headers[header] = record[key]
            _set_state_from_response(record, target=target, headers=headers, sha256=old_sha)
            _finish_download(target, dest_dir, state, record)
            return "unchanged"
        if response.status != 200:
            raise SelfListLoadError(f"Неожиданный HTTP-статус {response.status} для {target.name}")
        validate_wordlist(staged, target, response.headers)
        if old_sha is not None and response.sha256 != old_sha and not allow_shrink:
            check_wordlist_shrink(path, staged, target)
        if response.sha256 != old_sha or response.sha256 != record.get("sha256"):
            # Persist dirty aggregates before replacing a source, including crash recovery.
            _mark_target_dirty(target, state)
            save_state(dest_dir, state)
        changed = response.sha256 != old_sha
        if changed:
            os.replace(staged, path)
        _set_state_from_response(record, target=target, headers=response.headers, sha256=response.sha256)
        _finish_download(target, dest_dir, state, record)
        return ("downloaded" if old_sha is None else "updated") if changed else "unchanged"
    finally:
        if staged.exists():
            staged.unlink()


def normalize_dns_line(raw: bytes) -> str | None:
    # Preserve shell-script behavior: remove CR, trim trailing whitespace, drop empty lines.
    line = raw.replace(b"\r", b"").decode("utf-8", errors="replace").rstrip()
    if not line.strip():
        return None
    return line


def normalize_web_line(raw: bytes) -> str | None:
    # Preserve path case, slashes, percent escapes and meaningful spaces.
    line = raw.rstrip(b"\r\n").decode("utf-8", errors="replace")
    if not line.strip() or line.startswith("#"):
        return None
    return line


@dataclass(frozen=True)
class WordlistStats:
    name: str
    input_lines: int
    ignored_lines: int
    unique_lines: int
    duplicates_removed: int
    previous_lines: int | None
    added: int | None
    removed: int | None
    before_bytes: int
    after_bytes: int
    changed: bool


def _previous_wordlist_lines(path: Path, normalize: Callable[[bytes], str | None]) -> Iterator[bytes]:
    previous = None
    with path.open("rb") as stream:
        for raw in stream:
            value = normalize(raw)
            if value is None:
                continue
            word = value.encode("utf-8")
            if previous is not None and word < previous:
                raise ValueError("Previous aggregate is not sorted")
            if word != previous:
                yield word
            previous = word


def _chunk_words(stream: Any) -> Iterator[bytes]:
    for raw in stream:
        yield raw[:-1]  # Chunk files always have exactly one LF per record.


def wordlist_changes(
    path: Path, sorted_path: Path, unique_count: int, normalize: Callable[[bytes], str | None],
) -> tuple[int | None, int | None, int | None]:
    if not path.exists():
        return 0, unique_count, 0
    old = _previous_wordlist_lines(path, normalize)
    before_count = added = removed = 0
    try:
        with sorted_path.open("rb") as stream:
            new = _chunk_words(stream)
            left, right = next(old, None), next(new, None)
            while left is not None or right is not None:
                if left is None or (right is not None and right < left):
                    added += 1
                    right = next(new, None)
                elif right is None or left < right:
                    before_count += 1
                    removed += 1
                    left = next(old, None)
                else:
                    before_count += 1
                    left, right = next(old, None), next(new, None)
    except ValueError:
        return None, None, None
    finally:
        old.close()
    return before_count, added, removed


def merge_wordlist_chunks(chunks: list[Path], output: Path) -> int:
    count = 0
    previous = None
    with ExitStack() as stack, output.open("wb") as target:
        streams = [stack.enter_context(path.open("rb")) for path in chunks]
        for word in heapq.merge(*(_chunk_words(stream) for stream in streams)):
            if word != previous:
                target.write(word + b"\n")
                count += 1
            previous = word
    return count


def finish_wordlist_chunks(chunks: list[Path], work: Path) -> tuple[Path, int]:
    if WORDLIST_MERGE_FAN_IN < 2:
        raise SelfListLoadError("Предел файлов при слиянии должен быть не меньше 2")
    pass_number = 0
    while len(chunks) > WORDLIST_MERGE_FAN_IN:
        merged = []
        for index in range(0, len(chunks), WORDLIST_MERGE_FAN_IN):
            group = chunks[index:index + WORDLIST_MERGE_FAN_IN]
            path = work / f"merge-{pass_number}-{index}.txt"
            merge_wordlist_chunks(group, path)
            merged.append(path)
            for old_chunk in group:
                old_chunk.unlink()
        chunks = merged
        pass_number += 1
    staged = work / "result.txt"
    count = merge_wordlist_chunks(chunks, staged)
    # Keep only the final file while processing other sources for DNS statistics.
    for chunk in chunks:
        chunk.unlink()
    return staged, count


def build_wordlist_chunks(
    dest_dir: Path, sources: tuple[str, ...], work: Path,
    normalize: Callable[[bytes], str | None],
) -> tuple[list[Path], int, int]:
    chunks = []
    batch: set[bytes] = set()
    batch_bytes = input_lines = ignored = 0

    def flush() -> None:
        nonlocal batch_bytes
        path = work / f"chunk-{len(chunks):06d}.txt"
        with path.open("wb") as stream:
            stream.writelines(word + b"\n" for word in sorted(batch))
        chunks.append(path)
        batch.clear()
        batch_bytes = 0

    for name in sources:
        with (dest_dir / name).open("rb") as stream:
            for raw in stream:
                line = normalize(raw)
                if line is None:
                    ignored += 1
                    continue
                input_lines += 1
                word = line.encode("utf-8")
                if word not in batch:
                    batch.add(word)
                    batch_bytes += len(word)
                if len(batch) >= WORDLIST_CHUNK_LINES or batch_bytes >= WORDLIST_CHUNK_BYTES:
                    flush()
    if batch:
        flush()
    return chunks, input_lines, ignored


def format_size(size: int, *, signed: bool = False) -> str:
    prefix = ("+" if size >= 0 else "-") if signed else ""
    value = float(abs(size))
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            number = str(int(value)) if unit == "B" else f"{value:.2f}"
            return f"{prefix}{number} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def format_count(value: int) -> str:
    return f"{value:,}".replace(",", " ")


def log_wordlist_stats(stats: WordlistStats) -> None:
    log(f"==> Rebuilt {stats.name}: {format_count(stats.unique_lines)} unique lines")
    if stats.added is None:
        log("    added/removed: unavailable (previous aggregate was not sorted)")
    else:
        log(f"    lines: {format_count(stats.previous_lines)} -> {format_count(stats.unique_lines)}; "
            f"added: +{format_count(stats.added)}; removed: -{format_count(stats.removed)}")
    log(f"    duplicates discarded: {format_count(stats.duplicates_removed)}; ignored: {format_count(stats.ignored_lines)}")
    log(f"    size: {format_size(stats.before_bytes)} -> {format_size(stats.after_bytes)} "
        f"({format_size(stats.after_bytes - stats.before_bytes, signed=True)})")


def rebuild_wordlist(
    dest_dir: Path, sources: tuple[str, ...], output_name: str,
    normalize: Callable[[bytes], str | None],
) -> WordlistStats:
    missing = [name for name in sources if not (dest_dir / name).is_file()]
    if missing:
        raise SelfListLoadError(f"Отсутствуют файлы для {output_name}: {', '.join(missing)}")
    output = dest_dir / output_name
    output.parent.mkdir(parents=True, exist_ok=True)
    before_bytes = output.stat().st_size if output.exists() else 0
    with tempfile.TemporaryDirectory(prefix=".selflistload-merge-", dir=str(output.parent)) as temporary:
        work = Path(temporary)
        chunks, input_lines, ignored = build_wordlist_chunks(dest_dir, sources, work, normalize)
        staged, count = finish_wordlist_chunks(chunks, work)
        after_bytes = staged.stat().st_size
        changed = not output.is_file() or sha256_file(output) != sha256_file(staged)
        if changed:
            previous_lines, added, removed = wordlist_changes(output, staged, count, normalize)
            os.replace(staged, output)
        else:
            previous_lines, added, removed = count, 0, 0
    stats = WordlistStats(output_name, input_lines, ignored, count, input_lines - count,
                          previous_lines, added, removed, before_bytes, after_bytes, changed)
    log_wordlist_stats(stats)
    return stats


def rebuild_dns_wordlist(dest_dir: Path) -> int:
    return rebuild_wordlist(dest_dir, dns_source_names(), OUT_DNS_FILE, normalize_dns_line).unique_lines


def rebuild_web_wordlist(dest_dir: Path) -> int:
    return rebuild_wordlist(dest_dir, WEB_TARGET_NAMES, OUT_WEB_FILE, normalize_web_line).unique_lines


def log_unchanged_wordlist(path: Path, name: str) -> None:
    lines = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            lines += chunk.count(b"\n")
    size = format_size(path.stat().st_size)
    log(f"==> {name} unchanged: {format_count(lines)} unique lines; added: +0; removed: -0")
    log(f"    size: {size} -> {size} (+0 B)")


def _download_zip_member_to_path(
    *,
    label: str,
    zip_url: str,
    member_basename: str,
    dest_path: Path,
) -> bool:
    log(f"==> Winbin: {label}")
    with downloaded_zip(zip_url) as archive:
        with tempfile.TemporaryDirectory(prefix="selflistload-member-") as temporary:
            member_path = Path(temporary) / member_basename
            with zipfile.ZipFile(archive) as zf:
                matches = [info for info in zf.infolist() if not info.is_dir()
                           and Path(info.filename.replace("\\", "/")).name.lower() == member_basename.lower()]
                if not matches:
                    raise SelfListLoadError(f"В архиве не найден файл: {member_basename}")
                matches.sort(key=lambda info: (len(info.filename), info.filename.lower()))
                with zf.open(matches[0]) as source, member_path.open("wb") as target:
                    shutil.copyfileobj(source, target, HTTP_CHUNK_BYTES)
            changed = copy_file_if_changed(dest_path, member_path)
    if changed:
        log(f"    updated: {dest_path}")
    else:
        log(f"    unchanged: {dest_path}")
    return changed


def _sync_zip_bundle(
    *, label: str, zip_data: bytes | Path, bundle_dir: Path, bundle_name: str,
    required_rel_path: str,
) -> bool:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    state = load_state(bundle_dir)
    bundles = state.setdefault("bundles", {})
    if not isinstance(bundles, dict):
        raise SelfListLoadError("Некорректный список Windows-комплектов в state-файле")
    previous = bundles.get(bundle_name, {})
    previous_files = previous.get("files", {})
    archive_sha = sha256_bytes(zip_data) if isinstance(zip_data, bytes) else sha256_file(zip_data)
    if (previous.get("archive_sha256") == archive_sha and required_rel_path in previous_files
            and all(bundle_path(bundle_dir, name).is_file()
                    and sha256_file(bundle_path(bundle_dir, name)) == digest
                    for name, digest in previous_files.items())):
        log(f"    unchanged bundle: {label} -> {bundle_dir}")
        return False

    with tempfile.TemporaryDirectory(prefix=f"{bundle_name}.tmp.", dir=str(bundle_dir.parent)) as temporary:
        stage = Path(temporary) / "files"
        _extract_zip_into_dir(zip_data, stage)
        sources = {path.relative_to(stage).as_posix(): path for path in stage.rglob("*") if path.is_file()}
        outputs = {}
        hashes = {}
        folded = set()
        for name, source in sorted(sources.items()):
            relative = name
            if relative.casefold() in folded or relative.casefold() == META_FILE.casefold():
                raise SelfListLoadError(f"Конфликт имён файлов в архиве {label}: {relative}")
            folded.add(relative.casefold())
            outputs[relative] = source
            hashes[relative] = sha256_file(source)
        if required_rel_path not in outputs:
            raise SelfListLoadError(f"В комплекте {label} не найден {required_rel_path}")

        # Check every path before replacing files in this bundle directory.
        for relative, digest in hashes.items():
            target = bundle_dir / relative
            if target.exists() and not target.is_file():
                raise SelfListLoadError(f"Путь занят каталогом: {target}")
            if target.is_file() and relative not in previous_files \
                    and sha256_file(target) != digest:
                raise SelfListLoadError(f"Файл не принадлежит комплекту {bundle_name}: {target}")
            for parent in target.parents:
                if parent == bundle_dir:
                    break
                if parent.exists() and not parent.is_dir():
                    raise SelfListLoadError(f"Путь занят файлом: {parent}")

        changed = False
        for relative, source in outputs.items():
            changed |= copy_file_if_changed(bundle_dir / relative, source, digest=hashes[relative])
        for relative, digest in previous_files.items():
            if relative in hashes:
                continue
            obsolete = bundle_path(bundle_dir, relative)
            if obsolete.is_file() and sha256_file(obsolete) == digest:
                obsolete.unlink()
                changed = True
        record = {"archive_sha256": archive_sha, "files": hashes}
        if record != previous:
            bundles[bundle_name] = record
            save_state(bundle_dir, state)
            changed = True
    log(f"    {'updated' if changed else 'unchanged'} bundle: {label} -> {bundle_dir}")
    return changed


def run_winbins_download() -> int:
    winbins_dir = ensure_winbins_dir()
    log(f"==> Winbins dir: {winbins_dir}")

    changed_count = 0

    if _download_zip_member_to_path(
        label="psexec.exe",
        zip_url="https://download.sysinternals.com/files/PSTools.zip",
        member_basename="PsExec.exe",
        dest_path=winbins_dir / "psexec.exe",
    ):
        changed_count += 1

    if _download_zip_member_to_path(
        label="procdump.exe",
        zip_url="https://download.sysinternals.com/files/Procdump.zip",
        member_basename="procdump.exe",
        dest_path=winbins_dir / "procdump.exe",
    ):
        changed_count += 1

    if _download_zip_member_to_path(
        label="nc.exe (Ncat portable)",
        zip_url=NCAT_PORTABLE_URL,
        member_basename="ncat.exe",
        dest_path=winbins_dir / "nc.exe",
    ):
        changed_count += 1

    log("==> Winbin: ssh.exe (Win32-OpenSSH bundle)")
    openssh_asset_name, openssh_url = github_latest_release_asset_url(
        "PowerShell",
        "Win32-OpenSSH",
        asset_pattern=r"^OpenSSH-Win64\.zip$",
    )
    log(f"    source: {openssh_asset_name}")
    with downloaded_zip(openssh_url) as openssh_zip:
        if _sync_zip_bundle(
            label="OpenSSH-Win64.zip", zip_data=openssh_zip, bundle_dir=winbins_dir / "ssh",
            bundle_name="openssh", required_rel_path="ssh.exe",
        ):
            changed_count += 1

    log("==> Winbin: pwsh.exe (PowerShell 7)")
    pwsh_asset_name, pwsh_url = github_latest_release_asset_url(
        "PowerShell",
        "PowerShell",
        asset_pattern=r"^PowerShell-\d+\.\d+\.\d+-win-x64\.zip$",
    )
    log(f"    source: {pwsh_asset_name}")
    with downloaded_zip(pwsh_url) as pwsh_zip:
        if _sync_zip_bundle(
            label=pwsh_asset_name, zip_data=pwsh_zip, bundle_dir=winbins_dir / "pwsh",
            bundle_name="powershell", required_rel_path="pwsh.exe",
        ):
            changed_count += 1

    readme = winbins_dir / "README.txt"
    if readme.is_file():
        readme.unlink()
    return changed_count


def current_download_targets(*, failures: list[tuple[str, str]] | None = None) -> tuple[DownloadTarget, ...]:
    if not any(target.assetnote_prefix for target in TARGETS):
        return TARGETS
    catalog_error = None
    try:
        rows = http_get_json(ASSETNOTE_CATALOG_URL).get("data")
        if not isinstance(rows, list):
            raise SelfListLoadError("Каталог Assetnote не содержит список data")
    except SelfListLoadError as exc:
        if failures is None:
            raise
        catalog_error = str(exc)
        rows = []
    targets = []
    for target in TARGETS:
        if target.assetnote_prefix is None:
            targets.append(target)
            continue
        if catalog_error is not None:
            failures.append((target.name, f"Assetnote catalog unavailable: {catalog_error}"))
            continue
        pattern = re.compile(re.escape(target.assetnote_prefix) + r"\d{4}_\d{2}_\d{2}\.txt")
        names = [row["Filename"] for row in rows if isinstance(row, dict)
                 and isinstance(row.get("Filename"), str) and pattern.fullmatch(row["Filename"])]
        if not names:
            message = f"В каталоге Assetnote нет списка {target.assetnote_prefix}"
            if failures is None:
                raise SelfListLoadError(message)
            failures.append((target.name, message))
            continue
        # YYYY_MM_DD names sort chronologically, independent of the local filename.
        url = "https://wordlists-cdn.assetnote.io/data/automated/" + max(names)
        targets.append(replace(target, url=url))
    return tuple(targets)


def print_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    widths = [max(len(row[index]) for row in [headers, *rows]) for index in range(len(headers))]
    for row in [headers, *rows]:
        log("  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip())


def digest_wordlist(path: Path, *, compressed: bool = False) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    opener = open_wordlist if compressed else open
    with opener(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(HTTP_CHUNK_BYTES), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def verify_port_file(path: Path, count: int, *, ascending: bool = False, compressed: bool = False) -> list[int]:
    opener = open_wordlist if compressed else open
    with opener(path, "rt", encoding="utf-8", newline="") as stream:
        text = stream.read(count * 6 + 1)
    if len(text) > count * 6:
        raise SelfListLoadError(f"port file is too long for {count} ports")
    if not re.fullmatch(r"[0-9]+(?:,[0-9]+)*\n?", text):
        raise SelfListLoadError("expected one comma-separated line of ports")
    ports = [int(value) for value in text.strip().split(",")]
    if any(port < 1 or port > 65535 for port in ports):
        raise SelfListLoadError("port outside 1..65535")
    if len(ports) != len(set(ports)):
        raise SelfListLoadError("duplicate ports")
    if len(ports) != count:
        raise SelfListLoadError(f"expected {count} ports, found {len(ports)}")
    if ascending and ports != sorted(ports):
        raise SelfListLoadError("custom ports are not sorted numerically")
    return ports


def verify_aggregate(path: Path, name: str, *, compressed: bool = False) -> None:
    normalize = normalize_dns_line if name == OUT_DNS_FILE else normalize_web_line
    opener = open_wordlist if compressed else open
    previous = None
    with opener(path, "rb") as stream:
        for number, raw in enumerate(stream, 1):
            value = normalize(raw)
            if value is None or raw != value.encode("utf-8") + b"\n":
                raise SelfListLoadError(f"noncanonical aggregate entry at line {number}")
            word = value.encode("utf-8")
            if previous is not None and word <= previous:
                problem = "duplicate entry" if word == previous else "entries are not sorted"
                raise SelfListLoadError(f"{problem} at line {number}")
            previous = word
    if previous is None:
        raise SelfListLoadError("empty aggregate")


def verify_custom_dns(path: Path, length: int, *, compressed: bool = False) -> None:
    opener = open_wordlist if compressed else open
    pattern = re.compile(br"[0-9a-z]{" + str(length).encode("ascii") + br"}\n")
    count = 0
    previous = None
    with opener(path, "rb") as stream:
        for count, raw in enumerate(stream, 1):
            if not pattern.fullmatch(raw) or (previous is not None and raw <= previous):
                raise SelfListLoadError(f"invalid or unsorted custom DNS entry at line {count}")
            previous = raw
    expected = len(CUSTOM_DNS_ALPHABET) ** length
    if count != expected:
        raise SelfListLoadError(f"expected {expected} custom DNS entries, found {count}")


def verify_list_content(path: Path, name: str, *, compressed: bool = False) -> list[int] | None:
    port_sizes = {nmap_port_file(size): size for size in PORT_TOP_SIZES}
    port_sizes.update({PORT_CUSTOM_FILE: 2000, PORT_WEB_FILE: 1000})
    if name in port_sizes:
        return verify_port_file(path, port_sizes[name], ascending=name in (PORT_CUSTOM_FILE, PORT_WEB_FILE),
                                compressed=compressed)
    if name in custom_dns_sources():
        verify_custom_dns(path, custom_dns_sources()[name], compressed=compressed)
        return None
    target = next((target for target in TARGETS if target.name == name), DownloadTarget(name, ""))
    validate_wordlist(path, target, {}, compressed=compressed)
    if name in (OUT_DNS_FILE, OUT_WEB_FILE):
        verify_aggregate(path, name, compressed=compressed)
    return None


def verify_nmap_prefixes(ports: dict[str, list[int]]) -> list[str]:
    errors = []
    for smaller, larger in zip(PORT_TOP_SIZES, PORT_TOP_SIZES[1:]):
        left, right = nmap_port_file(smaller), nmap_port_file(larger)
        if left in ports and right in ports and ports[left] != ports[right][:smaller]:
            errors.append(f"{left}: does not match the first {smaller} ports of {right}")
    return errors


def verify_repository(repo_dir: Path, *, quiet: bool = False) -> list[str]:
    errors = []
    ports = {}
    expected = set(snapshot_file_names(repo_dir))
    seen = set()
    stored_seen = set()
    try:
        manifest = json.loads((repo_dir / BUNDLE_FILE).read_text(encoding="utf-8"))
        if (not isinstance(manifest, dict) or manifest.get("version") != 1
                or not isinstance(manifest.get("files"), list)):
            raise ValueError("expected a version 1 manifest with a files array")
    except (OSError, ValueError) as exc:
        return [f"{BUNDLE_FILE}: {exc}"]
    for entry in manifest["files"]:
        name = entry.get("path") if isinstance(entry, dict) else None
        try:
            if not isinstance(name, str) or name not in expected:
                raise SelfListLoadError(f"unexpected dictionary path: {name!r}")
            if name in seen:
                raise SelfListLoadError("duplicate manifest entry")
            seen.add(name)
            compressed = entry.get("compression") in ("gzip", "xz")
            if entry.get("compression") not in ("gzip", "xz", "none"):
                raise SelfListLoadError("unsupported compression")
            stored_name = entry.get("stored_path")
            if stored_name != name + {"gzip": ".gz", "xz": ".xz", "none": ""}[entry["compression"]] or stored_name in stored_seen:
                raise SelfListLoadError("invalid or duplicate stored path")
            stored_seen.add(stored_name)
            path = snapshot_target(repo_dir, stored_name)
            if not path.is_file():
                raise SelfListLoadError(f"missing file: {stored_name}")
            if path.stat().st_size > MAX_BUNDLE_FILE_BYTES:
                raise SelfListLoadError("stored file exceeds the size limit")
            for key in ("sha256", "stored_sha256"):
                if not isinstance(entry.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", entry[key]):
                    raise SelfListLoadError(f"invalid {key} in manifest")
            if type(entry.get("size")) is not int or entry["size"] < 0:
                raise SelfListLoadError("invalid uncompressed size in manifest")
            digest, size = digest_wordlist(path, compressed=compressed)
            if digest != entry["sha256"] or size != entry["size"]:
                errors.append(f"{name}: uncompressed checksum or size mismatch")
            stored_digest = sha256_file(path) if compressed else digest
            if stored_digest != entry["stored_sha256"]:
                errors.append(f"{name}: stored checksum mismatch")
            values = verify_list_content(path, name, compressed=compressed)
            if values is not None:
                ports[name] = values
            if not quiet:
                log(f"    checked: {name}")
        except (SelfListLoadError, OSError, EOFError, UnicodeError, ValueError, zlib.error, lzma.LZMAError) as exc:
            errors.append(f"{name or BUNDLE_FILE}: {exc}")
    errors.extend(f"{name}: missing manifest entry" for name in sorted(expected - seen))
    errors.extend(verify_nmap_prefixes(ports))
    return errors


def run_verify(root: Path, *, repository: bool = False) -> int:
    if not root.is_dir():
        raise SelfListLoadError(f"Wordlist directory does not exist: {root}")
    log(f"==> Verify {'repository' if repository else 'installed wordlists'}: {root}")
    if repository:
        errors = verify_repository(root)
        if (root / SNAPSHOT_TRANSACTION_DIR).exists():
            errors.append("unfinished refresh publication; run refresh to recover")
    else:
        errors = []
        ports = {}
        unchecked = []
        try:
            state = load_state(root)
        except SelfListLoadError as exc:
            errors.append(str(exc))
            state = {"files": {}}
        for name in snapshot_file_names(root):
            try:
                path = root / name
                if not path.is_file():
                    raise SelfListLoadError("missing file")
                digest, _ = digest_wordlist(path)
                record = state["files"].get(name, {})
                saved = record.get("sha256") if isinstance(record, dict) else None
                if saved and digest != saved:
                    errors.append(f"{name}: checksum differs from the last accepted version")
                elif not saved:
                    unchecked.append(name)
                values = verify_list_content(path, name)
                if values is not None:
                    ports[name] = values
                log(f"    checked: {name}")
            except (SelfListLoadError, OSError, EOFError, UnicodeError, ValueError, zlib.error, lzma.LZMAError) as exc:
                errors.append(f"{name}: {exc}")
        errors.extend(verify_nmap_prefixes(ports))
        if unchecked:
            log(f"    No saved checksum for {len(unchecked)} file(s); content checks performed only.")
    for message in errors:
        log(f"ERROR: {message}")
    log(f"==> Verification {'failed' if errors else 'passed'} ({len(errors)} errors)")
    return len(errors)


def run_status(dest_dir: Path) -> None:
    if not dest_dir.is_dir():
        raise SelfListLoadError(f"Wordlist directory does not exist: {dest_dir}")
    state = load_state(dest_dir)
    rows = []
    generated = {OUT_DNS_FILE, OUT_WEB_FILE, *custom_dns_sources()}
    for name in snapshot_file_names(dest_dir):
        path = dest_dir / name
        if not path.is_file():
            rows.append((name, "missing", "-", "-"))
            continue
        if name.startswith("ports/"):
            try:
                entries = format_count(len(read_port_list(path)))
            except SelfListLoadError:
                entries = "invalid"
        else:
            entries = format_count(count_file_lines(path))
        record = state["files"].get(name, {})
        checked = "not checked"
        if isinstance(record, dict) and record.get("checked_at"):
            checked = str(record["checked_at"]) if record.get("sha256") == sha256_file(path) else "locally modified"
        elif name in generated or name.startswith("ports/"):
            checked = "- (generated)"
        rows.append((name, entries, format_size(path.stat().st_size), checked))
    log(f"==> Installed wordlists: {dest_dir}")
    print_table(("File", "Lines / ports", "Size", "Last source check (UTC)"), rows)


@dataclass(frozen=True)
class DNSContribution:
    name: str
    unique_entries: int
    exclusive_entries: int


def dns_contributions(dest_dir: Path) -> tuple[int, list[DNSContribution]]:
    names = dns_source_names()
    missing = [name for name in names if not (dest_dir / name).is_file()]
    if missing:
        raise SelfListLoadError(f"Missing DNS sources: {', '.join(missing)}")
    sorted_sources = []
    counts = []
    exclusive = [0] * len(names)
    total = 0
    with tempfile.TemporaryDirectory(prefix="selflistload-dns-stats-") as temporary:
        for index, name in enumerate(names):
            log(f"==> Analyze: {name}")
            work = Path(temporary) / str(index)
            work.mkdir()
            chunks, _, _ = build_wordlist_chunks(dest_dir, (name,), work, normalize_dns_line)
            path, count = finish_wordlist_chunks(chunks, work)
            sorted_sources.append(path)
            counts.append(count)
        with ExitStack() as stack:
            streams = [stack.enter_context(path.open("rb")) for path in sorted_sources]
            tagged = [zip(_chunk_words(stream), itertools.repeat(index)) for index, stream in enumerate(streams)]
            for _, entries in itertools.groupby(heapq.merge(*tagged), key=lambda entry: entry[0]):
                owners = 0
                for _, index in entries:
                    owners |= 1 << index
                total += 1
                if owners & (owners - 1) == 0:
                    exclusive[owners.bit_length() - 1] += 1
    return total, [DNSContribution(name, count, only)
                   for name, count, only in zip(names, counts, exclusive)]


def run_dns_stats(dest_dir: Path) -> None:
    total, contributions = dns_contributions(dest_dir)
    rows = [(item.name, format_count(item.unique_entries), format_count(item.exclusive_entries),
             format_count(item.unique_entries - item.exclusive_entries)) for item in contributions]
    log(f"==> Combined DNS entries: {format_count(total)}")
    print_table(("Source", "Unique", "Exclusive", "Shared"), rows)
    log("Exclusive entries are absent from every other source; shared entries occur in multiple sources.")


def sync_wordlists(
    dest_dir: Path, state: dict[str, Any], *, mode: str, force_dns: bool = False, force_web: bool = False,
    keep_progress: bool = False, allow_shrink: bool = False,
) -> int:
    prepare_layout(dest_dir, state)
    dns_sources_touched = force_dns or bool(state.get("rebuild_dns")) or mode == "download"
    web_sources_touched = force_web or bool(state.get("rebuild_web")) or mode == "download"
    failures: list[tuple[str, str]] = []
    targets = current_download_targets(failures=failures)
    progress = state.get("sync")
    if not isinstance(progress, dict) or not isinstance(progress.get("completed"), dict):
        progress = {"completed": {}}
        state["sync"] = progress
    completed = progress["completed"]
    save_state(dest_dir, state)
    changed_count = sync_custom_dns_lists(dest_dir, state)
    accepted_outputs = set()
    for target in targets:
        checked = completed.get(target.name)
        path = dest_dir / target.name
        if (isinstance(checked, dict) and checked.get("url") == target.url
                and isinstance(checked.get("sha256"), str) and path.is_file()
                and sha256_file(path) == checked["sha256"]):
            log(f"    resumed: {target.name} (already completed)")
            continue
        try:
            status = download_target(target, dest_dir=dest_dir, state=state, mode=mode, allow_shrink=allow_shrink)
        except SelfListLoadError as exc:
            failures.append((target.name, str(exc)))
            log(f"    failed: {target.name}; {'previous file retained' if path.is_file() else 'no local copy'}")
            continue
        if status in {"downloaded", "updated"}:
            changed_count += 1
            log(f"    {status}: {target.name}")
            dns_sources_touched |= target.is_dns_source
            web_sources_touched |= target.is_web_source
        else:
            log(f"    unchanged: {target.name}")

    for name, sources, normalize, touched in (
        (OUT_DNS_FILE, dns_source_names(), normalize_dns_line, dns_sources_touched),
        (OUT_WEB_FILE, WEB_TARGET_NAMES, normalize_web_line, web_sources_touched),
    ):
        flag = "rebuild_dns" if name == OUT_DNS_FILE else "rebuild_web"
        if touched or state.get(flag) or not (dest_dir / name).exists():
            state[flag] = True
            save_state(dest_dir, state)
            missing = [source for source in sources if not (dest_dir / source).is_file()]
            if missing:
                failures.append((name, f"rebuild skipped; missing sources: {', '.join(missing)}"))
                continue
            stats = rebuild_wordlist(dest_dir, sources, name, normalize)
            changed_count += int(stats.changed)
            accepted_outputs.add(name)
            state.pop(flag, None)
            save_state(dest_dir, state)
        else:
            log_unchanged_wordlist(dest_dir / name, name)
    prepare_layout(dest_dir, state)
    try:
        changed_count += sync_port_lists(dest_dir)
        accepted_outputs.update(nmap_port_file(size) for size in PORT_TOP_SIZES)
        accepted_outputs.update((PORT_CUSTOM_FILE, PORT_WEB_FILE))
    except SelfListLoadError as exc:
        failures.append(("ports/nmap-services", str(exc)))
    for name in accepted_outputs:
        path = dest_dir / name
        if path.is_file():
            state["files"][name] = {"sha256": sha256_file(path)}
    if failures:
        progress["failures"] = dict(failures)
    elif not keep_progress:
        state.pop("sync", None)
    else:
        progress.pop("failures", None)
    save_state(dest_dir, state)
    if failures:
        log(f"==> Update summary: {changed_count} changed files; {len(failures)} failed tasks")
        for name, message in failures:
            log(f"    failed: {name}: {message}")
        raise SourceSyncError(failures, changed_count)
    return changed_count


def run_download(dest_dir: Path, state: dict[str, Any], *, lists_only: bool = False, allow_shrink: bool = False) -> int:
    prepare_layout(dest_dir, state)
    if find_bundle_dir() is not None:
        changed_count = install_snapshot(dest_dir, state, overwrite=True)
        changed_count += normalize_port_lists(dest_dir)
        prepare_layout(dest_dir, state)
    else:
        changed_count = sync_wordlists(dest_dir, state, mode="download", keep_progress=not lists_only,
                                       allow_shrink=allow_shrink)
    if not lists_only:
        changed_count += run_winbins_download()
    state.pop("sync", None)
    save_state(dest_dir, state)
    return changed_count


def run_update(dest_dir: Path, state: dict[str, Any], *, allow_shrink: bool = False) -> int:
    prepare_layout(dest_dir, state)
    missing_dns = not (dest_dir / OUT_DNS_FILE).exists()
    missing_web = not (dest_dir / OUT_WEB_FILE).exists()
    changed_count = install_snapshot(dest_dir, state)
    return changed_count + sync_wordlists(dest_dir, state, mode="update", force_dns=missing_dns,
                                          force_web=missing_web, allow_shrink=allow_shrink)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="selflistload",
        description="Download/update categorized wordlists and port sets in ~/selflists; download also prepares ~/winbins",
    )
    subparsers = parser.add_subparsers(dest="command")
    download = subparsers.add_parser(
        "download",
        help="Install bundled wordlists and port sets, and prepare ~/winbins",
    )
    update = subparsers.add_parser(
        "update",
        help="Update changed sources, rebuild combined wordlists, and refresh port sets",
    )
    status = subparsers.add_parser("status", help="Show local wordlist counts, sizes, and last source checks")
    dns_stats = subparsers.add_parser("dns-stats", help="Analyze exclusive and shared entries in local DNS sources")
    verify = subparsers.add_parser("verify", help="Check dictionary integrity and port list correctness offline")
    verify_paths = verify.add_mutually_exclusive_group()
    verify_paths.add_argument("--dest", type=Path, default=APP_DIR, help="Installed wordlist directory")
    verify_paths.add_argument("--repo", type=Path, help="Verify stored repository files instead of installed lists")
    for command in (download, update, status, dns_stats):
        command.add_argument("--dest", type=Path, default=APP_DIR,
                             help="Installation directory (default: ~/selflists)")
    download.add_argument("--lists-only", action="store_true",
                          help="Install wordlists without downloading Windows utilities")
    refresh = subparsers.add_parser("refresh", help="Update the repository snapshot from original sources")
    refresh.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent,
                         help="Path to the Selflists source checkout")
    for command in (download, update, refresh):
        command.add_argument("--allow-shrink", action="store_true",
                             help="Accept large source reductions after inspecting the upstream wordlist")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    command = args.command or "download"

    try:
        if command == "refresh":
            run_refresh(args.repo.expanduser().resolve(), allow_shrink=args.allow_shrink)
            return 0
        if command == "verify":
            root = args.repo if args.repo is not None else args.dest
            return int(run_verify(root.expanduser().resolve(), repository=args.repo is not None) > 0)
        if command in {"status", "dns-stats"}:
            dest_dir = args.dest.expanduser().resolve()
            if command == "status":
                run_status(dest_dir)
            else:
                run_dns_stats(dest_dir)
            return 0
        # With no subcommand, retain the historical download default.
        dest_dir = ensure_app_dir(getattr(args, "dest", APP_DIR).expanduser().resolve())
        log(f"==> Save dir: {dest_dir}")
        state = load_state(dest_dir)

        if command == "download":
            changed_count = run_download(dest_dir, state, lists_only=getattr(args, "lists_only", False),
                                          allow_shrink=getattr(args, "allow_shrink", False))
        elif command == "update":
            changed_count = run_update(dest_dir, state, allow_shrink=args.allow_shrink)
        else:
            raise SelfListLoadError(f"Неизвестная команда: {command}")

        save_state(dest_dir, state)
        log(f"==> Done ({command}). Changed files: {changed_count}")
        return 0
    except KeyboardInterrupt:
        log("ERROR: Остановлено пользователем")
        return 130
    except SelfListLoadError as exc:
        log(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
