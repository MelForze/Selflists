#!/usr/bin/env python3
"""Download wordlists into ~/selflists and prepare Windows admin tools in ~/winbins."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib import error, request


APP_DIR = Path.home() / "selflists"
WINBINS_DIR = Path.home() / "winbins"
META_FILE = ".selflistload_state.json"
OUT_DNS_FILE = "biggest_dnslist.txt"
USER_AGENT = "selflistload/0.1"
HTTP_TIMEOUT = 30
HTTP_RETRIES = 3
RETRY_DELAY_SEC = 2
NCAT_PORTABLE_URL = "https://nmap.org/dist/ncat-portable-5.59BETA1.zip"


@dataclass(frozen=True)
class DownloadTarget:
    name: str
    url: str
    is_dns_source: bool = False


TARGETS: tuple[DownloadTarget, ...] = (
    DownloadTarget(
        "fuzz.txt",
        "https://github.com/Bo0oM/fuzz.txt/raw/refs/heads/master/fuzz.txt",
    ),
    DownloadTarget(
        "hfuzz.txt",
        "https://github.com/thehlopster/hfuzz/raw/refs/heads/master/hfuzz.txt",
    ),
    DownloadTarget(
        "content_discovery_all.txt",
        "https://gist.github.com/jhaddix/b80ea67d85c13206125806f0828f4d10/raw/"
        "c81a34fe84731430741e0463eb6076129c20c4c0/content_discovery_all.txt",
    ),
    DownloadTarget(
        "api.txt",
        "https://gist.github.com/MelForze/7292bec4a39b0a376cd1acfcc8b6ab85/raw/"
        "3f51a2859d954d29d31773ff1daff0bb20777c8a/api-endpoints.txt",
    ),
    DownloadTarget(
        "openapi",
        "https://github.com/z5jt/API-documentation-Wordlist/raw/refs/heads/main/"
        "API-Documentation-Wordlist/api-documentation-endpoint.txt",
    ),
    DownloadTarget(
        "dodgypass.txt",
        "https://raw.githubusercontent.com/mohemiv/dodgypass/refs/heads/main/dodgypass.txt",
    ),
    DownloadTarget(
        "best-dns-wordlist.txt",
        "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "FUZZSUBS_CYFARE_1.txt",
        "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/"
        "Discovery/DNS/FUZZSUBS_CYFARE_1.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "FUZZSUBS_CYFARE_2.txt",
        "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/"
        "Discovery/DNS/FUZZSUBS_CYFARE_2.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "n0kovo_subdomains",
        "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/"
        "Discovery/DNS/n0kovo_subdomains.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "combined_subdomains.txt",
        "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/"
        "Discovery/DNS/combined_subdomains.txt",
        is_dns_source=True,
    ),
    DownloadTarget(
        "namelist.txt",
        "https://github.com/danielmiessler/SecLists/raw/refs/heads/master/"
        "Discovery/DNS/namelist.txt",
        is_dns_source=True,
    ),
)

DNS_TARGET_NAMES = tuple(t.name for t in TARGETS if t.is_dns_source)


class SelfListLoadError(RuntimeError):
    pass


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


def ensure_app_dir() -> Path:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    return APP_DIR


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


def save_state(dest_dir: Path, state: dict[str, Any]) -> None:
    path = dest_dir / META_FILE
    state.setdefault("files", {})
    state["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    data = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, data)


def _safe_rel_zip_path(name: str) -> Path:
    normalized = name.replace("\\", "/").strip("/")
    parts = [p for p in normalized.split("/") if p not in {"", "."}]
    if any(part == ".." for part in parts):
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


def _zip_member_bytes(zip_data: bytes, *, basename: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
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


def _extract_zip_into_dir(zip_data: bytes, dest_dir: Path) -> None:
    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    stage_dir = Path(tempfile.mkdtemp(prefix=f"{dest_dir.name}.tmp.", dir=str(dest_dir.parent)))
    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            files = [info for info in zf.infolist() if not info.is_dir()]
            root_prefix = _common_zip_root(files)
            for info in files:
                rel = _safe_rel_zip_path(info.filename)
                if not rel.parts:
                    continue
                if root_prefix and rel.parts[0] == root_prefix:
                    rel = Path(*rel.parts[1:])
                if not rel.parts:
                    continue
                out_path = stage_dir / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src:
                    atomic_write_bytes(out_path, src.read())
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
    headers = {"User-Agent": USER_AGENT}
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
        except error.URLError as exc:
            last_exc = exc
            if attempt == HTTP_RETRIES:
                break
        time.sleep(RETRY_DELAY_SEC * attempt)
    raise SelfListLoadError(f"Ошибка загрузки {url}: {last_exc}")


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


def download_target(
    target: DownloadTarget,
    *,
    dest_dir: Path,
    state: dict[str, Any],
    mode: str,
) -> str:
    """Return status: downloaded | updated | unchanged."""
    files_state: dict[str, Any] = state.setdefault("files", {})
    file_state = files_state.get(target.name)
    if not isinstance(file_state, dict):
        file_state = {}
        files_state[target.name] = file_state

    path = dest_dir / target.name
    conditional = _build_conditional_headers(file_state) if mode == "update" else {}

    log(f"==> Check: {target.name}")
    status_code, body, headers = http_get_with_retries(target.url, conditional=conditional or None)

    if status_code == 304:
        if not path.exists():
            # Remote says "not modified", but local file is missing: force re-download.
            log(f"    local file missing, forcing download: {target.name}")
            status_code, body, headers = http_get_with_retries(target.url, conditional=None)
        else:
            _set_state_from_response(file_state, target=target, headers=headers)
            return "unchanged"

    if body is None:
        raise SelfListLoadError(f"Пустой ответ при загрузке {target.name}")

    new_sha = sha256_bytes(body)
    old_sha = sha256_file(path) if path.exists() else None

    if old_sha == new_sha:
        _set_state_from_response(file_state, target=target, headers=headers, sha256=new_sha)
        return "unchanged"

    atomic_write_bytes(path, body)
    _set_state_from_response(file_state, target=target, headers=headers, sha256=new_sha)
    return "downloaded" if old_sha is None else "updated"


def normalize_dns_line(raw: bytes) -> str | None:
    # Preserve shell-script behavior: remove CR, trim trailing whitespace, drop empty lines.
    line = raw.replace(b"\r", b"").decode("utf-8", errors="replace").rstrip()
    if not line.strip():
        return None
    return line


def rebuild_dns_wordlist(dest_dir: Path) -> int:
    missing = [name for name in DNS_TARGET_NAMES if not (dest_dir / name).is_file()]
    if missing:
        raise SelfListLoadError(f"Отсутствуют DNS-файлы: {', '.join(missing)}")

    unique_lines: set[str] = set()
    for name in DNS_TARGET_NAMES:
        path = dest_dir / name
        with path.open("rb") as fh:
            for raw in fh:
                line = normalize_dns_line(raw)
                if line is not None:
                    unique_lines.add(line)

    # Closer to LC_ALL=C sort for ASCII-dominant inputs.
    sorted_lines = sorted(unique_lines, key=lambda s: s.encode("utf-8"))
    content = "\n".join(sorted_lines)
    if sorted_lines:
        content += "\n"

    out_path = dest_dir / OUT_DNS_FILE
    atomic_write_text(out_path, content)
    return len(sorted_lines)


def _download_zip_member_to_path(
    *,
    label: str,
    zip_url: str,
    member_basename: str,
    dest_path: Path,
) -> bool:
    log(f"==> Winbin: {label}")
    zip_data, _headers = http_get_bytes(zip_url)
    member_data = _zip_member_bytes(zip_data, basename=member_basename)
    changed = write_bytes_if_changed(dest_path, member_data)
    if changed:
        log(f"    updated: {dest_path}")
    else:
        log(f"    unchanged: {dest_path}")
    return changed


def _sync_zip_bundle(
    *,
    label: str,
    zip_data: bytes,
    bundle_dir: Path,
    required_rel_path: str,
) -> bool:
    marker_path = bundle_dir / ".bundle_sha256"
    archive_sha = sha256_bytes(zip_data)
    marker_sha: str | None = None
    if marker_path.exists():
        try:
            marker_sha = marker_path.read_text(encoding="utf-8").strip()
        except OSError:
            marker_sha = None

    required_path = bundle_dir / required_rel_path
    if bundle_dir.is_dir() and required_path.exists() and marker_sha == archive_sha:
        log(f"    unchanged bundle: {label} -> {bundle_dir}")
        return False

    _extract_zip_into_dir(zip_data, bundle_dir)
    atomic_write_text(marker_path, archive_sha + "\n")

    if not required_path.exists():
        raise SelfListLoadError(f"В bundle {label} не найден ожидаемый файл: {required_rel_path}")

    log(f"    updated bundle: {label} -> {bundle_dir}")
    return True


def _write_winbins_readme(winbins_dir: Path) -> None:
    readme = (
        "selflistload winbins\n"
        "\n"
        "Файлы/папки:\n"
        "- psexec.exe (из Sysinternals PSTools)\n"
        "- procdump.exe (из Sysinternals ProcDump)\n"
        "- nc.exe (переименованный ncat.exe из официального portable архива Ncat)\n"
        "- openssh/ssh.exe (portable bundle Win32-OpenSSH; используйте вместе с остальными файлами в openssh/)\n"
        "- powershell/pwsh.exe (portable PowerShell 7; отдельный redistributable powershell.exe обычно не поставляется)\n"
        "\n"
        "Примечание:\n"
        "- Для OpenSSH и PowerShell сохраняются целые bundle-папки, потому что одиночный .exe часто не работает без зависимостей.\n"
    )
    write_text_if_changed(winbins_dir / "README.txt", readme)


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
    openssh_zip, _headers = http_get_bytes(openssh_url)
    if _sync_zip_bundle(
        label="OpenSSH-Win64.zip",
        zip_data=openssh_zip,
        bundle_dir=winbins_dir / "openssh",
        required_rel_path="ssh.exe",
    ):
        changed_count += 1

    log("==> Winbin: powershell.exe (portable PowerShell bundle)")
    pwsh_asset_name, pwsh_url = github_latest_release_asset_url(
        "PowerShell",
        "PowerShell",
        asset_pattern=r"^PowerShell-\d+\.\d+\.\d+-win-x64\.zip$",
    )
    log(f"    source: {pwsh_asset_name}")
    pwsh_zip, _headers = http_get_bytes(pwsh_url)
    if _sync_zip_bundle(
        label=pwsh_asset_name,
        zip_data=pwsh_zip,
        bundle_dir=winbins_dir / "powershell",
        required_rel_path="pwsh.exe",
    ):
        changed_count += 1
    log("    note: в portable bundle используется pwsh.exe (не system powershell.exe)")

    _write_winbins_readme(winbins_dir)
    return changed_count


def run_download(dest_dir: Path, state: dict[str, Any]) -> int:
    changed_count = 0
    for target in TARGETS:
        status = download_target(target, dest_dir=dest_dir, state=state, mode="download")
        if status in {"downloaded", "updated"}:
            changed_count += 1
            log(f"    {status}: {target.name}")
        else:
            log(f"    unchanged: {target.name}")

    line_count = rebuild_dns_wordlist(dest_dir)
    log(f"==> Rebuilt {OUT_DNS_FILE} ({line_count} lines)")
    changed_count += run_winbins_download()
    return changed_count


def run_update(dest_dir: Path, state: dict[str, Any]) -> int:
    dns_sources_touched = False
    changed_count = 0

    for target in TARGETS:
        status = download_target(target, dest_dir=dest_dir, state=state, mode="update")
        if status in {"downloaded", "updated"}:
            changed_count += 1
            log(f"    {status}: {target.name}")
            if target.is_dns_source:
                dns_sources_touched = True
        else:
            log(f"    unchanged: {target.name}")

    out_path = dest_dir / OUT_DNS_FILE
    if dns_sources_touched or not out_path.exists():
        line_count = rebuild_dns_wordlist(dest_dir)
        log(f"==> Rebuilt {OUT_DNS_FILE} ({line_count} lines)")
    else:
        log(f"==> DNS sources unchanged, skipped rebuild of {OUT_DNS_FILE}")

    return changed_count


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="selflistload",
        description="Download/update wordlists in ~/selflists; download also prepares ~/winbins",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser(
        "download",
        help="Download wordlists, rebuild DNS list, and prepare ~/winbins",
    )
    subparsers.add_parser(
        "update",
        help="Check remote changes and update only changed files; rebuild DNS list if needed",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    command = args.command or "download"

    try:
        dest_dir = ensure_app_dir()
        log(f"==> Save dir: {dest_dir}")
        state = load_state(dest_dir)

        if command == "download":
            changed_count = run_download(dest_dir, state)
        elif command == "update":
            changed_count = run_update(dest_dir, state)
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
