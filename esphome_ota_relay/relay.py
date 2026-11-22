"""Receive a firmware.ota.bin and flash an ESPHome device on the LAN."""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

OPTIONS_PATH = Path(os.environ.get("OPTIONS_PATH", "/data/options.json"))
CONFIG_DIR = Path(os.environ.get("CONFIG_DIR", "/config"))
MAX_FIRMWARE_BYTES = 16 * 1024 * 1024
HOSTNAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
MDNS_TYPE = "_esphomelib._tcp.local."
MDNS_CACHE_SECONDS = 30

log = logging.getLogger("ota-relay")
_JOB: contextvars.ContextVar[Job | None] = contextvars.ContextVar("job", default=None)


class ImageRejected(Exception):
    pass


@dataclass
class Target:
    name: str
    host: str
    key: str | None
    aliases: set[str] = field(default_factory=set)

    def public(self, online: bool) -> dict[str, Any]:
        return {"name": self.name, "host": self.host, "online": online}


@dataclass
class Job:
    id: str
    device: str
    state: str
    percent: int = 0
    error: str | None = None
    log_lines: list[str] = field(default_factory=list)
    lock: threading.Lock = field(repr=False, default_factory=threading.Lock)

    def add_log(self, line: str) -> None:
        text = line.strip()
        if not text:
            return
        self.log_lines.append(text[:500])
        del self.log_lines[:-80]

    def public(self) -> dict[str, Any]:
        return {
            "job_id": self.id,
            "device": self.device,
            "state": self.state,
            "percent": self.percent,
            "error": self.error,
            "log": list(self.log_lines),
        }


class _JobLog(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        job = _JOB.get()
        if job is None:
            return
        job.add_log(record.getMessage())


_jobs: dict[str, Job] = {}
_jobs_guard = threading.Lock()
_device_locks: dict[str, threading.Lock] = {}
_device_locks_guard = threading.Lock()
_mdns_cache: tuple[float, dict[str, str]] = (0.0, {})
_mdns_guard = threading.Lock()
_progress_installed = False


def _load_options() -> dict[str, Any]:
    try:
        raw = json.loads(OPTIONS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        raise SystemExit(f"Cannot read add-on options: {err}") from err
    if not isinstance(raw, dict):
        raise SystemExit("Add-on options must be a JSON object")
    return raw


def _token_ok(header: str, token: str) -> bool:
    if not header.startswith("Bearer "):
        return False
    given = header[7:].strip().encode()
    expected = token.encode()
    if len(given) != len(expected):
        return False
    return hmac.compare_digest(given, expected)


def _read_storage(name: str) -> dict[str, Any]:
    path = CONFIG_DIR / ".storage" / name
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        log.warning("Cannot read %s: %s", name, err)
        return {}
    return data if isinstance(data, dict) else {}


def _storage_list(document: dict[str, Any], key: str) -> list[dict[str, Any]]:
    data = document.get("data")
    if isinstance(data, dict):
        rows = data.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    return []


def _norm(value: Any) -> str:
    return str(value or "").strip().casefold()


def _hostname(value: str) -> str | None:
    text = value.strip().removesuffix(".local").casefold()
    if HOSTNAME.fullmatch(text):
        return text
    return None


def _discover_mdns() -> dict[str, str]:
    """Map an ESPHome node name to an IPv4 address."""
    global _mdns_cache
    now = time.monotonic()
    with _mdns_guard:
        cached_at, cached = _mdns_cache
        if now - cached_at < MDNS_CACHE_SECONDS:
            return dict(cached)
    found: dict[str, str] = {}
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except ImportError:
        log.warning("zeroconf is not installed; device names come from Home Assistant only")
        return {}

    class _Listener(ServiceListener):
        def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name, timeout=1000)
            if info is None:
                return
            instance = name.split("._", 1)[0].casefold()
            host = _hostname(instance)
            if host is None:
                return
            for address in info.parsed_addresses():
                if ":" not in address:
                    found[host] = address
                    return

        def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            self.add_service(zc, type_, name)

        def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
            return

    browser = None
    zc = None
    try:
        zc = Zeroconf()
        browser = ServiceBrowser(zc, MDNS_TYPE, _Listener())
        time.sleep(2.0)
    except Exception as err:
        log.warning("mDNS browse failed: %s", err)
    finally:
        if browser is not None:
            browser.cancel()
        if zc is not None:
            zc.close()
    with _mdns_guard:
        _mdns_cache = (time.monotonic(), dict(found))
    return found


def _manual_targets(options: dict[str, Any]) -> list[Target]:
    rows = options.get("devices") or []
    targets: list[Target] = []
    if not isinstance(rows, list):
        return targets
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = _hostname(str(row.get("name") or ""))
        host = str(row.get("host") or "").strip()
        if name is None or not host:
            log.warning("Skipping a manual device with no name or host")
            continue
        key = str(row.get("encryption_key") or "").strip() or None
        targets.append(Target(name=name, host=host, key=key, aliases={name, host.casefold()}))
    return targets


def _ha_targets() -> list[Target]:
    entries = _storage_list(_read_storage("core.config_entries"), "entries")
    devices = _storage_list(_read_storage("core.device_registry"), "devices")
    by_entry: dict[str, list[dict[str, Any]]] = {}
    for device in devices:
        for entry_id in device.get("config_entries") or []:
            by_entry.setdefault(str(entry_id), []).append(device)

    mdns = _discover_mdns()
    ip_to_name = {ip: name for name, ip in mdns.items()}
    targets: list[Target] = []
    for entry in entries:
        if entry.get("domain") != "esphome" or entry.get("disabled_by"):
            continue
        data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
        host = str(data.get("host") or "").strip()
        if not host:
            continue
        key = str(data.get("noise_psk") or "").strip() or None
        aliases: set[str] = set()
        node = ip_to_name.get(host)
        if node:
            aliases.add(node)
        host_name = _hostname(host)
        if host_name:
            aliases.add(host_name)
        title = _hostname(str(entry.get("title") or ""))
        if title:
            aliases.add(title)
        for device in by_entry.get(str(entry.get("entry_id")), []):
            for label in (device.get("name"), device.get("name_by_user")):
                text = _norm(label)
                if text:
                    aliases.add(text)
                host_label = _hostname(str(label or ""))
                if host_label:
                    aliases.add(host_label)
        name = node or host_name or title
        if name is None:
            raw_title = str(entry.get("title") or "").strip()
            slug = _hostname(re.sub(r"[^a-z0-9]+", "-", raw_title.casefold()).strip("-"))
            name = slug
        if name is None:
            continue
        aliases.add(name)
        aliases.add(host.casefold())
        targets.append(Target(name=name, host=host, key=key, aliases=aliases))
    return targets


def load_targets(options: dict[str, Any]) -> list[Target]:
    """Manual devices replace a Home Assistant device with the same name."""
    merged: dict[str, Target] = {}
    for target in _ha_targets():
        merged[target.name] = target
    for target in _manual_targets(options):
        merged[target.name] = target
    return list(merged.values())


def _resolve_ips(name: str) -> set[str]:
    found: set[str] = set()
    for host in (name, f"{name}.local"):
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        for info in infos:
            found.add(info[4][0])
    return found


def find_target(options: dict[str, Any], requested: str) -> Target | None:
    wanted = requested.strip()
    wanted_host = _hostname(wanted)
    wanted_fold = wanted.casefold()
    targets = load_targets(options)
    exact = [
        target
        for target in targets
        if wanted_fold == target.name or wanted_fold in target.aliases or wanted_fold == target.host.casefold()
    ]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise ImageRejected(f"{requested} matches more than one device")
    ips = _resolve_ips(wanted_host or wanted)
    by_ip = [target for target in targets if target.host in ips]
    if len(by_ip) == 1:
        return by_ip[0]
    if len(by_ip) > 1:
        raise ImageRejected(f"{requested} resolves to more than one device")
    return None


def port_open(host: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def device_online(host: str) -> bool:
    return port_open(host, 3232) or port_open(host, 8266)


def classify_firmware(data: bytes) -> tuple[str, int]:
    from esphome.espota2 import DEFAULT_OTA_PORTS
    from esphome.ota_image import detect_platform, is_factory_image, is_partition_table

    if not data:
        raise ImageRejected("empty firmware file")
    if len(data) > MAX_FIRMWARE_BYTES:
        raise ImageRejected("firmware file is larger than 16MB")
    if is_factory_image(data):
        raise ImageRejected("factory image; upload firmware.ota.bin")
    if is_partition_table(data):
        raise ImageRejected("partition table; upload firmware.ota.bin")
    platform = detect_platform(data)
    if platform is None or platform not in DEFAULT_OTA_PORTS:
        raise ImageRejected("not an ESPHome OTA application image")
    return platform, DEFAULT_OTA_PORTS[platform]


def _install_progress_hook() -> None:
    global _progress_installed
    if _progress_installed:
        return
    from esphome.helpers import ProgressBar

    original = ProgressBar.update

    def update(self: ProgressBar, progress: float) -> None:
        job = _JOB.get()
        if job is not None:
            job.percent = max(0, min(100, int(progress * 100)))
        original(self, progress)

    ProgressBar.update = update  # type: ignore[method-assign]
    _progress_installed = True


def _device_lock(name: str) -> threading.Lock:
    with _device_locks_guard:
        return _device_locks.setdefault(name, threading.Lock())


def _remember(job: Job) -> None:
    with _jobs_guard:
        _jobs[job.id] = job
        if len(_jobs) > 40:
            oldest = sorted(_jobs.values(), key=lambda item: item.id)[: len(_jobs) - 40]
            for item in oldest:
                if item.state in {"success", "error"}:
                    _jobs.pop(item.id, None)


def _start_upload(target: Target, payload: bytes, port: int) -> Job:
    lock = _device_lock(target.name)
    if not lock.acquire(blocking=False):
        raise ImageRejected(f"{target.name} already has an upload running")
    job = Job(id=uuid.uuid4().hex, device=target.name, state="queued", lock=lock)
    path = Path(os.environ.get("TMPDIR", "/tmp")) / f"ota-{job.id}.bin"
    try:
        path.write_bytes(payload)
    except OSError:
        lock.release()
        raise
    _remember(job)

    def worker() -> None:
        token = _JOB.set(job)
        try:
            from esphome.espota2 import run_ota

            job.state = "uploading"
            job.add_log(f"Uploading to {target.host} port {port}")
            code, _host = run_ota(
                target.host,
                port,
                None,
                path,
                noise_psk=target.key,
                on_upload_start=lambda: job.add_log("Device accepted the upload"),
            )
            if code == 0:
                job.percent = 100
                job.state = "success"
                job.add_log("Upload finished")
                log.info("Uploaded firmware to %s at %s", target.name, target.host)
            else:
                job.state = "error"
                job.error = "upload failed"
                job.add_log("Upload failed")
                log.warning("Upload to %s at %s failed", target.name, target.host)
        except Exception as err:
            job.state = "error"
            job.error = str(err)
            job.add_log(str(err))
            log.warning("Upload to %s failed: %s", target.name, err)
        finally:
            _JOB.reset(token)
            path.unlink(missing_ok=True)
            lock.release()

    threading.Thread(target=worker, name=f"ota-{target.name}", daemon=False).start()
    return job


def _firmware_from_body(content_type: str, body: bytes) -> bytes:
    if content_type.startswith("application/octet-stream"):
        return body
    if not content_type.startswith("multipart/form-data"):
        raise ImageRejected("send the firmware as multipart form data or application/octet-stream")
    import email
    from email import policy

    message = email.message_from_bytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body,
        policy=policy.default,
    )
    if not message.is_multipart():
        raise ImageRejected("firmware file is missing")
    for part in message.iter_parts():
        if part.get_content_disposition() != "form-data":
            continue
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes) and payload:
            return payload
    raise ImageRejected("firmware file is missing")


class RelayHandler(BaseHTTPRequestHandler):
    options: dict[str, Any] = {}
    token: str = ""
    server_version = "esphome-ota-relay/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        log.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _unauthorized(self) -> None:
        self._send(401, {"error": "unauthorized"})

    def _authorized(self) -> bool:
        return _token_ok(self.headers.get("Authorization", ""), self.token)

    def do_GET(self) -> None:  # noqa: N802
        if not self._authorized():
            self._unauthorized()
            return
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/v1/devices":
            devices = []
            for target in load_targets(self.options):
                devices.append(target.public(device_online(target.host)))
            self._send(200, {"devices": devices})
            return
        if path.startswith("/v1/jobs/"):
            job_id = unquote(path.removeprefix("/v1/jobs/"))
            with _jobs_guard:
                job = _jobs.get(job_id)
            if job is None:
                self._send(404, {"error": "job not found"})
                return
            self._send(200, job.public())
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            self._unauthorized()
            return
        path = urlparse(self.path).path.rstrip("/")
        prefix = "/v1/devices/"
        suffix = "/firmware"
        if not path.startswith(prefix) or not path.endswith(suffix):
            self._send(404, {"error": "not found"})
            return
        name = unquote(path[len(prefix) : -len(suffix)])
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send(400, {"error": "invalid content length"})
            return
        if length <= 0 or length > MAX_FIRMWARE_BYTES + 1024 * 1024:
            self._send(400, {"error": "firmware file is empty or larger than 16MB"})
            return
        body = self.rfile.read(length)
        try:
            payload = _firmware_from_body(self.headers.get("Content-Type", ""), body)
            _platform, port = classify_firmware(payload)
            target = find_target(self.options, name)
            if target is None:
                self._send(404, {"error": f"no device named {name}"})
                return
            job = _start_upload(target, payload, port)
        except ImageRejected as err:
            status = 409 if "already has an upload" in str(err) else 400
            if "no device" in str(err):
                status = 404
            self._send(status, {"error": str(err)})
            return
        except Exception as err:
            log.exception("Failed to accept firmware for %s", name)
            self._send(500, {"error": str(err)})
            return
        self._send(202, job.public())


def _check_token_file(token: str) -> None:
    digest = hashlib.sha256(token.encode()).hexdigest()[:8]
    log.info("OTA relay token is set (%s)", digest)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    options = _load_options()
    token = str(options.get("token") or "").strip()
    if not token:
        raise SystemExit("Set a token in the add-on options. The relay will not listen without one.")
    try:
        port = int(options.get("port") or 8096)
    except (TypeError, ValueError) as err:
        raise SystemExit("The port option must be a number") from err
    _check_token_file(token)
    _install_progress_hook()
    handler = logging.getLogger("esphome")
    handler.setLevel(logging.INFO)
    handler.addHandler(_JobLog())
    RelayHandler.options = options
    RelayHandler.token = token
    server = ThreadingHTTPServer(("0.0.0.0", port), RelayHandler)
    log.info("Listening on port %s", port)
    server.serve_forever()


if __name__ == "__main__":
    main()
