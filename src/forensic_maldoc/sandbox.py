"""Fail-closed Linux worker launcher; no in-process or unsandboxed fallback."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Literal

BWRAP = Path("/usr/bin/bwrap")
OUTPUT_LIMIT = 64 * 1024
DEADLINE_SECONDS = 8.0


class WorkerError(RuntimeError):
    def __init__(self, status: Literal["not_checked", "error"], reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _receive(process: subprocess.Popen[bytes]) -> bytes:
    assert process.stdout is not None
    deadline = time.monotonic() + DEADLINE_SECONDS
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise WorkerError("error", "worker_timeout")
            chunk = os.read(process.stdout.fileno(), min(4096, OUTPUT_LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > OUTPUT_LIMIT:
                raise WorkerError("error", "worker_output_limit")
        try:
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise WorkerError("error", "worker_timeout") from None
    if status != 0:
        raise WorkerError("error", "sandbox_or_worker_failed")
    return bytes(data)


def run_worker(tool: str, indicators: tuple[str, ...], limit: int, source: bytes, sample: bytes) -> dict:
    if not BWRAP.is_file():
        raise WorkerError("not_checked", "sandbox_unavailable")
    with tempfile.TemporaryDirectory(prefix="forensic-maldoc-") as directory:
        private = Path(directory)
        sample_name = "sample.cfb" if tool in ("ole", "ole-metadata") else "sample.pdf"
        sample_path, script_path = private / sample_name, private / "analyzer.py"
        sample_path.write_bytes(sample)
        script_path.write_bytes(source)
        worker = Path(__file__).with_name("worker.py").resolve()
        argv = [
            str(BWRAP), "--unshare-all", "--unshare-user", "--unshare-net",
            "--disable-userns", "--new-session", "--die-with-parent",
            "--clearenv", "--setenv", "LC_ALL", "C", "--ro-bind", "/usr", "/usr",
            "--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64",
            "--ro-bind", str(worker), "/worker.py", "--ro-bind", str(sample_path), f"/{sample_name}",
            "--ro-bind", str(script_path), "/analyzer.py", "--remount-ro", "/",
            "--chdir", "/", "--", "/usr/bin/python3", "-IBS", "/worker.py", tool,
            str(limit), *indicators,
        ]
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, env={})
        except OSError:
            raise WorkerError("not_checked", "sandbox_unavailable") from None
        with process:
            try:
                output = _receive(process)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    try:
        result = json.loads(output)
        if not isinstance(result, dict):
            raise TypeError("expected worker object")
    except (ValueError, TypeError, RecursionError):
        raise WorkerError("error", "invalid_worker_report") from None
    return result
