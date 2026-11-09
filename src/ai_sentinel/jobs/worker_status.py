import json
import logging
import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread


def heartbeat_path(data_file: Path) -> Path:
    return data_file.with_name(f"{data_file.name}.worker.json")


def read_worker_heartbeat(data_file: Path) -> datetime | None:
    try:
        payload = json.loads(heartbeat_path(data_file).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return None
        process_id = payload.get("process_id")
        timestamp = payload.get("heartbeat_at")
        if not isinstance(process_id, int) or not isinstance(timestamp, str):
            return None
        heartbeat_at = datetime.fromisoformat(timestamp)
        if heartbeat_at.utcoffset() is None:
            return None
        return heartbeat_at.astimezone(UTC)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None


def is_worker_running(data_file: Path, *, max_age_seconds: int) -> bool:
    heartbeat_at = read_worker_heartbeat(data_file)
    if heartbeat_at is None:
        return False
    age = datetime.now(UTC) - heartbeat_at
    return timedelta(0) <= age <= timedelta(seconds=max_age_seconds)


@contextmanager
def worker_heartbeat(
    data_file: Path,
    *,
    interval_seconds: float,
    logger: logging.Logger,
) -> Iterator[None]:
    if interval_seconds <= 0:
        raise ValueError("Worker heartbeat interval must be positive.")
    path = heartbeat_path(data_file)

    def write() -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(
            prefix=f"{path.name}.",
            suffix=".tmp",
            dir=path.parent,
        )
        temporary_path = Path(name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as heartbeat:
                json.dump(
                    {
                        "process_id": os.getpid(),
                        "heartbeat_at": datetime.now(UTC).isoformat(),
                    },
                    heartbeat,
                )
                heartbeat.flush()
                os.fsync(heartbeat.fileno())
            temporary_path.replace(path)
        finally:
            temporary_path.unlink(missing_ok=True)

    stop = Event()
    heartbeat_thread: Thread | None = None
    try:
        write()

        def refresh() -> None:
            while not stop.wait(interval_seconds):
                try:
                    write()
                except OSError as exc:
                    logger.error(
                        "Worker heartbeat update failed",
                        extra={"error_type": type(exc).__name__},
                    )

        heartbeat_thread = Thread(
            target=refresh,
            name="ai-sentinel-worker-heartbeat",
            daemon=True,
        )
        heartbeat_thread.start()
        yield
    finally:
        stop.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=interval_seconds + 1)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = {}
        if isinstance(payload, dict) and payload.get("process_id") == os.getpid():
            path.unlink(missing_ok=True)
