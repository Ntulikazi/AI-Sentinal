import json
import logging
import time
from datetime import UTC, datetime, timedelta

import pytest

from ai_sentinel.jobs.worker_status import (
    heartbeat_path,
    is_worker_running,
    read_worker_heartbeat,
    worker_heartbeat,
)


def test_worker_heartbeat_is_refreshed_and_removed_on_exit(tmp_path) -> None:
    data_file = tmp_path / "store.json"
    path = heartbeat_path(data_file)
    logger = logging.getLogger("worker-status-refresh-test")

    with worker_heartbeat(data_file, interval_seconds=0.05, logger=logger):
        first_heartbeat = read_worker_heartbeat(data_file)
        assert first_heartbeat is not None
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            refreshed = read_worker_heartbeat(data_file)
            if refreshed is not None and refreshed > first_heartbeat:
                break
            time.sleep(0.01)
        else:
            pytest.fail("Worker heartbeat was not refreshed.")

        assert is_worker_running(data_file, max_age_seconds=15)

    assert not path.exists()


def test_worker_heartbeat_rejects_nonpositive_refresh_interval(tmp_path) -> None:
    with pytest.raises(ValueError, match="positive"):
        with worker_heartbeat(
            tmp_path / "store.json",
            interval_seconds=0,
            logger=logging.getLogger("worker-status-invalid-test"),
        ):
            pytest.fail("Invalid heartbeat interval should not start a worker.")


@pytest.mark.parametrize("payload", ["[]", '"not-an-object"', "{"])
def test_read_worker_heartbeat_handles_malformed_content(tmp_path, payload) -> None:
    data_file = tmp_path / "store.json"
    heartbeat_path(data_file).write_text(payload, encoding="utf-8")

    assert read_worker_heartbeat(data_file) is None
    assert not is_worker_running(data_file, max_age_seconds=15)


def test_is_worker_running_rejects_stale_and_future_heartbeats(tmp_path) -> None:
    data_file = tmp_path / "store.json"
    path = heartbeat_path(data_file)

    for heartbeat_at in (
        datetime.now(UTC) - timedelta(seconds=16),
        datetime.now(UTC) + timedelta(seconds=1),
    ):
        path.write_text(
            json.dumps(
                {
                    "process_id": 1,
                    "heartbeat_at": heartbeat_at.isoformat(),
                }
            ),
            encoding="utf-8",
        )
        assert not is_worker_running(data_file, max_age_seconds=15)
