import json

from ai_sentinel.db.maintenance import main


def test_validate_command_initializes_and_reports_store(tmp_path, capsys) -> None:
    data_file = tmp_path / "store.json"

    assert main(["validate", "--data-file", str(data_file)]) == 0

    assert json.loads(capsys.readouterr().out) == {
        "status": "valid",
        "schema_version": 1,
    }


def test_backup_and_restore_commands_round_trip(tmp_path, capsys) -> None:
    data_file = tmp_path / "store.json"
    backup_file = tmp_path / "backup.json"

    assert (
        main(
            [
                "backup",
                "--data-file",
                str(data_file),
                "--destination",
                str(backup_file),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {"status": "backed_up"}
    assert (
        main(
            [
                "restore",
                "--data-file",
                str(data_file),
                "--source",
                str(backup_file),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "status": "restored",
        "schema_version": 1,
    }


def test_validate_command_reports_corrupt_file_without_resetting(
    tmp_path, capsys
) -> None:
    data_file = tmp_path / "store.json"
    original = b"{not-json"
    data_file.write_bytes(original)

    assert main(["validate", "--data-file", str(data_file)]) == 1

    output = capsys.readouterr()
    assert json.loads(output.err)["status"] == "error"
    assert "restore" in output.err
    assert data_file.read_bytes() == original
