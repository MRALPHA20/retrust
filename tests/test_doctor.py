"""The installation health check: right states, right fixes, no false calm."""

import sqlite3
import time

from retrust import doctor, index


def _installation(tmp_path, *, kev_age_days=1):
    data = tmp_path / "data"
    (data / "CSAF").mkdir(parents=True)
    (data / "CSAF" / "a.json").write_text("{}")
    for name in ("kev.json", "epss.csv", "screening.json", "certifications.json"):
        (data / name).write_text("{}")
    if kev_age_days > 1:
        old = time.time() - kev_age_days * 86400
        import os
        os.utime(data / "kev.json", (old, old))
    db = str(data / "retrust.db")
    connection = index.connect(db)
    connection.execute(
        "INSERT INTO advisory (id, title, released, source)"
        " VALUES ('A-1', 't', '2026-01-01', 's')")
    connection.commit()
    return str(data), db


def test_a_current_installation_is_all_ok(tmp_path):
    data, db = _installation(tmp_path)
    checks = doctor.run(data_dir=data, db_path=db)
    fresh = [c for c in checks if c.name not in ("EPSS history", "gpg")]
    assert all(c.ok for c in fresh), [(c.name, c.state, c.detail) for c in fresh]


def test_an_old_kev_is_called_stale_with_its_fix(tmp_path):
    data, db = _installation(tmp_path, kev_age_days=40)
    checks = {c.name: c for c in doctor.run(data_dir=data, db_path=db)}
    assert checks["KEV feed"].state == "stale"
    assert checks["KEV feed"].fix == "retrust setup --force"


def test_a_missing_index_is_missing_not_a_crash(tmp_path):
    checks = doctor.run(data_dir=str(tmp_path), db_path=str(tmp_path / "no.db"))
    states = {c.name: c.state for c in checks}
    assert states["index"] == "missing"


def test_missing_history_names_the_consequence(tmp_path):
    data, db = _installation(tmp_path)
    checks = {c.name: c for c in doctor.run(data_dir=data, db_path=db)}
    assert checks["EPSS history"].state == "missing"
    assert "abstain" in checks["EPSS history"].detail
    assert checks["EPSS history"].fix == "retrust lev --update"


def test_the_report_lists_each_fix_once(tmp_path):
    data, db = _installation(tmp_path, kev_age_days=40)
    text = doctor.format_report(doctor.run(data_dir=data, db_path=db))
    assert text.count("retrust lev --update") == 1
    assert "To clear the flagged ones" in text
