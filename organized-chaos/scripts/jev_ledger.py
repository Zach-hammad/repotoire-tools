"""Small private, cross-process ledger for cumulative Jev advice requests."""

import os
from contextlib import closing
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
from urllib.parse import quote


class LedgerError(Exception):
    """Sanitized fail-closed ledger error."""


def ledger_path():
    return Path.home() / ".config" / "organized-chaos" / "jev-advice.sqlite3"


def _check_directory(path, create=False):
    parent = path.parent
    if create and not parent.exists():
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        info = parent.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise LedgerError("advice_ledger_unavailable") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise LedgerError("unsafe_advice_ledger")
    return True


def _check_file(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise LedgerError("advice_ledger_unavailable") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise LedgerError("unsafe_advice_ledger")
    return True


def _read_rows(path):
    if not _check_directory(path):
        return {}
    if not _check_file(path):
        return {}
    try:
        uri = "file:" + quote(str(path), safe="/") + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise LedgerError("invalid_advice_ledger")
            rows = db.execute("SELECT work_item_id, requests_used, last_state_sha256 FROM advice").fetchall()
    except LedgerError:
        raise
    except (sqlite3.Error, OSError):
        raise LedgerError("invalid_advice_ledger") from None
    result = {}
    for work_id, count, digest in rows:
        if (not isinstance(work_id, str) or not work_id.strip() or type(count) is not int
                or count not in (1, 2) or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            raise LedgerError("invalid_advice_ledger")
        result[work_id] = {"jev_requests_used": count, "last_state_sha256": digest}
    return result


def snapshot(work_ids):
    """Read authoritative state without creating the ledger or its directory."""
    rows = _read_rows(ledger_path())
    return {work_id: rows.get(work_id, {"jev_requests_used": 0, "last_state_sha256": None})
            for work_id in sorted(set(work_ids))}


def validate_claims(requests, *, requesting=True):
    """Compare packet count/basis to durable rows without mutating storage."""
    rows = _read_rows(ledger_path())
    for work_id, request in requests.items():
        _validate_request(work_id, request, rows.get(work_id), requesting=requesting)
    return {work_id: rows.get(work_id, {"jev_requests_used": 0, "last_state_sha256": None})
            for work_id in sorted(requests)}


def _validate_request(work_id, request, row, *, requesting=True):
    expected = request["expected_used"]
    basis = request["basis"]
    state_hash = request["state_hash"]
    require_hash = lambda value: isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    if row and (type(row.get("jev_requests_used")) is not int
                or row["jev_requests_used"] not in (1, 2)
                or not require_hash(row.get("last_state_sha256"))):
        raise LedgerError("invalid_advice_ledger")
    actual = row["jev_requests_used"] if row else 0
    if expected != actual:
        raise LedgerError("advice_ledger_count_mismatch")
    if expected == 0:
        if basis["previous_state_sha256"] is not None or basis["change_reason"] is not None:
            raise LedgerError("invalid_initial_advice_basis")
    elif (not row or basis["previous_state_sha256"] != row["last_state_sha256"]
          or not require_hash(basis["previous_state_sha256"])
          or not isinstance(basis["change_reason"], str) or not basis["change_reason"].strip()):
        raise LedgerError("advice_ledger_state_mismatch")
    if not require_hash(state_hash) or (requesting and row and state_hash == row["last_state_sha256"]):
        raise LedgerError("unchanged_advice_state")
    if requesting and actual >= 2:
        raise LedgerError("advice_budget_exhausted")


def _initialize_if_absent(path):
    """Publish a complete empty ledger atomically; never repair an existing file."""
    if _check_file(path):
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".jev-advice-", suffix=".sqlite3", dir=path.parent)
    os.close(descriptor)
    temp_path = Path(temporary)
    try:
        with closing(sqlite3.connect(temp_path)) as db:
            db.execute("CREATE TABLE advice (work_item_id TEXT PRIMARY KEY, requests_used INTEGER NOT NULL, last_state_sha256 TEXT NOT NULL)")
            db.execute("PRAGMA user_version=1")
            db.commit()
        try:
            os.link(temp_path, path)
        except FileExistsError:
            pass
    except (sqlite3.Error, OSError):
        raise LedgerError("advice_ledger_unavailable") from None
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
    _check_file(path)


def reserve(requests):
    """Atomically reserve each work item once; crash-after-reserve stays charged."""
    if not requests:
        return {}
    path = ledger_path()
    _check_directory(path, create=True)
    _initialize_if_absent(path)
    db = None
    reserved = {}
    try:
        db = sqlite3.connect(path, timeout=2, isolation_level=None)
        try:
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version != 1:
                raise LedgerError("invalid_advice_ledger")
            rows = {}
            for work_id, request in requests.items():
                row = db.execute("SELECT requests_used, last_state_sha256 FROM advice WHERE work_item_id=?", (work_id,)).fetchone()
                state = None if row is None else {"jev_requests_used": row[0], "last_state_sha256": row[1]}
                _validate_request(work_id, request, state)
                rows[work_id] = state
            for work_id, request in requests.items():
                used = (rows[work_id]["jev_requests_used"] if rows[work_id] else 0) + 1
                db.execute("INSERT INTO advice VALUES (?, ?, ?) ON CONFLICT(work_item_id) DO UPDATE SET requests_used=excluded.requests_used, last_state_sha256=excluded.last_state_sha256",
                           (work_id, used, request["state_hash"]))
                reserved[work_id] = {"jev_requests_used": used,
                                     "last_state_sha256": request["state_hash"]}
            db.commit()
        except Exception:
            db.rollback()
            raise
    except LedgerError:
        raise
    except sqlite3.Error:
        raise LedgerError("invalid_advice_ledger") from None
    except OSError:
        raise LedgerError("advice_ledger_unavailable") from None
    finally:
        if db is not None:
            db.close()
    _check_file(path)
    return reserved
