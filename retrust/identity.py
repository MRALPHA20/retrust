"""Code and complete input fingerprints for saved assessment evidence."""

import hashlib
import json
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def build_fingerprint():
    digest = hashlib.sha256()
    for path in sorted(Path(__file__).parent.glob('*.py')):
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


@lru_cache(maxsize=32)
def _file_digest(path, size, modified):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def file_digest(path):
    path = Path(path)
    if not path.exists():
        return 'missing'
    stat = path.stat()
    return _file_digest(str(path.resolve()), stat.st_size, stat.st_mtime_ns)


def data_fingerprint(connection, data_dir='data'):
    """Fingerprint the database plus supplementary inputs, not just row counts."""
    database = next((row[2] for row in connection.execute('PRAGMA database_list')
                     if row[1] == 'main'), '')
    # Serialize a transactional or WAL-backed database to include uncheckpointed
    # pages. File hashing is cached for ordinary read-only assessment requests.
    if (database and not connection.in_transaction
            and not Path(database + '-wal').exists()):
        db_digest = file_digest(database)
    else:
        serialize = getattr(connection, 'serialize', None)
        if serialize is not None:
            db_digest = hashlib.sha256(serialize()).hexdigest()
        else:
            # Python 3.10 has no Connection.serialize(). A logical dump also
            # includes this connection's uncommitted rows and visible WAL data;
            # hashing the file alone would silently miss those changes.
            digest = hashlib.sha256(b'sqlite logical dump\n')
            for statement in connection.iterdump():
                digest.update(statement.encode('utf-8'))
                digest.update(b'\n')
            db_digest = digest.hexdigest()
    inputs = {'database': db_digest}
    for name in ('certifications.json', 'screening.json'):
        inputs[name] = file_digest(Path(data_dir) / name)
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
