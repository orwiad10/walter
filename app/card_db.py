import io
import json
import os
import sqlite3
import tempfile
import zipfile
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union
from urllib.request import urlopen

ATOMIC_CARDS_URL = "https://mtgjson.com/api/v5/AtomicCards.json.zip"
CURRENT_SCHEMA_VERSION = "2"


def _normalize_name(name: str) -> str:
    normalized = ''.join(ch for ch in name.lower() if ch.isalnum())
    return normalized


def ensure_directory(path: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)


def _ensure_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            search_name TEXT NOT NULL,
            normalized_name TEXT NOT NULL UNIQUE,
            is_land INTEGER NOT NULL DEFAULT 0,
            is_basic_land INTEGER NOT NULL DEFAULT 0,
            is_standard_banned INTEGER NOT NULL DEFAULT 0,
            is_vintage_restricted INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(cards)").fetchall()
    }
    extra_columns = {
        'is_land': 'INTEGER NOT NULL DEFAULT 0',
        'is_basic_land': 'INTEGER NOT NULL DEFAULT 0',
        'is_standard_banned': 'INTEGER NOT NULL DEFAULT 0',
        'is_vintage_restricted': 'INTEGER NOT NULL DEFAULT 0',
    }
    for column, definition in extra_columns.items():
        if column not in columns:
            connection.execute(f"ALTER TABLE cards ADD COLUMN {column} {definition}")
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_cards_search_name ON cards(search_name)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_cards_normalized_name ON cards(normalized_name)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS card_faces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_id INTEGER NOT NULL,
            face_normalized_name TEXT NOT NULL,
            UNIQUE(card_id, face_normalized_name),
            FOREIGN KEY(card_id) REFERENCES cards(id) ON DELETE CASCADE
        )
        """
    )
    connection.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_card_faces_face ON card_faces(face_normalized_name)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_card_faces_card ON card_faces(card_id)"
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )


def _get_schema_version(connection: sqlite3.Connection) -> Optional[str]:
    try:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version' LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    return row[0] if row else None


def _set_schema_version(connection: sqlite3.Connection, version: str) -> None:
    connection.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES ('schema_version', ?)",
        (version,),
    )


def populate_card_database(path: str, card_records: Iterable[Union[str, Dict[str, Any]]]) -> None:
    ensure_directory(path)
    connection = sqlite3.connect(path)
    try:
        _ensure_schema(connection)
        current_version = _get_schema_version(connection)
        if current_version == CURRENT_SCHEMA_VERSION:
            existing = connection.execute("SELECT COUNT(*) FROM cards").fetchone()
            if existing and existing[0]:
                return
        connection.execute("DELETE FROM card_faces")
        connection.execute("DELETE FROM cards")
        for record in card_records:
            if isinstance(record, str):
                name = record
                metadata: Dict[str, Any] = {}
            else:
                metadata = record
                name = metadata.get('name', '')
            name = (name or '').strip()
            if not name:
                continue
            search_name = name.lower()
            normalized = _normalize_name(name)
            is_land = int(bool(metadata.get('is_land')))
            is_basic_land = int(bool(metadata.get('is_basic_land')))
            is_standard_banned = int(bool(metadata.get('is_standard_banned')))
            is_vintage_restricted = int(bool(metadata.get('is_vintage_restricted')))
            cursor = connection.execute(
                """
                INSERT OR REPLACE INTO cards(
                    name, search_name, normalized_name,
                    is_land, is_basic_land, is_standard_banned, is_vintage_restricted
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    search_name,
                    normalized,
                    is_land,
                    is_basic_land,
                    is_standard_banned,
                    is_vintage_restricted,
                ),
            )
            card_id = cursor.lastrowid
            face_names = metadata.get('face_names') or []
            seen_faces = set()
            for face in face_names:
                normalized_face = _normalize_name(face)
                if not normalized_face or normalized_face in seen_faces:
                    continue
                connection.execute(
                    "INSERT OR IGNORE INTO card_faces(card_id, face_normalized_name) VALUES (?, ?)",
                    (card_id, normalized_face),
                )
                seen_faces.add(normalized_face)
        _set_schema_version(connection, CURRENT_SCHEMA_VERSION)
        connection.commit()
    finally:
        connection.close()


def _read_atomic_cards_from_zip(path: str) -> List[Dict[str, Any]]:
    with zipfile.ZipFile(path) as archive:
        json_name = None
        for member in archive.namelist():
            if member.lower().endswith('.json'):
                json_name = member
                break
        if not json_name:
            raise RuntimeError("AtomicCards.json not found in archive")
        with archive.open(json_name) as handle:
            text_wrapper = io.TextIOWrapper(handle, encoding='utf-8')
            data = json.load(text_wrapper)
        cards = data.get('data', {})
        if not isinstance(cards, dict):
            raise RuntimeError("Unexpected AtomicCards format")
        records: List[Dict[str, Any]] = []
        for name, entries in cards.items():
            if not isinstance(entries, list):
                continue
            is_land = any('Land' in (entry.get('types') or []) for entry in entries)
            is_basic = any('Basic' in (entry.get('supertypes') or []) for entry in entries)
            is_standard_banned = any(
                (entry.get('legalities') or {}).get('standard') == 'Banned'
                for entry in entries
            )
            is_vintage_restricted = any(
                (entry.get('legalities') or {}).get('vintage') == 'Restricted'
                for entry in entries
            )
            face_names = []
            for entry in entries:
                face_name = entry.get('faceName')
                if face_name:
                    face_names.append(face_name)
            records.append(
                {
                    'name': name,
                    'is_land': is_land,
                    'is_basic_land': is_basic,
                    'is_standard_banned': is_standard_banned,
                    'is_vintage_restricted': is_vintage_restricted,
                    'face_names': face_names,
                }
            )
        records.sort(key=lambda item: item['name'])
        return records


def build_card_database(path: str, source_url: Optional[str] = None) -> None:
    ensure_directory(path)
    url = source_url or ATOMIC_CARDS_URL
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        temp_name = tmp.name
        with urlopen(url) as response:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)
    try:
        card_records = _read_atomic_cards_from_zip(temp_name)
        populate_card_database(path, card_records)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def ensure_card_database(path: str, source_url: Optional[str] = None) -> str:
    rebuild = False
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        rebuild = True
    else:
        connection = sqlite3.connect(path)
        try:
            _ensure_schema(connection)
            version = _get_schema_version(connection)
            if version != CURRENT_SCHEMA_VERSION:
                rebuild = True
        finally:
            connection.close()
    if rebuild:
        build_card_database(path, source_url=source_url)
    return path


@contextmanager
def open_card_database(path: str):
    connection = sqlite3.connect(path)
    try:
        yield connection
    finally:
        connection.close()


def _lookup_card_with_connection(connection: sqlite3.Connection, normalized: str) -> Optional[str]:
    if not normalized:
        return None
    row = connection.execute(
        "SELECT name FROM cards WHERE normalized_name = ? LIMIT 1",
        (normalized,),
    ).fetchone()
    if row:
        return row[0]
    row = connection.execute(
        """
        SELECT cards.name
        FROM card_faces
        JOIN cards ON card_faces.card_id = cards.id
        WHERE card_faces.face_normalized_name = ?
        LIMIT 1
        """,
        (normalized,),
    ).fetchone()
    if row:
        return row[0]
    return None


def search_cards(path: str, query: str, limit: int = 20) -> List[str]:
    if not query:
        return []
    normalized_query = query.strip().lower()
    if not normalized_query:
        return []
    pattern = f"%{normalized_query}%"
    with open_card_database(path) as connection:
        _ensure_schema(connection)
        rows = connection.execute(
            "SELECT name FROM cards WHERE search_name LIKE ? ORDER BY name LIMIT ?",
            (pattern, limit),
        ).fetchall()
    return [row[0] for row in rows]


def lookup_card(path: str, name: str) -> Optional[str]:
    normalized = _normalize_name(name)
    if not normalized:
        return None
    with open_card_database(path) as connection:
        _ensure_schema(connection)
        return _lookup_card_with_connection(connection, normalized)


def canonicalize_names(path: str, names: Iterable[str]) -> List[Optional[str]]:
    with open_card_database(path) as connection:
        _ensure_schema(connection)
        results = []
        for name in names:
            normalized = _normalize_name(name)
            canonical = _lookup_card_with_connection(connection, normalized)
            results.append(canonical)
    return results


def get_card_metadata(path: str, names: Sequence[str]) -> Dict[str, Dict[str, bool]]:
    if not names:
        return {}
    unique_names = list(dict.fromkeys(names))
    placeholders = ','.join('?' for _ in unique_names)
    if not placeholders:
        return {}
    with open_card_database(path) as connection:
        _ensure_schema(connection)
        rows = connection.execute(
            f"""
            SELECT name, is_land, is_basic_land, is_standard_banned, is_vintage_restricted
            FROM cards
            WHERE name IN ({placeholders})
            """,
            tuple(unique_names),
        ).fetchall()
    metadata: Dict[str, Dict[str, bool]] = {}
    for row in rows:
        metadata[row[0]] = {
            'is_land': bool(row[1]),
            'is_basic_land': bool(row[2]),
            'is_standard_banned': bool(row[3]),
            'is_vintage_restricted': bool(row[4]),
        }
    return metadata
