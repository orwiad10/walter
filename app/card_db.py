import io
import json
import os
import sqlite3
import tempfile
import zipfile
from contextlib import contextmanager
from typing import Iterable, List, Optional
from urllib.request import urlopen

ATOMIC_CARDS_URL = "https://mtgjson.com/api/v5/AtomicCards.json.zip"


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
            normalized_name TEXT NOT NULL UNIQUE
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_cards_search_name ON cards(search_name)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_cards_normalized_name ON cards(normalized_name)"
    )


def populate_card_database(path: str, card_names: Iterable[str]) -> None:
    ensure_directory(path)
    connection = sqlite3.connect(path)
    try:
        _ensure_schema(connection)
        existing = connection.execute("SELECT name FROM cards").fetchone()
        if existing:
            return
        rows = [
            (name, name.lower(), _normalize_name(name))
            for name in card_names
        ]
        connection.executemany(
            "INSERT OR IGNORE INTO cards(name, search_name, normalized_name) VALUES (?, ?, ?)",
            rows,
        )
        connection.commit()
    finally:
        connection.close()


def _read_atomic_cards_from_zip(path: str) -> List[str]:
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
        return list(cards.keys())


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
        card_names = _read_atomic_cards_from_zip(temp_name)
        populate_card_database(path, sorted(card_names))
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def ensure_card_database(path: str, source_url: Optional[str] = None) -> str:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        build_card_database(path, source_url=source_url)
    return path


@contextmanager
def open_card_database(path: str):
    connection = sqlite3.connect(path)
    try:
        yield connection
    finally:
        connection.close()


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
        row = connection.execute(
            "SELECT name FROM cards WHERE normalized_name = ? LIMIT 1",
            (normalized,),
        ).fetchone()
    if row:
        return row[0]
    return None


def canonicalize_names(path: str, names: Iterable[str]) -> List[Optional[str]]:
    normalized_names = [(_normalize_name(name), name) for name in names]
    with open_card_database(path) as connection:
        _ensure_schema(connection)
        results = []
        for normalized, original in normalized_names:
            if not normalized:
                results.append(None)
                continue
            row = connection.execute(
                "SELECT name FROM cards WHERE normalized_name = ? LIMIT 1",
                (normalized,),
            ).fetchone()
            results.append(row[0] if row else None)
    return results
