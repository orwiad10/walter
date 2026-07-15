import io
import json
import os
import tempfile
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

ATOMIC_CARDS_URL = "https://mtgjson.com/api/v5/AtomicCards.json.zip"
CURRENT_SCHEMA_VERSION = "3"
CARD_DB_USER_AGENT = "Walter/1.0 (MTG tournament card database updater)"


def _normalize_name(name: str) -> str:
    normalized = ''.join(ch for ch in name.lower() if ch.isalnum())
    return normalized


def _engine(database_url: str) -> Engine:
    if not database_url:
        raise ValueError('CARD_DATABASE_URL is required.')
    return create_engine(database_url, pool_pre_ping=True, future=True)


def _ensure_schema(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS cards (
                    id INTEGER NOT NULL AUTO_INCREMENT,
                    name VARCHAR(255) NOT NULL,
                    search_name VARCHAR(255) NOT NULL,
                    normalized_name VARCHAR(255) NOT NULL,
                    is_land BOOLEAN NOT NULL DEFAULT FALSE,
                    is_basic_land BOOLEAN NOT NULL DEFAULT FALSE,
                    is_standard_banned BOOLEAN NOT NULL DEFAULT FALSE,
                    is_vintage_restricted BOOLEAN NOT NULL DEFAULT FALSE,
                    type_line TEXT NULL,
                    primary_type VARCHAR(120) NULL,
                    PRIMARY KEY (id),
                    UNIQUE KEY uq_cards_name (name),
                    UNIQUE KEY uq_cards_normalized_name (normalized_name),
                    KEY idx_cards_search_name (search_name)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS card_faces (
                    id INTEGER NOT NULL AUTO_INCREMENT,
                    card_id INTEGER NOT NULL,
                    face_normalized_name VARCHAR(255) NOT NULL,
                    PRIMARY KEY (id),
                    UNIQUE KEY uq_card_faces_card_face (card_id, face_normalized_name),
                    UNIQUE KEY uq_card_faces_face (face_normalized_name),
                    KEY idx_card_faces_card (card_id),
                    CONSTRAINT fk_card_faces_card_id
                        FOREIGN KEY (card_id) REFERENCES cards(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    `key` VARCHAR(100) NOT NULL,
                    value VARCHAR(255) NOT NULL,
                    PRIMARY KEY (`key`)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                """
            )
        )


def _get_schema_version(engine: Engine) -> Optional[str]:
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT value FROM metadata WHERE `key` = 'schema_version' LIMIT 1")
        ).fetchone()
    return row[0] if row else None


def _set_schema_version(connection, version: str) -> None:
    connection.execute(
        text(
            """
            INSERT INTO metadata(`key`, value) VALUES ('schema_version', :version)
            ON DUPLICATE KEY UPDATE value = VALUES(value)
            """
        ),
        {'version': version},
    )


def populate_card_database(database_url: str, card_records: Iterable[Union[str, Dict[str, Any]]]) -> None:
    engine = _engine(database_url)
    _ensure_schema(engine)
    current_version = _get_schema_version(engine)
    with engine.begin() as connection:
        if current_version == CURRENT_SCHEMA_VERSION:
            existing = connection.execute(text("SELECT COUNT(*) FROM cards")).fetchone()
            if existing and existing[0]:
                return
        connection.execute(text("DELETE FROM card_faces"))
        connection.execute(text("DELETE FROM cards"))
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
            params = {
                'name': name,
                'search_name': search_name,
                'normalized_name': normalized,
                'is_land': bool(metadata.get('is_land')),
                'is_basic_land': bool(metadata.get('is_basic_land')),
                'is_standard_banned': bool(metadata.get('is_standard_banned')),
                'is_vintage_restricted': bool(metadata.get('is_vintage_restricted')),
                'type_line': metadata.get('type_line'),
                'primary_type': metadata.get('primary_type'),
            }
            connection.execute(
                text(
                    """
                    INSERT INTO cards(
                        name, search_name, normalized_name,
                        is_land, is_basic_land, is_standard_banned, is_vintage_restricted,
                        type_line, primary_type
                    ) VALUES (
                        :name, :search_name, :normalized_name,
                        :is_land, :is_basic_land, :is_standard_banned, :is_vintage_restricted,
                        :type_line, :primary_type
                    )
                    ON DUPLICATE KEY UPDATE
                        id = LAST_INSERT_ID(id),
                        name = VALUES(name),
                        search_name = VALUES(search_name),
                        is_land = VALUES(is_land),
                        is_basic_land = VALUES(is_basic_land),
                        is_standard_banned = VALUES(is_standard_banned),
                        is_vintage_restricted = VALUES(is_vintage_restricted),
                        type_line = VALUES(type_line),
                        primary_type = VALUES(primary_type)
                    """
                ),
                params,
            )
            card_id = connection.execute(text("SELECT LAST_INSERT_ID()")).scalar_one()
            face_names = metadata.get('face_names') or []
            seen_faces = set()
            for face in face_names:
                normalized_face = _normalize_name(face)
                if not normalized_face or normalized_face in seen_faces:
                    continue
                connection.execute(
                    text(
                        """
                        INSERT IGNORE INTO card_faces(card_id, face_normalized_name)
                        VALUES (:card_id, :face_normalized_name)
                        """
                    ),
                    {'card_id': card_id, 'face_normalized_name': normalized_face},
                )
                seen_faces.add(normalized_face)
        _set_schema_version(connection, CURRENT_SCHEMA_VERSION)


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
            supertypes: List[str] = []
            type_parts: List[str] = []
            subtypes: List[str] = []
            for entry in entries:
                face_name = entry.get('faceName')
                if face_name:
                    face_names.append(face_name)
                for value in entry.get('supertypes') or []:
                    if value not in supertypes:
                        supertypes.append(value)
                for value in entry.get('types') or []:
                    if value not in type_parts:
                        type_parts.append(value)
                for value in entry.get('subtypes') or []:
                    if value not in subtypes:
                        subtypes.append(value)
            type_line_components = supertypes + type_parts
            type_line = ' '.join(type_line_components)
            if subtypes:
                subtype_line = ' '.join(subtypes)
                type_line = f"{type_line} — {subtype_line}" if type_line else f"— {subtype_line}"
            primary_type = type_parts[-1] if type_parts else None
            records.append(
                {
                    'name': name,
                    'is_land': is_land,
                    'is_basic_land': is_basic,
                    'is_standard_banned': is_standard_banned,
                    'is_vintage_restricted': is_vintage_restricted,
                    'type_line': type_line,
                    'primary_type': primary_type,
                    'face_names': face_names,
                }
            )
        records.sort(key=lambda item: item['name'])
        return records


def _card_database_request(url: str) -> Request:
    parsed_url = urlparse(url)
    if parsed_url.scheme != 'https' or not parsed_url.netloc:
        raise ValueError('Card database URL must be an absolute https URL.')
    return Request(url, headers={'User-Agent': CARD_DB_USER_AGENT})


def build_card_database(database_url: str, source_url: Optional[str] = None) -> None:
    url = source_url or ATOMIC_CARDS_URL
    request = _card_database_request(url)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        temp_name = tmp.name
        with urlopen(request) as response:  # nosec B310
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                tmp.write(chunk)
    try:
        card_records = _read_atomic_cards_from_zip(temp_name)
        populate_card_database(database_url, card_records)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def ensure_card_database(database_url: str, source_url: Optional[str] = None) -> str:
    engine = _engine(database_url)
    _ensure_schema(engine)
    version = _get_schema_version(engine)
    existing = 0
    with engine.connect() as connection:
        existing = connection.execute(text("SELECT COUNT(*) FROM cards")).scalar_one()
    if version != CURRENT_SCHEMA_VERSION or not existing:
        build_card_database(database_url, source_url=source_url)
    return database_url


def _lookup_card_with_engine(engine: Engine, normalized: str) -> Optional[str]:
    if not normalized:
        return None
    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT name FROM cards WHERE normalized_name = :normalized LIMIT 1"),
            {'normalized': normalized},
        ).fetchone()
        if row:
            return row[0]
        row = connection.execute(
            text(
                """
                SELECT cards.name
                FROM card_faces
                JOIN cards ON card_faces.card_id = cards.id
                WHERE card_faces.face_normalized_name = :normalized
                LIMIT 1
                """
            ),
            {'normalized': normalized},
        ).fetchone()
    if row:
        return row[0]
    return None


def search_cards(database_url: str, query: str, limit: int = 20) -> List[str]:
    if not query:
        return []
    normalized_query = query.strip().lower()
    if not normalized_query:
        return []
    engine = _engine(database_url)
    _ensure_schema(engine)
    pattern = f"%{normalized_query}%"
    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT name FROM cards WHERE search_name LIKE :pattern ORDER BY name LIMIT :limit"),
            {'pattern': pattern, 'limit': int(limit)},
        ).fetchall()
    return [row[0] for row in rows]


def lookup_card(database_url: str, name: str) -> Optional[str]:
    engine = _engine(database_url)
    _ensure_schema(engine)
    return _lookup_card_with_engine(engine, _normalize_name(name or ''))


def canonicalize_names(database_url: str, names: Sequence[str]) -> List[Optional[str]]:
    engine = _engine(database_url)
    _ensure_schema(engine)
    return [_lookup_card_with_engine(engine, _normalize_name(name or '')) for name in names]


def get_card_metadata(database_url: str, names: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    if not names:
        return {}
    engine = _engine(database_url)
    _ensure_schema(engine)
    normalized_names = [_normalize_name(name or '') for name in names]
    result: Dict[str, Dict[str, Any]] = {}
    with engine.connect() as connection:
        for original, normalized in zip(names, normalized_names):
            if not normalized:
                continue
            row = connection.execute(
                text(
                    """
                    SELECT name, is_land, is_basic_land, is_standard_banned,
                           is_vintage_restricted, type_line, primary_type
                    FROM cards
                    WHERE normalized_name = :normalized
                    LIMIT 1
                    """
                ),
                {'normalized': normalized},
            ).fetchone()
            if not row:
                row = connection.execute(
                    text(
                        """
                        SELECT cards.name, cards.is_land, cards.is_basic_land,
                               cards.is_standard_banned, cards.is_vintage_restricted,
                               cards.type_line, cards.primary_type
                        FROM card_faces
                        JOIN cards ON card_faces.card_id = cards.id
                        WHERE card_faces.face_normalized_name = :normalized
                        LIMIT 1
                        """
                    ),
                    {'normalized': normalized},
                ).fetchone()
            if row:
                result[original] = {
                    'name': row[0],
                    'is_land': bool(row[1]),
                    'is_basic_land': bool(row[2]),
                    'is_standard_banned': bool(row[3]),
                    'is_vintage_restricted': bool(row[4]),
                    'type_line': row[5],
                    'primary_type': row[6],
                }
    return result
