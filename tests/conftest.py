import json
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
from sqlalchemy import create_engine, text
from app.app import create_app, db
from app.models import Role, DEFAULT_ROLE_PERMISSIONS, DEFAULT_ROLE_LEVELS
from app import card_db


SAMPLE_CARDS = [
    {'name': 'Strip Mine', 'is_land': True, 'is_basic_land': False},
    {'name': 'Archon of Emeria'},
    {'name': 'Black Lotus', 'is_vintage_restricted': True},
    {'name': 'Mana Crypt'},
    {'name': 'Karakas', 'is_land': True, 'is_basic_land': False},
    {'name': 'Chancellor of the Annex'},
    {'name': 'Chrome Mox'},
    {'name': 'Solitude'},
    {'name': 'Clarion Conqueror'},
    {'name': 'Cavern of Souls', 'is_land': True, 'is_basic_land': False},
    {'name': 'Mox Emerald'},
    {'name': 'Mox Jet'},
    {'name': 'Mox Pearl'},
    {'name': 'Mox Ruby'},
    {'name': 'Mox Sapphire'},
    {'name': 'Plains', 'is_land': True, 'is_basic_land': True},
    {'name': 'Seasoned Dungeoneer'},
    {'name': 'Anointed Peacekeeper'},
    {'name': 'Vexing Bauble'},
    {'name': 'Wasteland', 'is_land': True, 'is_basic_land': False},
    {'name': 'White Plume Adventurer'},
    {
        'name': 'Witch Enchanter // Witch-Blessed Meadow',
        'face_names': ['Witch Enchanter', 'Witch-Blessed Meadow'],
        'is_land': True,
        'is_basic_land': False,
    },
    {'name': 'Ancient Tomb', 'is_land': True, 'is_basic_land': False},
    {'name': 'Void Mirror'},
    {'name': 'March of Otherworldly Light'},
    {'name': 'Archon of Absolution'},
    {'name': 'Leyline of the Void'},
    {'name': 'Containment Priest'},
    {'name': 'Swords to Plowshares'},
    {'name': 'Null Rod'},
    {'name': 'Hopeless Nightmare', 'is_standard_banned': True},
]


@pytest.fixture
def app(tmp_path, monkeypatch):
    base_url = os.environ.get("TEST_DATABASE_URL", "mysql+pymysql://walter:walter@127.0.0.1:3306/walter_test?charset=utf8mb4")
    log_url = os.environ.get("TEST_LOG_DATABASE_URL", "mysql+pymysql://walter:walter@127.0.0.1:3306/walter_test_logs?charset=utf8mb4")
    media_url = os.environ.get("TEST_MEDIA_DATABASE_URL", "mysql+pymysql://walter:walter@127.0.0.1:3306/walter_test_media?charset=utf8mb4")
    card_url = os.environ.get("TEST_CARD_DATABASE_URL", "mysql+pymysql://walter:walter@127.0.0.1:3306/walter_test_cards?charset=utf8mb4")
    monkeypatch.setenv("DATABASE_URL", base_url)
    monkeypatch.setenv("LOG_DATABASE_URL", log_url)
    monkeypatch.setenv("MEDIA_DATABASE_URL", media_url)
    monkeypatch.setenv("CARD_DATABASE_URL", card_url)
    monkeypatch.setenv("MEDIA_STORAGE_DIR", str(tmp_path / "media"))
    try:
        for url in (base_url, log_url, media_url, card_url):
            engine = create_engine(url, pool_pre_ping=True, future=True)
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
    except Exception as exc:
        pytest.skip(f"MySQL test databases are unavailable: {exc}")
    card_db.populate_card_database(card_url, SAMPLE_CARDS)
    application = create_app()
    application.config['TESTING'] = True
    with application.app_context():
        db.drop_all()
        db.drop_all(bind_key="logs")
        db.drop_all(bind_key="media")
        db.create_all()
        # set up default roles
        for name, perms in DEFAULT_ROLE_PERMISSIONS.items():
            role = Role(
                name=name,
                permissions=json.dumps(perms),
                level=DEFAULT_ROLE_LEVELS.get(name, 500),
            )
            db.session.add(role)
        db.session.commit()
        yield application
        db.session.remove()


@pytest.fixture
def session(app):
    return db.session


@pytest.fixture
def client(app):
    return app.test_client()
