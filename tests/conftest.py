import json
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import pytest
from app.app import create_app, db
from app.models import Role, DEFAULT_ROLE_PERMISSIONS, DEFAULT_ROLE_LEVELS
from app import card_db


@pytest.fixture
def app(tmp_path, monkeypatch):
    # use temporary SQLite databases for testing
    monkeypatch.setenv("MTG_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("MTG_LOG_DB_PATH", str(tmp_path / "test_logs.db"))
    card_db_path = tmp_path / "cards.db"
    monkeypatch.setenv("MTG_CARD_DB_PATH", str(card_db_path))
    application = create_app()
    application.config['TESTING'] = True
    with application.app_context():
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
        sample_cards = [
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
        card_db.populate_card_database(str(card_db_path), sample_cards)
        yield application
        db.session.remove()


@pytest.fixture
def session(app):
    return db.session


@pytest.fixture
def client(app):
    return app.test_client()
