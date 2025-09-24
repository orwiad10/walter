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
            'Strip Mine', 'Archon of Emeria', 'Black Lotus', 'Mana Crypt', 'Karakas',
            'Chancellor of the Annex', 'Chrome Mox', 'Solitude', 'Clarion Conqueror',
            'Cavern of Souls', 'Mox Emerald', 'Mox Jet', 'Mox Pearl', 'Mox Ruby',
            'Mox Sapphire', 'Plains', 'Seasoned Dungeoneer', 'Anointed Peacekeeper',
            'Vexing Bauble', 'Wasteland', 'White Plume Adventurer', 'Witch Enchanter',
            'Ancient Tomb', 'Void Mirror', 'March of Otherworldly Light',
            'Archon of Absolution', 'Leyline of the Void', 'Containment Priest',
            'Swords to Plowshares', 'Null Rod'
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
