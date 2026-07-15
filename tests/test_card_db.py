import json
import os
import zipfile

import pytest
from sqlalchemy import create_engine, text

from app import card_db


def _atomic_cards_zip(path):
    payload = {
        'data': {
            'Black Lotus': [
                {
                    'types': ['Artifact'],
                    'supertypes': [],
                    'subtypes': [],
                    'legalities': {'vintage': 'Restricted'},
                }
            ]
        }
    }
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('AtomicCards.json', json.dumps(payload))


def test_build_card_database_sends_user_agent(monkeypatch, tmp_path):
    source_zip = tmp_path / 'AtomicCards.json.zip'
    _atomic_cards_zip(source_zip)
    seen = {}

    class FakeResponse:
        def __init__(self, request):
            seen['request'] = request
            self.handle = open(source_zip, 'rb')

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            self.handle.close()

        def read(self, size=-1):
            return self.handle.read(size)

    def fake_urlopen(request):
        return FakeResponse(request)

    monkeypatch.setattr(card_db, 'urlopen', fake_urlopen)

    database_url = os.environ.get('TEST_CARD_DATABASE_URL')
    if not database_url:
        pytest.skip('TEST_CARD_DATABASE_URL is required for MySQL card database tests.')
    try:
        engine = create_engine(database_url, pool_pre_ping=True, future=True)
        with engine.connect() as connection:
            connection.execute(text('SELECT 1'))
    except Exception as exc:
        pytest.skip(f'MySQL card test database is unavailable: {exc}')

    card_db.build_card_database(database_url, source_url='https://mtgjson.example/cards.zip')

    assert seen['request'].full_url == 'https://mtgjson.example/cards.zip'
    assert seen['request'].get_header('User-agent') == card_db.CARD_DB_USER_AGENT
    assert card_db.lookup_card(database_url, 'Black Lotus') == 'Black Lotus'


def test_build_card_database_rejects_non_https_urls():
    database_url = 'mysql+pymysql://walter:walter@127.0.0.1:3306/walter_test_cards?charset=utf8mb4'

    for source_url in ['http://mtgjson.example/cards.zip', 'file:///tmp/cards.zip', 'mtgjson.example/cards.zip']:
        try:
            card_db.build_card_database(database_url, source_url=source_url)
        except ValueError as exc:
            assert 'https URL' in str(exc)
        else:
            raise AssertionError(f'{source_url} should have been rejected')
