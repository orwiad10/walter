import json
import zipfile

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

    db_path = tmp_path / 'cards.db'
    card_db.build_card_database(str(db_path), source_url='https://mtgjson.example/cards.zip')

    assert seen['request'].full_url == 'https://mtgjson.example/cards.zip'
    assert seen['request'].get_header('User-agent') == card_db.CARD_DB_USER_AGENT
    assert card_db.lookup_card(str(db_path), 'Black Lotus') == 'Black Lotus'


def test_build_card_database_rejects_non_https_urls(tmp_path):
    db_path = tmp_path / 'cards.db'

    for source_url in ['http://mtgjson.example/cards.zip', 'file:///tmp/cards.zip', 'mtgjson.example/cards.zip']:
        try:
            card_db.build_card_database(str(db_path), source_url=source_url)
        except ValueError as exc:
            assert 'https URL' in str(exc)
        else:
            raise AssertionError(f'{source_url} should have been rejected')
