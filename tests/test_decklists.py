import base64
import io
import json
import os

import pytest

import json

from app.app import db
from app.models import (
    Role,
    Tournament,
    TournamentPlayer,
    TournamentPlayerDeck,
    Round,
    User,
)


@pytest.fixture
def user(session):
    role = session.query(Role).filter_by(name='user').first()
    player = User(email='player@example.com', name='Player One', role=role)
    player.set_password('secret')
    session.add(player)
    session.commit()
    return player


def create_tournament(session, name='Deck Event', fmt='Constructed'):
    tournament = Tournament(name=name, format=fmt, passcode='0000')
    session.add(tournament)
    session.commit()
    return tournament


def register_player(session, tournament, user):
    tp = TournamentPlayer(tournament_id=tournament.id, user_id=user.id)
    session.add(tp)
    session.commit()
    return tp


def login(client, user):
    return client.post(
        '/login',
        data={'email': user.email, 'password': 'secret'},
        follow_redirects=True,
    )


def test_manual_deck_submission(client, session, user):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    deck_text = '1 Black Lotus\n1 Strip Mine\nSideboard\n2 Null Rod'
    response = client.post(
        f'/t/{tournament.id}/deck/manual',
        data={'deck_text': deck_text},
        follow_redirects=False,
    )
    assert response.status_code == 302

    session.refresh(tp)
    deck = tp.deck
    assert deck is not None
    assert deck.source == 'manual'
    assert any(card['name'] == 'Black Lotus' for card in deck.mainboard_cards())
    assert deck.total_sideboard() == 2
@pytest.mark.parametrize(
    ('deck_url', 'expected_code'),
    [
        ('https://www.moxfield.com/decks/abc123', 'abc123'),
        ('https://www.moxfield.com/decks/commander/AbC123', 'AbC123'),
    ],
)
def test_moxfield_import(client, session, user, monkeypatch, deck_url, expected_code):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    sample_payload = {
        'boards': {
            'mainboard': {
                'cards': {
                    '1': {'quantity': 2, 'card': {'name': 'Archon of Emeria'}},
                    '2': {'quantity': 1, 'card': {'name': 'Black Lotus'}},
                }
            },
            'sideboard': {
                'cards': {
                    'a': {'quantity': 1, 'card': {'name': 'Null Rod'}},
                }
            },
        }
    }

    class DummyResponse:
        status_code = 200

        def json(self):
            return sample_payload

    requests_made = []

    def fake_get(url, timeout=15, **kwargs):
        requests_made.append({'url': url, 'headers': kwargs.get('headers')})
        return DummyResponse()

    monkeypatch.setattr('app.app.requests.get', fake_get)

    response = client.post(
        f'/t/{tournament.id}/deck/moxfield',
        data={'moxfield_url': deck_url},
    )
    assert response.status_code == 302

    session.refresh(tp)
    deck = tp.deck
    assert deck is not None
    assert deck.source == 'moxfield'
    assert deck.moxfield_url == deck_url
    assert requests_made == [
        {
            'url': f'https://api2.moxfield.com/v3/decks/all/{expected_code}',
            'headers': {
                'Accept': 'application/json',
                'User-Agent': 'WalterDeckImporter/1.0',
            },
        }
    ]
    names = {card['name'] for card in deck.mainboard_cards()}
    assert {'Archon of Emeria', 'Black Lotus'} <= names


def test_moxfield_import_retries_on_forbidden(client, session, user, monkeypatch):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    sample_payload = {
        'boards': {
            'mainboard': {
                'cards': {
                    '1': {'quantity': 2, 'card': {'name': 'Archon of Emeria'}},
                }
            },
            'sideboard': {'cards': {}},
        }
    }

    class DummyResponse:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload

        def json(self):
            if self._payload is None:
                raise ValueError('no payload')
            return self._payload

    calls = []

    def fake_get(url, timeout=15, headers=None, **kwargs):
        calls.append({'url': url, 'headers': headers})
        if len(calls) == 1:
            return DummyResponse(403)
        return DummyResponse(200, sample_payload)

    monkeypatch.setattr('app.app.requests.get', fake_get)

    response = client.post(
        f'/t/{tournament.id}/deck/moxfield',
        data={'moxfield_url': 'https://www.moxfield.com/decks/abc123'},
    )
    assert response.status_code == 302

    session.refresh(tp)
    deck = tp.deck
    assert deck is not None
    assert deck.source == 'moxfield'
    assert len(calls) == 2
    assert calls[0]['headers']['User-Agent'] == 'WalterDeckImporter/1.0'
    assert calls[1]['headers']['User-Agent'] == 'Mozilla/5.0'


def test_moxfield_import_scrapes_frontend_when_api_fails(client, session, user, monkeypatch):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    frontend_payload = {
        'data': [
            {
                'deck': {
                    'boards': {
                        'mainboard': {
                            'cards': {
                                '1': {'quantity': 1, 'card': {'name': 'Black Lotus'}},
                            }
                        },
                        'sideboard': {
                            'cards': {
                                '2': {'quantity': 1, 'card': {'name': 'Null Rod'}},
                            }
                        },
                    }
                }
            }
        ]
    }
    frontend_html = (
        '<html><body><script type="application/json" id="__NUXT_DATA__">'
        + json.dumps(frontend_payload)
        + '</script></body></html>'
    )

    class ApiErrorResponse:
        status_code = 500

        def json(self):
            return {'error': 'server error'}

    class FrontendResponse:
        status_code = 200
        text = frontend_html

    requests_made = []

    def fake_get(url, timeout=15, headers=None, **kwargs):
        requests_made.append({'url': url, 'headers': headers})
        if url.startswith('https://api2.moxfield.com'):
            return ApiErrorResponse()
        return FrontendResponse()

    monkeypatch.setattr('app.app.requests.get', fake_get)

    response = client.post(
        f'/t/{tournament.id}/deck/moxfield',
        data={'moxfield_url': 'https://www.moxfield.com/decks/abc123'},
    )
    assert response.status_code == 302

    session.refresh(tp)
    deck = tp.deck
    assert deck is not None
    assert deck.source == 'moxfield'
    assert deck.total_sideboard() == 1
    assert requests_made[0]['url'] == 'https://api2.moxfield.com/v3/decks/all/abc123'
    assert requests_made[1]['url'] == 'https://www.moxfield.com/decks/abc123'
    frontend_headers = requests_made[1]['headers']
    assert frontend_headers['User-Agent'] == 'Mozilla/5.0'
    assert 'text/html' in frontend_headers['Accept']


def test_mtgo_deck_upload(client, session, user):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    mtgo_text = '1 Strip Mine\n1 Black Lotus\nSideboard\n1 Null Rod\n'
    response = client.post(
        f'/t/{tournament.id}/deck/mtgo',
        data={'mtgo_file': (io.BytesIO(mtgo_text.encode('utf-8')), 'deck.txt')},
        content_type='multipart/form-data',
    )
    assert response.status_code == 302

    session.refresh(tp)
    deck = tp.deck
    assert deck is not None
    assert deck.source == 'mtgo'
    assert deck.total_mainboard() == 2
    assert deck.total_sideboard() == 1


def test_deck_image_upload_for_draft(client, session, user):
    tournament = create_tournament(session, fmt='Draft')
    tp = register_player(session, tournament, user)
    login(client, user)

    png_bytes = base64.b64decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO5lH2gAAAAASUVORK5CYII='
    )
    response = client.post(
        f'/t/{tournament.id}/deck/image',
        data={'deck_image': (io.BytesIO(png_bytes), 'deck.png')},
        content_type='multipart/form-data',
    )
    assert response.status_code == 302

    session.refresh(tp)
    deck = tp.deck
    assert deck is not None
    assert deck.image_path

    # Ensure non-draft events reject image uploads
    other = create_tournament(session, name='Constructed', fmt='Constructed')
    register_player(session, other, user)
    response = client.post(
        f'/t/{other.id}/deck/image',
        data={'deck_image': (io.BytesIO(png_bytes), 'deck2.png')},
        content_type='multipart/form-data',
    )
    assert response.status_code == 302
    other_tp = (
        session.query(TournamentPlayer)
        .filter_by(tournament_id=other.id, user_id=user.id)
        .first()
    )
    assert other_tp.deck is None


def test_deck_image_delete_removes_file(client, session, user, app):
    tournament = create_tournament(session, fmt='Draft')
    tp = register_player(session, tournament, user)
    login(client, user)

    png_bytes = base64.b64decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO5lH2gAAAAASUVORK5CYII='
    )
    upload_response = client.post(
        f'/t/{tournament.id}/deck/image',
        data={'deck_image': (io.BytesIO(png_bytes), 'deck.png')},
        content_type='multipart/form-data',
    )
    assert upload_response.status_code == 302

    session.refresh(tp)
    deck = tp.deck
    assert deck is not None and deck.image_path
    image_path = deck.image_path
    media_dir = app.config['MEDIA_STORAGE_DIR']
    file_path = os.path.join(media_dir, image_path)
    assert os.path.exists(file_path)

    response = client.post(f'/t/{tournament.id}/deck/image/delete')
    assert response.status_code == 302

    session.refresh(tp)
    assert tp.deck.image_path is None
    assert not os.path.exists(file_path)


def test_card_search_endpoint(client, session, user):
    tournament = create_tournament(session)
    register_player(session, tournament, user)
    login(client, user)

    response = client.get(f'/t/{tournament.id}/deck/search?q=archon')
    assert response.status_code == 200
    data = response.get_json()
    assert 'results' in data
    assert any('Archon of Emeria' == name for name in data['results'])


def test_manual_deck_ignores_unknown_cards(client, session, user):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    deck_text = '1 Black Lotus\n1 Imaginary Card\nSideboard\n1 Null Rod'
    client.post(
        f'/t/{tournament.id}/deck/manual',
        data={'deck_text': deck_text},
    )

    session.refresh(tp)
    deck = tp.deck
    assert deck is not None
    assert {card['name'] for card in deck.mainboard_cards()} == {'Black Lotus'}
    assert {card['name'] for card in deck.sideboard_cards()} == {'Null Rod'}


def test_manual_deck_accepts_single_face_name(client, session, user):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    deck_text = '1 Witch Enchanter'
    client.post(
        f'/t/{tournament.id}/deck/manual',
        data={'deck_text': deck_text},
    )

    session.refresh(tp)
    deck = tp.deck
    assert deck is not None
    names = {card['name'] for card in deck.mainboard_cards()}
    assert 'Witch Enchanter // Witch-Blessed Meadow' in names


def test_manual_deck_parse_errors_still_saved(client, session, user):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    deck_text = '1 Black Lotus\nBad Line\nSideboard\n1 Null Rod'
    client.post(
        f'/t/{tournament.id}/deck/manual',
        data={'deck_text': deck_text},
    )

    session.refresh(tp)
    deck = tp.deck
    assert deck is not None
    assert deck.total_mainboard() == 1
    assert deck.total_sideboard() == 1


def submit_deck(client, tournament_id, deck_json):
    return client.post(
        f'/t/{tournament_id}/deck/manual',
        data={'deck_json': json.dumps(deck_json), 'action': 'submit'},
    )


def test_submit_requires_minimum_mainboard(client, session, user):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    submit_deck(
        client,
        tournament.id,
        {'main': [{'name': 'Black Lotus', 'count': 1}], 'side': []},
    )

    session.refresh(tp)
    assert tp.deck is not None
    assert tp.deck.is_submitted is False


def test_submit_valid_deck_marks_submitted(client, session, user):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    submit_deck(
        client,
        tournament.id,
        {'main': [{'name': 'Plains', 'count': 60}], 'side': []},
    )

    session.refresh(tp)
    assert tp.deck is not None
    assert tp.deck.is_submitted is True


def test_submit_non_basic_land_limit(client, session, user):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    submit_deck(
        client,
        tournament.id,
        {
            'main': [
                {'name': 'Ancient Tomb', 'count': 5},
                {'name': 'Plains', 'count': 55},
            ],
            'side': [],
        },
    )

    session.refresh(tp)
    assert tp.deck is not None
    assert tp.deck.is_submitted is False


def test_submit_restricted_card_limit(client, session, user):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    submit_deck(
        client,
        tournament.id,
        {
            'main': [
                {'name': 'Black Lotus', 'count': 2},
                {'name': 'Plains', 'count': 58},
            ],
            'side': [],
        },
    )

    session.refresh(tp)
    assert tp.deck is not None
    assert tp.deck.is_submitted is False


def test_submit_banned_card_rejected(client, session, user):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    submit_deck(
        client,
        tournament.id,
        {
            'main': [
                {'name': 'Hopeless Nightmare', 'count': 4},
                {'name': 'Plains', 'count': 56},
            ],
            'side': [],
        },
    )

    session.refresh(tp)
    assert tp.deck is not None
    assert tp.deck.is_submitted is False


def test_deck_changes_locked_prevents_updates(client, session, user):
    tournament = create_tournament(session)
    register_player(session, tournament, user)
    session.add(Round(tournament_id=tournament.id, number=1))
    session.commit()
    login(client, user)

    response = client.post(
        f'/t/{tournament.id}/deck/manual',
        data={'deck_text': '1 Black Lotus'},
    )
    assert response.status_code == 302

    tp = (
        session.query(TournamentPlayer)
        .filter_by(tournament_id=tournament.id, user_id=user.id)
        .first()
    )
    session.refresh(tp)
    assert tp.deck is None
