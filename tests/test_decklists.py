import base64
import io

import pytest

from app.app import db
from app.models import (
    Role,
    Tournament,
    TournamentPlayer,
    TournamentPlayerDeck,
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


def test_moxfield_import(client, session, user, monkeypatch):
    tournament = create_tournament(session)
    tp = register_player(session, tournament, user)
    login(client, user)

    sample_payload = {
        'mainboard': {
            '1': {'quantity': 2, 'card': {'name': 'Archon of Emeria'}},
            '2': {'quantity': 1, 'card': {'name': 'Black Lotus'}},
        },
        'sideboard': {
            'a': {'quantity': 1, 'card': {'name': 'Null Rod'}},
        },
    }

    class DummyResponse:
        status_code = 200

        def json(self):
            return sample_payload

    monkeypatch.setattr('app.app.requests.get', lambda url, timeout=15: DummyResponse())

    deck_url = 'https://www.moxfield.com/decks/abc123'
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
    names = {card['name'] for card in deck.mainboard_cards()}
    assert {'Archon of Emeria', 'Black Lotus'} <= names


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


def test_card_search_endpoint(client, session, user):
    tournament = create_tournament(session)
    register_player(session, tournament, user)
    login(client, user)

    response = client.get(f'/t/{tournament.id}/deck/search?q=archon')
    assert response.status_code == 200
    data = response.get_json()
    assert 'results' in data
    assert any('Archon of Emeria' == name for name in data['results'])
