import io
import json

from app.models import Role, User, Tournament, TournamentPlayer, Round, Match, MatchResult


def login_admin(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='backup-admin@example.com', name='Backup Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    session.add(admin)
    session.commit()
    response = client.post('/login', data={'email': admin.email, 'password': 'secret'})
    assert response.status_code == 302
    return admin


def test_admin_backup_export_and_import(client, session):
    login_admin(client, session)
    custom_role = Role(
        name='backup judge',
        permissions=json.dumps({'tournaments.manage': True, 'admin.panel': False}),
        level=250,
    )
    player = User(
        email='backup-player@example.com',
        name='Backup Player',
        role=custom_role,
        permission_overrides=json.dumps({'admin.panel': 'deny'}),
    )
    player.set_password('player-secret')
    tournament = Tournament(name='Backup Event', format='Constructed', passcode='1234')
    session.add_all([custom_role, player, tournament])
    session.commit()
    entry = TournamentPlayer(tournament=tournament, user=player, points=3, game_wins=2)
    round_one = Round(tournament=tournament, number=1)
    session.add_all([entry, round_one])
    session.commit()
    match = Match(round=round_one, player1=entry, table_number=1, completed=True)
    match.result = MatchResult(player1_wins=2, player2_wins=0)
    session.add(match)
    session.commit()

    export_response = client.get('/admin/backup/export')
    assert export_response.status_code == 200
    payload = json.loads(export_response.data)
    assert payload['format'] == 'walter-admin-backup'
    assert any(role['name'] == 'backup judge' for role in payload['roles'])
    assert any(user['permission_overrides'] == {'admin.panel': 'deny'} for user in payload['users'])
    assert any(t['name'] == 'Backup Event' for t in payload['tournaments'])

    session.delete(tournament)
    session.delete(player)
    session.delete(custom_role)
    session.commit()
    assert session.query(Tournament).filter_by(name='Backup Event').first() is None
    assert session.query(User).filter_by(email='backup-player@example.com').first() is None

    import_response = client.post(
        '/admin/backup',
        data={'backup_file': (io.BytesIO(export_response.data), 'backup.json'), 'overwrite': 'yes'},
        content_type='multipart/form-data',
        follow_redirects=True,
    )
    assert import_response.status_code == 200
    restored_user = session.query(User).filter_by(email='backup-player@example.com').one()
    restored_tournament = session.query(Tournament).filter_by(name='Backup Event').one()
    restored_entry = session.query(TournamentPlayer).filter_by(
        tournament_id=restored_tournament.id,
        user_id=restored_user.id,
    ).one()
    assert restored_user.role.name == 'backup judge'
    assert restored_user.permission_overrides_dict() == {'admin.panel': 'deny'}
    assert restored_user.check_password('player-secret')
    assert restored_entry.points == 3
    assert session.query(Match).join(Round).filter(Round.tournament_id == restored_tournament.id).count() == 1


def test_admin_backup_export_and_import_with_encryption(client, session):
    login_admin(client, session)
    encrypted_role = Role(
        name='encrypted judge',
        permissions=json.dumps({'tournaments.manage': True}),
        level=275,
    )
    encrypted_user = User(email='encrypted-player@example.com', name='Encrypted Player', role=encrypted_role)
    encrypted_user.set_password('player-secret')
    encrypted_tournament = Tournament(name='Encrypted Event', format='Constructed', passcode='9876')
    session.add_all([encrypted_role, encrypted_user, encrypted_tournament])
    session.commit()
    encrypted_entry = TournamentPlayer(tournament=encrypted_tournament, user=encrypted_user, points=6)
    session.add(encrypted_entry)
    session.commit()

    export_response = client.post(
        '/admin/backup/export',
        data={
            'export_password': 'correct horse battery staple',
            'export_password_confirm': 'correct horse battery staple',
        },
    )
    assert export_response.status_code == 200
    encrypted_payload = json.loads(export_response.data)
    assert encrypted_payload['format'] == 'walter-admin-backup-encrypted'
    assert encrypted_payload['encryption']['algorithm'] == 'AES-256-GCM'
    assert b'encrypted-player@example.com' not in export_response.data
    assert b'Encrypted Event' not in export_response.data

    session.delete(encrypted_tournament)
    session.delete(encrypted_user)
    session.delete(encrypted_role)
    session.commit()

    missing_password_response = client.post(
        '/admin/backup',
        data={'backup_file': (io.BytesIO(export_response.data), 'encrypted-backup.json'), 'overwrite': 'yes'},
        content_type='multipart/form-data',
        follow_redirects=True,
    )
    assert missing_password_response.status_code == 200
    assert session.query(User).filter_by(email='encrypted-player@example.com').first() is None

    import_response = client.post(
        '/admin/backup',
        data={
            'backup_file': (io.BytesIO(export_response.data), 'encrypted-backup.json'),
            'backup_password': 'correct horse battery staple',
            'overwrite': 'yes',
        },
        content_type='multipart/form-data',
        follow_redirects=True,
    )
    assert import_response.status_code == 200
    restored_user = session.query(User).filter_by(email='encrypted-player@example.com').one()
    restored_tournament = session.query(Tournament).filter_by(name='Encrypted Event').one()
    restored_entry = session.query(TournamentPlayer).filter_by(
        tournament_id=restored_tournament.id,
        user_id=restored_user.id,
    ).one()
    assert restored_user.role.name == 'encrypted judge'
    assert restored_user.check_password('player-secret')
    assert restored_entry.points == 6
