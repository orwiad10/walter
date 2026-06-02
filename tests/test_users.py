import json

from app.app import db

from app.models import User, Role


def test_user_crud(session):
    role_user = session.query(Role).filter_by(name='user').first()
    # create
    u = User(email='test@example.com', name='Test', role=role_user)
    u.set_password('secret')
    session.add(u)
    session.commit()

    fetched = session.query(User).filter_by(email='test@example.com').one()
    assert fetched.check_password('secret')

    # modify
    fetched.name = 'Updated'
    session.commit()
    assert session.get(User, fetched.id).name == 'Updated'

    # delete
    session.delete(fetched)
    session.commit()
    assert session.query(User).count() == 0


def test_judge_roles_exist(session):
    roles = {r.name for r in session.query(Role).all()}
    assert 'venue judge' in roles
    assert 'event head judge' in roles
    assert 'floor judge' in roles


def test_judge_roles_have_user_manage(session):
    roles = {r.name: r for r in session.query(Role).all()}
    for name in ('venue judge', 'event head judge', 'floor judge'):
        perms = json.loads(roles[name].permissions)
        assert perms.get('users.manage')


def test_user_permission_overrides(session):
    manager_role = session.query(Role).filter_by(name='manager').one()
    user = User(email='override@example.com', name='Override User', role=manager_role)
    user.set_password('secret')
    user.permission_overrides = json.dumps({'admin.panel': 'allow', 'users.manage': 'deny'})
    session.add(user)
    session.commit()

    fetched = session.query(User).filter_by(email='override@example.com').one()
    assert fetched.has_permission('admin.panel')
    assert not fetched.has_permission('users.manage')


def test_default_role_levels(session):
    levels = {r.name: r.level for r in session.query(Role).all()}
    assert levels['admin'] == 0
    assert levels['manager'] == 100
    assert levels['venue judge'] == 200
    assert levels['event head judge'] == 300
    assert levels['floor judge'] == 400
    assert levels['user'] == 500


def test_roles_can_approve_join(session):
    roles = {r.name: r for r in session.query(Role).all()}
    for name in ('manager', 'venue judge', 'event head judge', 'floor judge'):
        perms = json.loads(roles[name].permissions)
        assert perms.get('tournaments.approve_join')


def test_admin_bulk_delete_users(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    user_role = session.query(Role).filter_by(name='user').one()
    admin = User(email='admin-bulk@example.com', name='Bulk Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    user_one = User(email='bulk1@example.com', name='Bulk One', role=user_role)
    user_two = User(email='bulk2@example.com', name='Bulk Two', role=user_role)
    session.add_all([admin, user_one, user_two])
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            '/admin/users/bulk-delete',
            data={'user_ids': [str(user_one.id), str(user_two.id), str(admin.id)]},
            follow_redirects=True,
        )

    assert response.status_code == 200
    assert session.get(User, user_one.id) is None
    assert session.get(User, user_two.id) is None
    assert session.get(User, admin.id) is not None


def test_registration_sends_mailgun_pin_and_requires_verification(client, session, app, monkeypatch):
    from app.models import PendingRegistration

    app.config['MAILGUN_API_KEY'] = 'key-test'
    app.config['MAILGUN_DOMAIN'] = 'mg.example.com'
    app.config['MAILGUN_FROM_EMAIL'] = 'Walter <noreply@example.com>'
    sent = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(request_obj, timeout=10):
        sent['url'] = request_obj.full_url
        sent['body'] = request_obj.data.decode()
        sent['auth'] = request_obj.headers.get('Authorization')
        return FakeResponse()

    monkeypatch.setattr('app.app.urllib.request.urlopen', fake_urlopen)

    response = client.post('/register', data={
        'email': 'new@example.com',
        'name': 'New User',
        'password': 'secret',
        'password_confirm': 'secret',
    })

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/register/verify?email=new@example.com')
    pending = session.query(PendingRegistration).filter_by(email='new@example.com').one()
    assert len(pending.verification_pin) == 6
    assert sent['url'] == 'https://api.mailgun.net/v3/mg.example.com/messages'
    assert 'new%40example.com' in sent['body']
    assert pending.verification_pin in sent['body']
    assert session.query(User).filter_by(email='new@example.com').first() is None

    verify_response = client.post('/register/verify', data={
        'email': 'new@example.com',
        'pin': pending.verification_pin,
        'password': 'secret',
    })

    assert verify_response.status_code == 302
    created = session.query(User).filter_by(email='new@example.com').one()
    assert created.check_password('secret')
    assert session.query(PendingRegistration).filter_by(email='new@example.com').first() is None


def test_invite_only_registration_requires_tournament_passcode(client, session, app, monkeypatch):
    from app.models import Tournament

    app.config['ACCOUNT_CREATION_INVITE_ONLY'] = True

    response = client.post('/register', data={
        'email': 'blocked@example.com',
        'name': 'Blocked User',
        'password': 'secret',
        'password_confirm': 'secret',
    })

    assert response.status_code == 302
    assert session.query(User).filter_by(email='blocked@example.com').first() is None

    tournament = Tournament(name='Invite Event', format='Constructed', passcode='1234')
    session.add(tournament)
    session.commit()

    app.config['MAILGUN_API_KEY'] = 'key-test'
    app.config['MAILGUN_DOMAIN'] = 'mg.example.com'
    app.config['MAILGUN_FROM_EMAIL'] = 'Walter <noreply@example.com>'

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr('app.app.urllib.request.urlopen', lambda request_obj, timeout=10: FakeResponse())

    response = client.post('/register', data={
        'email': 'invited@example.com',
        'name': 'Invited User',
        'password': 'secret',
        'password_confirm': 'secret',
        'tournament_id': str(tournament.id),
        'passcode': '1234',
    })

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/register/verify?email=invited@example.com')
