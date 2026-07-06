import json

from sqlalchemy import text

from app.app import db

from app.models import SiteLog, User, Role


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


def test_mailgun_domain_validation_rejects_url_syntax(app):
    from app.app import _mailgun_messages_url

    assert _mailgun_messages_url('mg.example.com') == 'https://api.mailgun.net/v3/mg.example.com/messages'

    for domain in ['https://evil.example', 'mg.example.com/messages', 'mg..example.com', 'file:mg.example.com']:
        try:
            _mailgun_messages_url(domain)
        except RuntimeError as exc:
            assert 'Mailgun domain' in str(exc) or 'Mailgun API URL' in str(exc)
        else:
            raise AssertionError(f'{domain} should have been rejected')


def test_invite_only_registration_blocks_public_tournament_registration(client, session, app, monkeypatch):
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
    })

    assert response.status_code == 302
    assert response.headers['Location'].endswith('/register')
    assert session.query(User).filter_by(email='invited@example.com').first() is None


def test_account_locks_after_three_bad_passwords(client, session, app):
    app.config['ACCOUNT_LOCKOUT_ATTEMPTS'] = 3
    user_role = session.query(Role).filter_by(name='user').one()
    user = User(email='lock@example.com', name='Lock User', role=user_role)
    user.set_password('secret')
    session.add(user)
    session.commit()

    for _ in range(3):
        response = client.post('/login', data={'email': user.email, 'password': 'wrong'})
        assert response.status_code == 200

    session.refresh(user)
    assert user.locked_at is not None
    assert user.failed_login_count == 3

    response = client.post('/login', data={'email': user.email, 'password': 'secret'})
    assert response.status_code == 200
    assert b'Account locked' in response.data


def test_site_logs_and_current_connections_use_cf_connecting_ip(client, session):
    from app.app import CURRENT_CONNECTIONS

    CURRENT_CONNECTIONS.clear()
    response = client.post(
        '/login',
        data={'email': 'missing-cf@example.com', 'password': 'wrong'},
        headers={
            'CF-Connecting-IP': '198.51.100.24',
            'X-Real-IP': '172.69.151.76',
            'X-Forwarded-For': '203.0.113.9, 172.69.151.76',
        },
    )

    assert response.status_code == 200
    log = session.query(SiteLog).filter_by(action='login', result='failure').order_by(SiteLog.id.desc()).first()
    assert log.ip_address == '198.51.100.24'
    assert any(item['ip_address'] == '198.51.100.24' for item in CURRENT_CONNECTIONS.values())

def test_admin_bad_passwords_blacklist_ip_without_locking_account(client, session, app):
    app.config['ACCOUNT_LOCKOUT_ATTEMPTS'] = 3
    app.config['IP_BLACKLIST_ATTEMPTS'] = 10
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='admin-threshold@example.com', name='Admin Threshold', role=admin_role, is_admin=True)
    admin.set_password('secret')
    session.add(admin)
    session.commit()

    for _ in range(3):
        response = client.post('/login', data={'email': admin.email, 'password': 'wrong'})
        assert response.status_code == 200

    session.refresh(admin)
    assert admin.locked_at is None
    assert admin.lock_reason is None
    assert admin.failed_login_count == 3

    from app.models import BlacklistedIP
    entry = session.query(BlacklistedIP).filter_by(ip_address='127.0.0.1').one()
    assert entry.is_active
    assert 'Admin account bad login threshold reached' in entry.reason

    response = client.get('/')
    assert response.status_code == 403


def test_ip_blacklisted_after_ten_bad_logins(client, session, app):
    app.config['IP_BLACKLIST_ATTEMPTS'] = 10
    for _ in range(10):
        response = client.post('/login', data={'email': 'missing@example.com', 'password': 'wrong'})
        assert response.status_code == 200

    from app.models import BlacklistedIP
    entry = session.query(BlacklistedIP).filter_by(ip_address='127.0.0.1').one()
    assert entry.is_active

    response = client.get('/')
    assert response.status_code == 403


def test_admin_can_view_bad_login_audit_and_export_blacklist(client, session):
    from app.models import BadLoginAttempt, BlacklistedIP
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='security-admin@example.com', name='Security Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    session.add(admin)
    session.add(BadLoginAttempt(email='bad@example.com', ip_address='203.0.113.8', result='bad_password'))
    session.add(BlacklistedIP(ip_address='203.0.113.8', reason='test'))
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.get('/admin/security/bad-logins')
        assert response.status_code == 200
        assert b'bad@example.com' in response.data
        export = client.get('/admin/security/ip-blacklist/export')
        assert export.status_code == 200
        assert b'iptables -A INPUT -s 203.0.113.8 -j DROP' in export.data


def test_admin_can_manually_lock_and_unlock_user(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    user_role = session.query(Role).filter_by(name='user').one()
    admin = User(email='admin-lock@example.com', name='Lock Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    target = User(email='manual-lock@example.com', name='Manual Lock', role=user_role)
    target.set_password('secret')
    session.add_all([admin, target])
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            f'/admin/users/{target.id}/update',
            data={
                'email': target.email,
                'account_lock_action': 'lock',
                'lock_reason': 'manual review',
            },
        )
        assert response.status_code == 302

    session.refresh(target)
    assert target.locked_at is not None
    assert target.lock_reason == 'manual review'

    with client:
        client.get('/logout')
        response = client.post('/login', data={'email': target.email, 'password': 'secret'}, follow_redirects=True)
        assert b'Account locked' in response.data

        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            f'/admin/users/{target.id}/update',
            data={
                'email': target.email,
                'account_lock_action': 'unlock',
            },
        )
        assert response.status_code == 302

    session.refresh(target)
    assert target.locked_at is None
    assert target.lock_reason is None


def test_admin_lock_succeeds_when_site_log_unavailable(client, session, app):
    admin_role = session.query(Role).filter_by(name='admin').one()
    user_role = session.query(Role).filter_by(name='user').one()
    admin = User(email='admin-log-fail@example.com', name='Log Fail Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    target = User(email='log-fail-lock@example.com', name='Log Fail Lock', role=user_role)
    target.set_password('secret')
    session.add_all([admin, target])
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        with app.app_context():
            with db.engines['logs'].begin() as conn:
                conn.execute(text('DROP TABLE site_log'))

        response = client.post(
            f'/admin/users/{target.id}/update',
            data={
                'email': target.email,
                'account_lock_action': 'lock',
                'lock_reason': 'log database unavailable',
            },
        )
        assert response.status_code == 302

    session.refresh(target)
    assert target.locked_at is not None
    assert target.lock_reason == 'log database unavailable'


def test_admin_password_change_rekeys_user_and_preserves_lock_without_unlock_action(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    user_role = session.query(Role).filter_by(name='user').one()
    admin = User(email='admin-rekey@example.com', name='Rekey Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    target = User(email='rekey-target@example.com', name='Rekey Target', role=user_role)
    target.set_password('old-secret')
    target.generate_keys('old-secret')
    target.locked_at = __import__('datetime').datetime.utcnow()
    target.lock_reason = 'manual review'
    session.add_all([admin, target])
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            f'/admin/users/{target.id}/update',
            data={
                'email': target.email,
                'password': 'new-secret',
                'password_confirm': 'new-secret',
                'account_lock_action': '',
            },
        )

    assert response.status_code == 302
    session.refresh(target)
    assert target.check_password('new-secret')
    assert target.decrypt_private_key('new-secret').startswith(b'-----BEGIN PRIVATE KEY-----')
    assert target.locked_at is not None
    assert target.lock_reason == 'manual review'


def test_anonymous_home_hides_tournaments(client, session):
    from app.models import Tournament

    tournament = Tournament(name='Private Event', format='Constructed')
    session.add(tournament)
    session.commit()

    response = client.get('/')

    assert response.status_code == 200
    assert b'Private Event' not in response.data
    assert b'Tournament information is private' not in response.data


def test_authenticated_home_shows_tournaments(client, session):
    from app.models import Tournament

    user_role = session.query(Role).filter_by(name='user').one()
    user = User(email='home-user@example.com', name='Home User', role=user_role)
    user.set_password('secret')
    tournament = Tournament(name='Visible Event', format='Constructed')
    session.add_all([user, tournament])
    session.commit()

    with client:
        login_response = client.post('/login', data={'email': user.email, 'password': 'secret'})
        assert login_response.status_code == 302
        response = client.get('/')

    assert response.status_code == 200
    assert b'Visible Event' in response.data


def test_login_next_rejects_external_redirect(client, session):
    user_role = session.query(Role).filter_by(name='user').one()
    user = User(email='next-user@example.com', name='Next User', role=user_role)
    user.set_password('secret')
    session.add(user)
    session.commit()

    response = client.post(
        '/login?next=https://evil.example/phish',
        data={'email': user.email, 'password': 'secret'},
    )

    assert response.status_code == 302
    assert response.headers['Location'] == '/'


def test_login_next_allows_local_redirect(client, session):
    user_role = session.query(Role).filter_by(name='user').one()
    user = User(email='local-next-user@example.com', name='Local Next User', role=user_role)
    user.set_password('secret')
    session.add(user)
    session.commit()

    response = client.post(
        '/login?next=/t/1/join-link',
        data={'email': user.email, 'password': 'secret'},
    )

    assert response.status_code == 302
    assert response.headers['Location'] == '/t/1/join-link'


def test_admin_user_actions_ignore_tampered_next(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    user_role = session.query(Role).filter_by(name='user').one()
    admin = User(email='admin-next@example.com', name='Next Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    user = User(email='managed-next@example.com', name='Managed Next', role=user_role)
    session.add_all([admin, user])
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            f'/admin/users/{user.id}/update',
            data={
                'email': user.email,
                'role_id': str(user_role.id),
                'next': 'https://evil.example/admin',
            },
        )

    assert response.status_code == 302
    assert response.headers['Location'] == f'/admin/users/{user.id}'


def test_site_settings_save_site_theme(client, session):
    from app.models import SiteSetting

    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='admin-theme@example.com', name='Theme Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    session.add(admin)
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            '/admin/site-settings',
            data={'action': 'settings', 'registration_mode': 'closed', 'site_theme': 'dark'},
            follow_redirects=True,
        )

    assert response.status_code == 200
    assert b'data-theme="dark"' in response.data
    assert session.get(SiteSetting, 'registration_mode').value == 'closed'
    assert session.get(SiteSetting, 'site_theme').value == 'dark'


def test_invalid_site_theme_falls_back_to_light(client, session):
    from app.models import SiteSetting

    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='admin-theme-invalid@example.com', name='Theme Invalid Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    session.add(admin)
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            '/admin/site-settings',
            data={'action': 'settings', 'registration_mode': 'open', 'site_theme': 'sepia'},
            follow_redirects=True,
        )

    assert response.status_code == 200
    assert b'data-theme="light"' in response.data
    assert session.get(SiteSetting, 'site_theme').value == 'light'


def test_non_admin_with_admin_permissions_cannot_access_site_admin_surfaces(client, session):
    from app.models import RegistrationInvite, SiteSetting

    manager_role = session.query(Role).filter_by(name='manager').one()
    manager_perms = manager_role.permissions_dict()
    manager_perms['admin.site_settings'] = True
    manager_role.permissions = json.dumps(manager_perms)
    manager = User(email='manager-site-admin@example.com', name='Manager Site Admin', role=manager_role)
    manager.set_password('secret')
    session.add(manager)
    session.commit()

    assert client.post('/login', data={'email': manager.email, 'password': 'secret'}).status_code == 302

    home = client.get('/').get_data(as_text=True)
    assert 'data-dropdown-toggle aria-expanded="false">Admin</button>' not in home
    assert 'Site Settings' not in home
    assert 'Registration Invites' not in home

    assert client.get('/admin/site-settings').status_code == 403
    assert client.post(
        '/admin/site-settings',
        data={'action': 'settings', 'registration_mode': 'closed', 'site_theme': 'dark'},
    ).status_code == 403
    assert session.get(SiteSetting, 'registration_mode') is None
    assert client.get('/admin/registration-invites').status_code == 403
    assert client.post('/admin/registration-invites', data={'email': 'invitee@example.com'}).status_code == 403
    assert session.query(RegistrationInvite).count() == 0


def test_regular_user_cannot_access_admin_management_surfaces(client, session):
    from app.models import Role, User, Venue, Vendor, ArtistProfile, Tournament, TournamentPlayer

    user_role = session.query(Role).filter_by(name='user').one()
    user = User(email='regular-venue@example.com', name='Regular Venue User', role=user_role)
    user.set_password('secret')
    venue = Venue(name='Public Venue', notes='Open play area')
    vendor = Vendor(name='Sleeve Seller', venue=venue, services_provided='Sleeves and deck boxes')
    artist = ArtistProfile(name='Token Artist', venue=venue, services_provided='Token sketches')
    tournament = Tournament(name='Venue Event', format='Constructed', venue=venue)
    session.add_all([user, venue, vendor, artist, tournament])
    session.flush()
    session.add(TournamentPlayer(tournament_id=tournament.id, user_id=user.id))
    session.commit()

    assert client.post('/login', data={'email': user.email, 'password': 'secret'}).status_code == 302

    home = client.get('/').get_data(as_text=True)
    assert 'data-dropdown-toggle aria-expanded="false">Admin</button>' not in home
    assert 'Registration Invites' not in home
    assert 'Site Settings' not in home

    assert client.get('/admin/site-settings').status_code == 403
    assert client.get('/admin/registration-invites').status_code == 403
    assert client.post('/admin/registration-invites', data={'email': 'invitee@example.com'}).status_code == 403
    assert client.get('/admin/venues/vendors').status_code == 403
    assert client.get('/admin/venues/artists').status_code == 403

    venue_page = client.get(f'/admin/venues/{venue.id}')
    assert venue_page.status_code == 200
    html = venue_page.get_data(as_text=True)
    assert 'Sleeve Seller' in html
    assert 'Sleeves and deck boxes' in html
    assert 'Token Artist' in html
    assert 'Token sketches' in html
    assert 'Vendor Management' not in html
    assert 'Artist Profiles' not in html
    assert 'Lost &amp; Found' not in html
    assert 'Bulk Add Tournaments' not in html
