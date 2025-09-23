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
