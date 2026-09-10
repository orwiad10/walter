from app.app import TOURNAMENT_FORMATS
from app.models import DEFAULT_ROLE_PERMISSIONS, PERMISSION_GROUPS, Tournament, User


def test_old_school_formats_and_point_fields_are_configured():
    assert {
        'Old School - ATL',
        'Old School - EC',
        'Old School - SWE',
        'Old School - X-point',
    }.issubset(TOURNAMENT_FORMATS)
    assert 'old_school_point_value' in Tournament.__table__.columns


def test_hidden_user_permission_is_admin_only_by_default():
    assert 'view_hidden' in PERMISSION_GROUPS['users']
    assert DEFAULT_ROLE_PERMISSIONS['admin']['users.view_hidden'] is True
    assert all(
        not permissions.get('users.view_hidden', False)
        for role, permissions in DEFAULT_ROLE_PERMISSIONS.items()
        if role != 'admin'
    )
    assert 'hidden' in User.__table__.columns
