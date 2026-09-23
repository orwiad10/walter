from app.models import ArtistProfile, Role, User, Vendor, Venue


def _login_admin(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='venue-admin@example.com', name='Venue Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    session.add(admin)
    session.commit()
    response = client.post('/login', data={'email': admin.email, 'password': 'secret'})
    assert response.status_code == 302


def test_profiles_can_be_linked_to_multiple_venues(client, session):
    _login_admin(client, session)
    first = Venue(name='First Hall')
    second = Venue(name='Second Hall')
    session.add_all([first, second])
    session.commit()

    response = client.post('/admin/venues/vendors', data={
        'name': 'Traveling Vendor',
        'venue_ids': [str(first.id), str(second.id)],
    })
    assert response.status_code == 302
    vendor = session.query(Vendor).filter_by(name='Traveling Vendor').one()
    assert {venue.id for venue in vendor.venues} == {first.id, second.id}

    response = client.post('/admin/venues/artists', data={
        'name': 'Touring Artist',
        'venue_ids': [str(first.id), str(second.id)],
    })
    assert response.status_code == 302
    artist = session.query(ArtistProfile).filter_by(name='Touring Artist').one()
    assert {venue.id for venue in artist.venues} == {first.id, second.id}

    for venue in (first, second):
        detail = client.get(f'/admin/venues/{venue.id}')
        assert b'Traveling Vendor' in detail.data
        assert b'Touring Artist' in detail.data


def test_management_page_does_not_render_profiles(client, session):
    _login_admin(client, session)
    venue = Venue(name='Main Hall')
    venue.vendors.append(Vendor(name='Hidden Vendor'))
    venue.artists.append(ArtistProfile(name='Hidden Artist'))
    session.add(venue)
    session.commit()

    response = client.get('/admin/venues')
    assert response.status_code == 200
    assert b'Hidden Vendor' not in response.data
    assert b'Hidden Artist' not in response.data

    detail = client.get(f'/admin/venues/{venue.id}')
    assert b'Hidden Vendor' in detail.data
    assert b'Hidden Artist' in detail.data
