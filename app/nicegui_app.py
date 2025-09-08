"""NiceGUI interface for the MTG Tournament app.

This module provides a lightweight user interface built with
[nicegui](https://nicegui.io/) while reusing the existing Flask backend.
It does not modify or replace the backend logic; instead it queries the
same database models to present data to the user.
"""

from nicegui import ui
from .app import create_app, db
from .models import Tournament

# Reuse the existing Flask application and database configuration
flask_app = create_app()


@ui.page('/nice')
def tournament_page() -> None:
    """Show a list of tournaments using a simple NiceGUI page."""
    with flask_app.app_context():
        tournaments = (
            db.session.query(Tournament)
            .order_by(Tournament.created_at.desc())
            .all()
        )

    ui.label('Tournaments').classes('text-2xl m-4')
    for t in tournaments:
        with ui.card().classes('m-4 p-4'):
            ui.label(t.name).classes('text-lg')
            ui.label(f'{len(t.players)} players')


def run() -> None:
    """Start the NiceGUI interface."""
    ui.run()


if __name__ == '__main__':
    run()
