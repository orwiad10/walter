from nicegui import ui
import requests

API_URL = 'http://localhost:5000'

@ui.page('/')
def index_page() -> None:
    """Landing page showing basic navigation using NiceGUI components."""
    with ui.header().classes('items-center justify-between'):
        ui.label('MTG Tournament App').classes('text-h5')
    with ui.column().classes('p-4 gap-2'):
        ui.button('Login', on_click=lambda: ui.open('/login'))
        ui.button('Register', on_click=lambda: ui.open('/register'))

@ui.page('/login')
def login_page() -> None:
    """Simple login form backed by the existing Flask endpoint."""
    email = ui.input('Email')
    password = ui.input('Password', password=True, password_toggle_button=True)

    def do_login() -> None:
        requests.post(f'{API_URL}/login', data={'email': email.value, 'password': password.value})
        ui.open('/')

    ui.button('Login', on_click=do_login)

@ui.page('/register')
def register_page() -> None:
    """Registration form that posts to the backend without using HTML templates."""
    email = ui.input('Email')
    name = ui.input('Name')
    password = ui.input('Password', password=True, password_toggle_button=True)

    def do_register() -> None:
        requests.post(
            f'{API_URL}/register',
            data={'email': email.value, 'name': name.value, 'password': password.value},
        )
        ui.open('/login')

    ui.button('Register', on_click=do_register)


def run() -> None:
    """Run the NiceGUI frontend application."""
    ui.run()


if __name__ == '__main__':
    run()
