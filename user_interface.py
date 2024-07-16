import register
from db import init
from colorama import Fore
from utils import Response
from form import UserRegisterForm


def print_response(response: Response):
    color = Fore.GREEN if response.status_code == 200 else Fore.RED
    print(color + response.data + Fore.RESET)


def login_page():
    username = input('Enter your username: ')
    password = input('Enter your password: ')
    response = register.login(username, password)
    print_response(response)


def register_page():
    username = input('Enter your username: ')
    password = input('Enter your password: ')
    form = UserRegisterForm(username, password)
    response = register.register(form)
    print_response(response)


def logout_page():
    response = register.logout()
    print_response(response)


def add_todo():
    name = input('Enter name: ')
    description = input('Enter description: ')
    response = register.todo_add(name, description)
    print_response(response)


def update_todo():
    user_id = int(input('Enter ID for todo update: '))
    name = input('Enter name: ')
    description = input('Enter description: ')
    response = register.todo_update(user_id, name, description)
    print_response(response)


def delete_todo():
    todo_id = int(input('Enter ID for todo delete: '))
    response = register.todo_delete(todo_id)
    print_response(response)


def block_user():
    username = input('Enter username to block: ')
    response = register.block_user(username)
    print_response(response)


def main():
    while True:
        print("This is menu:"
              "\nLogin => 1"
              "\nRegister => 2"
              "\nLogout => 3"
              "\nAdd Todo => 4"
              "\nUpdate Todo => 5"
              "\nDelete Todo => 6"
              "\nBlock User => 7"
              "\nQuit=> q")

        init()
        try:
            choice: str = input('Enter your choice: ')
            if choice == '1':
                login_page()
            elif choice == '2':
                register_page()
            elif choice == '3':
                logout_page()
            elif choice == '4':
                add_todo()
            elif choice == '5':
                update_todo()
            elif choice == '6':
                delete_todo()
            elif choice == '7':
                block_user()
            elif choice == 'q':
                break
        except KeyboardInterrupt:
            print("User cancelled.")
