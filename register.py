from db import cursor, conn, commit, init
from session import Session
from models import User, UserRole, UserStatus
from utils import Response, hash_password, match_password

session = Session()


@commit
def login(username: str, password: str):
    user: User | None = session.check_session()
    if user:
        return Response('You already logged in', 404)
    get_user_by_username = '''
    SELECT * FROM users WHERE username = %s;
    '''
    cursor.execute(get_user_by_username, (username,))
    user_data = cursor.fetchone()
    if not user_data:
        return Response('User not found', 404)
    user = User(username=user_data[1], password=user_data[2], role=user_data[3],
                status=user_data[4], login_try_count=user_data[5])
    if password != user_data[2]:
        update_user_query = '''
        UPDATE users SET login_try_count = login_try_count + 1 WHERE username = %s;
        '''
        cursor.execute(update_user_query, (username,))
        return Response('Wrong Password', 404)
    session.add_session(user)
    return Response('User successfully logged in', 200)


# response = login('Sharafbek', '7003')
#
# if response.status_code == 200:
#     print('True')
#
# else:
#     print('False')


@commit
def register(username: str, password: str, role: UserRole = UserRole.USER, status: UserStatus = UserStatus.ACTIVE):
    get_user_by_username = '''
    SELECT * FROM users WHERE username = %s;
    '''
    cursor.execute(get_user_by_username, (username,))
    user_data = cursor.fetchone()
    if user_data:
        return Response('Username already taken', 409)
    insert_user_query = '''
    INSERT INTO users(username, password, role, status, login_try_count)
    VALUES (%s,%s,%s,%s,%s);
    '''
    hashed_password = hash_password(password)
    cursor.execute(insert_user_query, (username, hashed_password, role.value, status.value, 0))
    return Response('This user is successfully registered', 201)


def main():
    while True:
        choice: str = input('Do you want to register or login? [register/login] ==> r/l: ')
        init()
        try:
            if choice in ['r' and 'l']:
                if choice == 'r':
                    response = register(input('Enter new username: '), input('Enter new password: '))
                    if response.status_code == 201:
                        return 'Successfully registered'
                    else:
                        return response.data
                if choice == 'l':
                    response = login(input('Enter username: '), input('Enter password: '))
                    if response.status_code == 200:
                        return 'Successfully logged in'
                    else:
                        return response.data
        except KeyboardInterrupt:
            return Response('User cancelled.')
