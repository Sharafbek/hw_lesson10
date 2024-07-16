from db import cursor, conn, commit, is_authenticated
from session import Session
from typing import Optional
from models import User, UserRole, UserStatus, TodoType
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

def logout():
    global session
    if session:
        session.session = None
        return Response('Successfully logged out', status_code=200)
    return Response('Session Not Found', status_code=404)


@is_authenticated
@commit
def todo_add(name: str, description: Optional[str] = None):
    insert_todo = """
        insert into todo(name,description,todo_type,user_id)
        values (%s,%s,%s,%s)
    """
    cursor.execute(insert_todo, (name, description, TodoType.PERSONAL.value, session.session.id))
    return Response('Successfully inserted todo', status_code=200)


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


def logout():
    global session
    if session:
        session.session = None
        return Response('Successfully logged out', status_code=200)
    return Response('Session Not Found', status_code=404)


@is_authenticated
def get_all_data():
    data = []
    get_all_data_query = '''SELECT id, name FROM todo WHERE user_id = %s;'''
    cursor.execute(get_all_data_query, (session.session.id,))
    data_list = cursor.fetchall()
    if not data_list:
        return Response('Data is\'n this table', 404)
    for todo in data_list:
        data.append(todo)
    return data


@is_authenticated
@commit
def data_add(name: str, description: Optional[str] = None):
    insert_data_query = """
        INSERT INTO todo(name,description,todo_type,user_id)
        VALUES (%s,%s,%s,%s)
    """
    cursor.execute(insert_data_query, (name, description, TodoType.PERSONAL.value, session.session.id))
    return Response('Successfully insert data', status_code=200)


@commit
def todo_update(name: str, todo_id: int, description: Optional[str] = None):
    result = get_all_data()
    for todo in result:
        if todo_id in str(todo):
            update_data_query = '''UPDATE todo SET name = %s, 
                                    description = %s WHERE id = %s;'''
            cursor.execute(update_data_query, (name, description, todo_id))
            return Response('Successfully update', 200)
    return Response(f'This id: {todo_id} is not found.', 404)


@commit
def todo_delete(todo_id: str):
    result = get_all_data()
    for todo in result:
        if todo_id in str(todo):
            delete_data_query = '''DELETE FROM todo WHERE id = %s;'''
            cursor.execute(delete_data_query, (todo_id,))
            return Response('Successfully deleted', 200)
    return Response(f'This id: {todo_id} is not found.', 404)

#
# def main():
#     while True:
#         choice: str = input('Do you want to register or login? [register/login] ==> r/l: ')
#         init()
#         try:
#             if choice in ['r' and 'l']:
#                 if choice == 'r':
#                     response = register(input('Enter new username: '), input('Enter new password: '))
#                     if response.status_code == 201:
#                         return 'Successfully registered'
#                     else:
#                         return response.data
#                 if choice == 'l':
#                     response = login(input('Enter username: '), input('Enter password: '))
#                     if response.status_code == 200:
#                         return 'Successfully logged in'
#                     else:
#                         return response.data
#         except KeyboardInterrupt:
#             return Response('User cancelled.')
