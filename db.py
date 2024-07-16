import psycopg2
from models import UserRole, UserStatus
from session import Session
from utils import Response

data_case = {
    'database': 'todo_project',
    'user': 'postgres',
    'password': '1234',
    'host': 'localhost',
    'port': 5432
}

conn = psycopg2.connect(**data_case)
cursor = conn.cursor()

create_user_query = """CREATE TABLE IF NOT EXISTS users(
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(255) NOT NULL,
                        password VARCHAR(64) NOT NULL,
                        "role" VARCHAR(85) NOT NULL,
                        status VARCHAR(50) NOT NULL ,
                        login_try_count INTEGER NOT NULL DEFAULT 0,
                        UNIQUE (username)
                    );
                    """

create_todo_query = """CREATE TABLE IF NOT EXISTS todo(
                        id SERIAL PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        description VARCHAR(255),
                        todo_type VARCHAR(50) NOT NULL,
                        user_id INT NOT NULL REFERENCES users(id)
                    );
                    """


def create_table():
    cursor.execute(create_user_query)
    cursor.execute(create_todo_query)


def migrate():
    insert_admin_user_query = """
                                INSERT INTO users(username, password, role, status, login_try_count)
                                VALUES (%s,%s,%s,%s,%s);
                                """
    user_data = ('Sharafbek', '7003', UserRole.ADMIN.value, UserStatus.ACTIVE.value, 0)
    cursor.execute(insert_admin_user_query, user_data)
    conn.commit()


def init():
    create_table()
    migrate()


def commit(func):
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        conn.commit()
        return result

    return wrapper


session = Session()


def is_authenticated(func):
    def wrapper(*args, **kwargs):
        if not session.session:
            return Response('Not authenticated', status_code=404)
        result = func(*args, **kwargs)
        return result

    return wrapper
