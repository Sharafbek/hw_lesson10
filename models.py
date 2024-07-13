from enum import Enum
from typing import Optional


class UserRole(Enum):
    ADMIN = 'admin'
    USER = 'user'


class UserStatus(Enum):
    ACTIVE = 'active'
    INACTIVE = 'inactive'
    BLOCK = 'block'


class TodoType(Enum):
    PERSONAL = 'personal'
    SHOPPING = 'shopping'


class User:
    def __init__(self,
                 username: str,
                 password: str,
                 role: UserRole,
                 status: UserStatus,
                 login_try_count: int):
        self.username = username
        self.password = password
        self.role = role or UserRole.USER.value
        self.status = status or UserStatus.INACTIVE.value
        self.login_try_count = login_try_count or 0


class Todo:
    def __init__(self,
                 name: str,

                 todo_type: TodoType,
                 user_id: int,
                 description: Optional[str] = None, ):
        self.name = name
        self.todo_type = todo_type or TodoType.PERSONAL.value
        self.user_id = user_id
        self.description = description
