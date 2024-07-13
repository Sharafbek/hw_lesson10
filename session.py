from typing import Optional

from models import User


class Session:
    instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super(Session, cls).__new__(cls)

        return cls.instance

    def __init__(self, session: Optional[User] = None):
        self.session = session

    def add_session(self, user: User):
        self.session = user

    def check_session(self):
        return self.session
