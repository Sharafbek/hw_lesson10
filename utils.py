import hashlib


class Response:
    def __init__(self, data: str, status_code: int):
        self.data = data
        self.status_code = status_code


def hash_password(raw_password):
    return hashlib.sha256(raw_password.encode()).hexdigest()


def match_password(raw_password, encoded_password):
    return hash_password(raw_password) == encoded_password

