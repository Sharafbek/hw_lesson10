from form import UserRegisterForm


def check_validation(form: UserRegisterForm):
    if not form.username:
        raise Exception('Username is required')
    if not form.password:
        raise Exception('Password is required')
