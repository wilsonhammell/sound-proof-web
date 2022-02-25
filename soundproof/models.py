from . import db
from flask_login import UserMixin
import re


from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import base64


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(64))
    otp_secret = db.Column(db.String(32))
    twofa_device_id= db.Column(db.String(32), default='')
    twofa_enabled = db.Column(db.Boolean, default=False)
    current_totp = db.Column(db.String(6), default='645852')

    def __repr__(self):
        return '<User %r>' % self.email

def register_account(name, email, password):
    if not is_email(email):
        return False, "Email format is invalid"

    existed = User.query.filter_by(email=email).all()
    if len(existed) > 0:
        return False, "Email is already in use"

    existed = User.query.filter_by(username=name).all()
    if len(existed) > 0:
        return False, "Username is already in use"

    if not is_complex_password(password):
        return False, "Password does not meet requirements"

    if not is_proper_username(name):
        return False, "Username does not meet requirements"

    user = User(
        id=User.query.count(),
        email=email,
        username=name,
        password_hash=generate_password_hash(password, method='sha256'),
        otp_secret = secrets.token_hex(32)
    )

    db.session.add(user)
    db.session.commit()

    return True, None


def two_factor_activation(email, totp):
    user = User.query.filter_by(email=email).first()
    user.twofa_enabled = not user.twofa_enabled
    db.session.commit()
    return True


def login_account(email, password, totp=None):
    if not is_email(email):
        return None, "Email entered doesn't match requirements"

    if not is_complex_password(password):
        return None, "Password entered doesn't match requirements"

    user = User.query.filter_by(email=email).first()
    if(user):
        if(check_password_hash(user.password_hash, password)):
            if(user.twofa_enabled):
                if(user.current_totp==totp):
                    return user, None
                elif(totp==None):
                    return 0, None
                else:
                    return None, "Incorrect code, please wait for the code to refresh and try again"
            else:
                return user, None
        else:
            return None, "Password is incorrect"
    return None, "No account exists with that email"


def is_complex_password(password):
    regex = r'[\s!\"#\$%&\'\(\)\*\+,-\./:;<=>\?@\[\]\^_`\{\|\}~]'
    if not bool(re.search(regex, password)):
        return False
    if not bool(re.search(r'[a-z]', password)):
        return False
    if not bool(re.search(r'[A-Z]', password)):
        return False
    return len(password) >= 6


def is_email(email):
    regex = (r'([!#-\'*+/-9=?A-Z^-~-]+(\.[!#-\'*+/-9=?A-Z^-~-]+)*|\'"([]!#-[^-'
             r'~\t]|(\\[\t -~]))+")@([!#-\'*+/-9=?A-Z^-~-]+(\.[!#-\'*+/-9=?'
             r'A-Z^-~-]+)*|\[[\t -Z^-~]*])')

    return bool(re.match(regex, email))


def is_proper_username(name):
    if len(name) < 3 or len(name) > 19:
        return False
    return bool(re.match(r'^[A-z0-9]+[A-z0-9 ]*[A-z0-9]+$', name))