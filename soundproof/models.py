from . import db
from flask_login import UserMixin
import re
import json

from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import base64

#The user table in the database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(64))
    #Random 32 character value used for 2FA enrollment, should be kept secret
    otp_secret = db.Column(db.String(32))
    
    #Stores the phones public key
    twofa_device_id= db.Column(db.String(512), default='')

    #Bool for if 2FA is enabled
    twofa_enabled = db.Column(db.Boolean, default=False)

    #Bool for if the account is sound_verified
    twofa_soundverified = db.Column(db.Boolean, default=False)

    #Bool for if the account is currently recording
    twofa_recording = db.Column(db.Boolean, default=False) 
    current_totp = db.Column(db.String(6), default='645852') #eventually randomly generate with token and time

    def __repr__(self):
        return '<User %r>' % self.email

#Function to register users
def register_account(name, email, password):
    #Check email format
    if not is_email(email):
        return False, "Email format is invalid"

    #Check if email is in use
    existed = User.query.filter_by(email=email).all()
    if len(existed) > 0:
        return False, "Email is already in use"

    #Check if username is in use
    existed = User.query.filter_by(username=name).all()
    if len(existed) > 0:
        return False, "Username is already in use"

    #Check if password is valid
    if not is_complex_password(password):
        return False, "Password does not meet requirements"

    #Check if username is valid
    if not is_proper_username(name):
        return False, "Username does not meet requirements"

    #Create a new user
    user = User(
        id=User.query.count(),
        email=email,
        username=name,
        password_hash=generate_password_hash(password, method='sha256'),
        otp_secret = secrets.token_hex(32)
    )
    #Add user to DB and commit
    #Might need mutexs here in case multiple db adjustments are being made
    db.session.add(user)
    db.session.commit()

    #Create a blank recording data file for the user
    temp = {'new' : 'true'}
    with open(f'soundproof/audio/recordings/{email}.json', 'w') as destination:
        json.dump(temp, destination)

    return True, None

#2FA activation function
def twofactoractivation(token, publickey):
    #Find the user will the corresponding enrollment token
    user = User.query.filter_by(otp_secret=token).first()

    #If a user exists, add the public key to their account and set 2fa flag to enabled
    if(user):
        prefix="-----BEGIN PUBLIC KEY-----"
        suffix="-----END PUBLIC KEY-----"
        pubKey=prefix+publickey+suffix

        user.twofa_device_id=pubKey
        user.twofa_enabled=True
        #Might need mutexs here in case multiple db adjustments are being made
        db.session.commit()
        return True
    return False

#Function to check if a user is recording
def is_user_recording(publickey):
    user = User.query.filter_by(twofa_device_id=publickey).first()
    if(user):
        return user.twofa_recording
    return False

#Two separate functions rather than a toggle for more control in case of error else where
#Function to flag a user as recording
def user_recording(email):
    #Finds user based on given email
    user = User.query.filter_by(email=email).first()

    #If a user exists flag them as recording
    if(user):
        user.twofa_recording = True
        db.session.commit()
        return True
    return False

#Function to flag a user as not recording
def user_recording_done(email):
    #Finds user based on given email
    user = User.query.filter_by(email=email).first()

    #If a user exists flag them as not recording
    if(user):
        user.twofa_recording = False
        db.session.commit()
        return True
    return False

#Function to check if a user has been sound_verfied
def sound_isverified(email):
    user = User.query.filter_by(email=email).first();
    if(user):
        return user.twofa_soundverified
    return False

#Two separate functions rather than a toggle for more control in case of error else where
#Functions to flag the user as sound_verified or not 
def sound_verified(publickey):
    user = User.query.filter_by(twofa_device_id=publickey).first()

    if(user):
        user.twofa_soundverified = True
        db.session.commit()
        return True
    return False

def sound_verified_reset(email):
    user = User.query.filter_by(email=email).first()

    if(user):
        user.twofa_soundverified = False
        db.session.commit()
        return True
    return False

#Function to return the public key associated with the user having the given email
def get_public_key(email):
    user = User.query.filter_by(email=email).first()
    if(user):
        return user.twofa_device_id
    return False

#Function to return the email of the user associated with the given public key
def get_user_email(publickey):
    user = User.query.filter_by(twofa_device_id=publickey).first()
    if(user):
        return user.email
    return False

#Function to validate a login attempt and return a user object
def login_account(email, password=None, totp=None, verifiedsound=False):
    if verifiedsound==False:
        if not is_email(email):
            return None, "Email entered doesn't match requirements"

        if not is_complex_password(password):
            return None, "Password entered doesn't match requirements"

    user = User.query.filter_by(email=email).first()
    if(user):
        if(verifiedsound):
            return user, None
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

#Function to check if password is valid
def is_complex_password(password):
    regex = r'[\s!\"#\$%&\'\(\)\*\+,-\./:;<=>\?@\[\]\^_`\{\|\}~]'
    if not bool(re.search(regex, password)):
        return False
    if not bool(re.search(r'[a-z]', password)):
        return False
    if not bool(re.search(r'[A-Z]', password)):
        return False
    return len(password) >= 6

#Function to check email format
def is_email(email):
    regex = (r'([!#-\'*+/-9=?A-Z^-~-]+(\.[!#-\'*+/-9=?A-Z^-~-]+)*|\'"([]!#-[^-'
             r'~\t]|(\\[\t -~]))+")@([!#-\'*+/-9=?A-Z^-~-]+(\.[!#-\'*+/-9=?'
             r'A-Z^-~-]+)*|\[[\t -Z^-~]*])')

    return bool(re.match(regex, email))

#Function to check username format
def is_proper_username(name):
    if len(name) < 3 or len(name) > 19:
        return False
    return bool(re.match(r'^[A-z0-9]+[A-z0-9 ]*[A-z0-9]+$', name))