from flask import Blueprint, render_template, request, redirect, url_for, session
from flask_login import login_user, login_required, logout_user, current_user
from .models import register_account, login_account, get_public_key, twofactoractivation, is_user_recording, user_recording, user_recording_done, get_user_email
from datetime import datetime
import time
import copy
import os
import json

authentication = Blueprint('authentication', __name__)

@authentication.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('views.home'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user, error_message = login_account(email, password)
        if user==0:
            session['email'] = email
            session['password'] = password
            session['redirected'] = True
            user_recording(email)
            return redirect(url_for('authentication.login_2fa_sound'))
        elif user:
            login_user(user, remember=True)
            return redirect(url_for('views.home', code=303))
        else:
            return render_template('login.html', user=current_user, message=error_message)
    else:
        return render_template('login.html', user=current_user)


@authentication.route('/tokenenrollment', methods=['POST'])
def token_enrollment():
    if request.method == 'POST':
        enrollment_data = json.loads(request.data)
        token = enrollment_data['token']
        public_key = enrollment_data['key']
        if(twofactoractivation(token,public_key)):
            return ('success', 200)
        else:
            return ('', 400)
    return ('', 400)

@authentication.route('/login/2fasound', methods=['GET', 'POST'])
def login_2fa_sound(email=None, password=None, redirected=None):
    if current_user.is_authenticated:
        return redirect(url_for('views.home'))

    try:
        email=copy.deepcopy(session['email'])
        password=copy.deepcopy(session['password'])
        redirected=copy.deepcopy(session['redirected'])
    except:
        return redirect(url_for('views.home'))

    if redirected==True:
        session['redirected']=False
    else:
        session.pop('email')
        session.pop('password')
        session.pop('redirected')
        if request.method == 'GET':
            return redirect(url_for('views.home'))

    if request.method == 'POST':
        totp = request.form.get('totp_code')
        user, error_message = login_account(email, password, totp)

        if user:
            login_user(user, remember=True)
            return redirect(url_for('views.home', code=303))
        else:
            session['email'] = email
            session['password'] = password
            session['redirected'] = True
            #maybe send a request from the browser just prior to recording, this is probably fine tho
            user_recording(email)
            return render_template('twofa_sound.html', user=current_user, message=error_message)
    else:
        user_recording(email)
        return render_template('twofa_sound.html', user=current_user, pubic_key=get_public_key(email), email=email)


#phone app calls this regularly, will get a response saying either to record or not, times out every 20 seconds
#if the account with given pub key says recording, return response to phone informing them to start recording
@authentication.route('/login/2farecordpolling', methods=['GET'])
def login_2fa_polling():
    if current_user.is_authenticated:
        return
    
    data = json.loads(request.data)
    key = data['key']

    polling_end = time.time() + 20
    while(time.time()<polling_end):
        if(is_user_recording(key)):
            return('record',200)
    return('', 204)


#long poll this function from app with pub key
#retrieves the recording for the given user, if it exists and if its recently recorded
#maybe set recording to false from here rather than in the uploadaudio function, will see 
@authentication.route('/login/2farecordingdata', method=['GET'])
def login_2fa_data():
    if current_user.is_authenticated:
        return

    data = json.loads(request.data)
    key = data['key']

    email = get_user_email(key)
    path=f'soundproof/audio/recordings/{email}.json'
    if(os.path.isfile(path)):
        polling_end = time.time() + 20
        while(time.time()<polling_end):
            if(is_recent(path)):
                return send_file(path)
    return('', 503) 

def is_recent(path):
    if(abs(os.path.getmtime(path)-time.time())<=3):
        return True
    return False#change this back

#possibly terrible
#it just verifies the account for login on the server, no login session token, needs adjustments
@authentication.route('/login/2faresponse', methods=['POST'])
def login_2fa_response():
    if current_user.is_authenticated:
        return

    data = json.loads(request.data)
    valid = data['valid']
    key = data['key']

    if(valid=="true"):
        sound_verified(key)
    return('',200)

#not finished, needs to recieve response from phone
@authentication.route("/uploadaudio", methods=['POST'])
def uploadaudio():
    if request.method == 'POST':
        recording_data = json.loads(request.data)
        email = request.headers.get('email')
        file=email
        with open(f'soundproof/audio/recordings/{file}.json', 'w') as destination:
            json.dump(recording_data, destination)
        
        user_recording_done(email)
        polling_end = time.time() + 20
        while(time.time()<polling_end):
            if(sound_isverified(email)):
                user, error_message = login_account(email, verifiedsound=True)
                login_user(user, remember=True)
                sound_verified_reset(email)
                return (url_for('views.home'), 201)
        return ('', 400) 
    return ('', 400)


@authentication.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('authentication.login'))


@authentication.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('views.home'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        error_message = None

        if password != password2:
            error_message = "Passwords do not match"
        else:
            success, error_message = register_account(username, email, password)
        if error_message:
            return render_template('register.html', user=current_user, message=error_message)
        else:
            return redirect(url_for('authentication.login'))
    else:
        return render_template('register.html', user=current_user)


@authentication.route("/twofa_register", methods=['GET', 'POST'])
@login_required
def twofa_register():
    if request.method == 'POST':
        totp = request.form.get("totp_code")
        error_message = ""

        if not result:
            return render_template('twofa_register.html', user=current_user, message="Inputted code was incorrect")
        else:
            return render_template('twofa_register.html', user=current_user, message=error_message)
    else:
        return render_template('twofa_register.html', user=current_user)