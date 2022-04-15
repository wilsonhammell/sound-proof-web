from flask import Blueprint, render_template, request, redirect, url_for, session, send_file
from flask_login import login_user, login_required, logout_user, current_user
from .models import register_account, login_account, get_public_key, twofactoractivation, is_user_recording, user_recording, user_recording_done, get_user_email, sound_isverified, sound_verified, sound_verified_reset
from datetime import datetime
import time
import copy
import os
import json

authentication = Blueprint('authentication', __name__)

#Login route
#If user is authenticated redirect
#If its a GET request, render the page
#If its a post request, handle the login attempt
@authentication.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('views.home', _external=True, _scheme = 'https'))

    if request.method == 'POST':
        #Collect inputs
        email = request.form.get('email')
        password = request.form.get('password')
        #attempt login
        user, error_message = login_account(email, password)
        #if user==0 then the account has 2fa enabled, save relevant session data, set the account to recording and redirect to 2fa recording page
        if user==0:
            session['email'] = email
            session['password'] = password
            session['redirected'] = True
            user_recording(email)
            return redirect(url_for('authentication.login_2fa_sound', _external=True, _scheme = 'https'))
        #if a user object is returned login the user and redirect to home
        elif user:
            login_user(user, remember=True)
            return redirect(url_for('views.home', code=303, _external=True, _scheme = 'https'))
        #else the login details were incorrect, redirect back to login
        else:
            return render_template('login.html', user=current_user, message=error_message)
    else:
        return render_template('login.html', user=current_user, _external=True, _scheme = 'https')


#2FA enrollment route for the app to call
#The phone must include it's public key and the enrollment token for the account
@authentication.route('/tokenenrollment', methods=['POST'])
def token_enrollment():
    if request.method == 'POST':
        #load request data
        enrollment_data = json.loads(request.data)
        token = enrollment_data['token']
        public_key = enrollment_data['key']

        #attempt 2fa enrollment
        if(twofactoractivation(token,public_key)):
            return ('success', 200)
    return ('', 400)

#The 2FA login page, rediected here after succesful login if 2FA is enabled for the account
#Redirected flag tracks whether of not the user is on the page due to a redirect, used for redirects and to stop invalid access or page refreshes
@authentication.route('/login/2fasound', methods=['GET', 'POST'])
def login_2fa_sound(email=None, password=None, redirected=None):
    #Rediects if user is authenticated
    if current_user.is_authenticated:
        return redirect(url_for('views.home', _external=True, _scheme = 'https'))

    #Attempts to gather session data, if there is none that means they never a login or refreshed the page and should be redirected
    try:
        email=copy.deepcopy(session['email'])
        password=copy.deepcopy(session['password'])
        redirected=copy.deepcopy(session['redirected'])
    except:
        return redirect(url_for('views.home', _external=True, _scheme = 'https'))

    #If the user was redirected here, toggle off the redirected flag so refreshing will redirect away
    #Session is cleared if there was no redirect
    if redirected==True:
        session['redirected']=False
    else:
        session.pop('email')
        session.pop('password')
        session.pop('redirected')
        if request.method == 'GET':
            return redirect(url_for('views.home', _external=True, _scheme = 'https'))

    #This block is for TOTP input, currently the app doesn't generate codes so this section will never be called as there is no code to use
    if request.method == 'POST':
        totp = request.form.get('totp_code')
        user, error_message = login_account(email, password, totp)

        if user:
            login_user(user, remember=True)
            return redirect(url_for('views.home', code=303, _external=True, _scheme = 'https'))
        else:
            session['email'] = email
            session['password'] = password
            session['redirected'] = True
            user_recording(email)
            return render_template('twofa_sound.html', user=current_user, message=error_message)
    else:
        #Render the page and flag the user as recording
        user_recording(email)
        return render_template('twofa_sound.html', user=current_user, pubic_key=get_public_key(email), email=email)


#The route for record polling, called by the phone to see if their linked user is currently recording
@authentication.route('/login/2farecordpolling', methods=['POST'])
def login_2fa_polling():
    if current_user.is_authenticated:
        return

    #The phone sends a json containing their public key
    if request.method == 'POST':
        enrollment_data = json.loads(request.data)
        key = enrollment_data['key']

        #Long polling
        #For the next 25 seconds the server will check every second if the user is recording and will immediately inform the phone is the user starts recording 
        polling_end = time.time() + 25
        while(time.time()<polling_end):
            #Check the account associated with the provided key, if the accounts recording flag is set return a 200 to the phone, informing it to record
            if(is_user_recording(key)):
                return('record',200)
            time.sleep(1)#May need to be reduced or outright removed to tighten timings for audio comparison
        #After 25 seconds inform the phone that the user is not currently recording by returning a 204
        #upon recieving this the phone will then call this route again to ensure that the phone will be immediately informed when recording starts
        return('poll again', 204)
    return('bad request', 417)


#The route called by the phone to gather recording data
#Called by the phone after being told to record
@authentication.route('/login/2farecordingdata', methods=['POST'])
def login_2fa_data():
    if current_user.is_authenticated:
        return

    #The phone sends a json containing their public key
    if request.method == 'POST':
        data = json.loads(request.data)
        key = data['key']

        #Check the email corresponding to the public key, will be a string if a corresponding email exists, otherwise it will be False
        email = get_user_email(key)
        
        #If email is false then account doesnt exist
        if(email!=False):
            #Two different file path strings pointing to the same file, due to different method functionality between send_file and isfile
            path=f'soundproof/audio/recordings/{email}.json'
            path2=f'audio/recordings/{email}.json'
            #If the file exists start long polling for 20 seconds
            if(os.path.isfile(path)):
                polling_end = time.time() + 20
                while(time.time()<polling_end):
                    #Check if the file is recent
                    if(is_recent(path)):
                        #If recording is recent send the file to the phone
                        return send_file(path2), 200
                    time.sleep(1)
                #If polling completes and the recording data file was never recent, return a 204 to the phone informing of this issue
                #this should return the phone to a record polling state
                return('not recent', 204) 
        #If this is reached either the user or the recording data file didnt exist
        return('no file/user', 503) 
    return('bad request', 417)

#Check a file path to see if the file has been modified in the last 5 seconds, if so return true, else false
def is_recent(path):
    if(abs(os.path.getmtime(path)-time.time())<=5):
        return True
    return False

#possibly terrible
#it just verifies the account for login on the server, no login session token, needs adjustments
#The route to recieve the phones verdict on whether or not the audio is from the same location
@authentication.route('/login/2faresponse', methods=['POST'])
def login_2fa_response():
    if current_user.is_authenticated:
        return

    #Recieves the public key and the verdict from the phone
    if request.method == 'POST':
        data = json.loads(request.data)
        valid = data['valid']
        key = data['key']

        #If the phone returned true, temporarily set the sound_verified flag for the account associated with the key
        if(valid=="true"):
            if(sound_verified(key)):
                #Inform the phone of the succes
                return('',200)
            #An error occured in the process, E.G. invalid public key was in the request
            return('', 204)
    #A bad request
    return('', 417)

#The upload audio route called by the browser
@authentication.route("/uploadaudio", methods=['POST'])
def uploadaudio():
    if request.method == 'POST':
        #Recieve the recording data and update the users recording data json with the new information
        recording_data = json.loads(request.data)
        email = request.headers.get('email')
        file=email
        with open(f'soundproof/audio/recordings/{file}.json', 'w') as destination:
            json.dump(recording_data, destination)
        
        #Toggle off the users recording flag as they are done recording
        user_recording_done(email)
        #Begin long polling the server for 20 seconds, awaiting a response from the phone
        polling_end = time.time() + 20
        while(time.time()<polling_end):
            #Check if the users sound_verified flag is set, if so allow them to login and turn off their sound_verified flag before redirecting them home
            if(sound_isverified(email)):
                user, error_message = login_account(email, verifiedsound=True)
                login_user(user, remember=True)
                sound_verified_reset(email)
                return (url_for('views.home', _external=True, _scheme = 'https'), 201)
            time.sleep(1)
    return ('', 400)

#Logout route
#Logs the current user out and redirects the user to login
@authentication.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('authentication.login', _external=True, _scheme = 'https'))

#Registration route
@authentication.route('/register', methods=['GET', 'POST'])
def register():
    #Redirect is user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('views.home', _external=True, _scheme = 'https'))

    if request.method == 'POST':
        #Gather registration inputs
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password2 = request.form.get('password2')
        error_message = None

        #Initial input validation
        if password != password2:
            error_message = "Passwords do not match"
        else:
            #Attempt registration
            success, error_message = register_account(username, email, password)
        #If there was an error in registration, return to registration page with error message
        if error_message:
            return render_template('register.html', user=current_user, message=error_message)
        #Else registration was a success, redirect to login page
        else:
            return redirect(url_for('authentication.login', _external=True, _scheme = 'https'))
    else:
        #Render template
        return render_template('register.html', user=current_user)

#A route for the user to call
#Displays their 2FA information for registration
@authentication.route("/twofa_register", methods=['GET'])
@login_required
def twofa_register():
    return render_template('twofa_register.html', user=current_user)
