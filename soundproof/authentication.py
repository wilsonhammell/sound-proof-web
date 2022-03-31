from flask import Blueprint, render_template, request, redirect, url_for, session
from flask_login import login_user, login_required, logout_user, current_user
from .models import register_account, login_account, two_factor_activation, get_public_key
import copy
import time

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
            session['publickey'] = get_public_key(email)
            session['redirected'] = True
            return redirect(url_for('authentication.login_2fa_sound'))
        elif user:
            login_user(user, remember=True)
            return redirect(url_for('views.home', code=303))
        else:
            return render_template('login.html', user=current_user, message=error_message)
    else:
        return render_template('login.html', user=current_user)



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
            return render_template('twofa_login.html', user=current_user, message=error_message)
    else:
        return render_template('twofa_sound.html', user=current_user, pubic_key=get_public_key(email))

@authentication.route('/login/2fasound/<token>', methods=['GET', 'POST'])
def verificationpolling(token):
    pass



#leaving for testing in case, will be removed
#@authentication.route('/login/2fa', methods=['GET', 'POST'])
#def login_2fa(email=None, password=None, redirected=None):
#    if current_user.is_authenticated:
#        return redirect(url_for('views.home'))

#    try:
#        email=copy.deepcopy(session['email'])
#        password=copy.deepcopy(session['password'])
#        redirected=copy.deepcopy(session['redirected'])
#    except:
#        return redirect(url_for('views.home'))

#    if redirected==True:
#        session['redirected']=False
#    else:
#        session.pop('email')
#        session.pop('password')
#        session.pop('redirected')
#        if request.method == 'GET':
#            return redirect(url_for('views.home'))

#    if request.method == 'POST':
#        totp = request.form.get('totp_code')
#        user, error_message = login_account(email, password, totp)

#        if user:
#            login_user(user, remember=True)
#            return redirect(url_for('views.home', code=303))
#        else:
#            session['email'] = email
#            session['password'] = password
#            session['redirected'] = True
#            return render_template('twofa_login.html', user=current_user, message=error_message)
#    else:
#        return render_template('twofa_login.html', user=current_user)


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

        result = two_factor_activation(email=current_user.email, totp=totp)

        if not result:
            return render_template('twofa_register.html', user=current_user, message="Inputted code was incorrect")
        else:
            return render_template('twofa_register.html', user=current_user, message=error_message)
    else:
        return render_template('twofa_register.html', user=current_user)