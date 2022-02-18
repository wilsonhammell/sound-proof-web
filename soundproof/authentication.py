from flask import Blueprint, render_template, request, redirect
from flask_login import login_user, login_required, logout_user, current_user
from .models import register_account, login_account

authentication = Blueprint('authentication', __name__)

@authentication.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user, error_message = login_account(email, password)
        if user:
            login_user(user, remember=True)
            return redirect('/', code=303)
        else:
            return render_template('login.html', user=current_user, message=error_message)
    else:
        return render_template('login.html', user=current_user)

@authentication.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@authentication.route('/register', methods=['GET', 'POST'])
def register():
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
            return redirect('/login')
    else:
        return render_template('register.html', user=current_user)