from flask import Blueprint, render_template, url_for, request
from flask_login import login_required, current_user
from datetime import datetime

views = Blueprint('views', __name__)

@views.route("/", methods=['GET', 'POST'])
@login_required
def home():
     return render_template('home.html', user=current_user)

@views.before_request
def before_request():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)
