from flask import Blueprint, render_template, url_for, request
from flask_login import login_required, current_user
from datetime import datetime
import time
import os

views = Blueprint('views', __name__)

@views.route("/", methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        audio=request.files['file']
        file=datetime.now().strftime("%d%m%Y%H%M%S")
        with open(f'soundproof/audio/recordings/{file}.wav', 'wb') as destination:
            audio.save(destination)
        return render_template('home.html', user=current_user)

    else:
        return render_template('home.html', user=current_user, servertime=time.time())
