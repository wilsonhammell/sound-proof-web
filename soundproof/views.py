from flask import Blueprint, render_template, url_for, request
from flask_login import login_required, current_user
from datetime import datetime

views = Blueprint('views', __name__)

#The route for the home page
#Login is required, if logged in render the template
@views.route("/", methods=['GET', 'POST'])
@login_required
def home():
     return render_template('home.html', user=current_user)
