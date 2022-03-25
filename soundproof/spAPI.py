from flask import Blueprint, render_template, url_for, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime
import time
import os

spAPI = Blueprint('spAPI', __name__)

@spAPI.route("/servertime", methods=['GET'])
@login_required
def servertime():
	return jsonify(time.time()*1000)
