from flask import Blueprint, render_template, url_for, request, jsonify
from flask_login import login_required, current_user
from datetime import datetime
import json
import time
import os

spAPI = Blueprint('spAPI', __name__)

@spAPI.route("/servertime", methods=['GET'])
def servertime():
	return jsonify(time.time()*1000)

@spAPI.route("/uploadaudio", methods=['POST'])
def uploadaudio():
    if request.method == 'POST':
        recording_data = json.loads(request.data)
        file=datetime.now().strftime("%d%m%Y%H%M%S")
        with open(f'soundproof/audio/recordings/{file}.json', 'w') as destination:
            json.dump(recording_data, destination)
        return ('', 204) 
    return ('', 400)


