from flask import Blueprint, jsonify
import time


spAPI = Blueprint('spAPI', __name__)

@spAPI.route("/servertime", methods=['GET'])
def servertime():
	return jsonify(time.time()*1000)


@spAPI.before_request
def before_request():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        code = 301
        return redirect(url, code=code)