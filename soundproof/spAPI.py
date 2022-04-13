from flask import Blueprint, jsonify
import time


spAPI = Blueprint('spAPI', __name__)

@spAPI.route("/servertime", methods=['GET'])
def servertime():
	return jsonify(time.time()*1000)
