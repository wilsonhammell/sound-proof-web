from flask import Blueprint, jsonify
import time


spAPI = Blueprint('spAPI', __name__)

@spAPI.route("/servertime", methods=['GET'])
def servertime():
	polling_end = time.time() + 20
	while(time.time()<polling_end):
		time.sleep(1)
	return jsonify(time.time()*1000)
