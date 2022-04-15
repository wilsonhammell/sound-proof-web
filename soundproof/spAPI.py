from flask import Blueprint, jsonify
import time


spAPI = Blueprint('spAPI', __name__)

#Route for server time
#Called by either the phone or the website 
@spAPI.route("/servertime", methods=['GET'])
def servertime():
	return jsonify(time.time()*1000)
