from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_qrcode import QRcode
from os import path

db = SQLAlchemy()
DB_NAME = "soundproof.db"

def launch_website():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dzk4NDFlZ2U0cmg5NjRlOTY4NGc5NjhKS2V3OGRyZnBuMnRydSt6ZGY0eTIrc3R5K2oyeTc4Mmo0WGIrdDR5dWorc3I0dDErajc0c0hKdCs0MXJldGErODk0MzJldzRjKzFhMmV3Njc4YTI='
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    app.config['PREFERRED_URL_SCHEME'] = 'https'
    db.init_app(app)

    from .views import views
    from .authentication import authentication
    from .spAPI import spAPI
    from .models import User

    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(authentication, url_prefix="/")
    app.register_blueprint(spAPI, url_prefix="/")

    if (not path.exists('soundproof/' + DB_NAME)):
        db.create_all(app=app)

    login_manager = LoginManager()
    login_manager.init_app(app)

    QRcode(app)

    @login_manager.unauthorized_handler
    def unauthorized():
        return redirect(url_for('authentication.login', _external=True, _scheme = 'https'))

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app