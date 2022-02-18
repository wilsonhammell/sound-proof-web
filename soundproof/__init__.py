from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from os import path

db = SQLAlchemy()
DB_NAME = "soundproof.db"

def launch_website():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'm78hn3g8m6mg5f46g4869m3uigy40m'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    from .views import views
    from .authentication import authentication
    from .models import User

    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(authentication, url_prefix="/")

    if (not path.exists('soundproof/' + DB_NAME)):
        db.create_all(app=app)

    login_manager = LoginManager()
    login_manager.login_view = 'authentication.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app