"""music_manager project"""

__author__ = 'Piotr Dyba'

from os import path
from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'
db = SQLAlchemy()
db.app = app
db.init_app(app)
lm = LoginManager()
lm.init_app(app)
bcrypt = Bcrypt()
lm.login_view = 'login'

app.static_path = path.join(path.abspath(__file__), 'static')


if __name__ == '__main__':
    from views import *
    app.run(host='0.0.0.0', port=5000, debug=True)
