"""music_manager project"""

__author__ = 'Piotr Dyba'

from sqlalchemy import Column
from sqlalchemy.types import Integer
from sqlalchemy.types import String
from sqlalchemy.types import Boolean
from main import db
import requests


#UserMixin
class User(db.Model):
    """
    User model for reviewers.
    """
    __tablename__ = 'user'
    id = Column(Integer, autoincrement=True, primary_key=True)
    active = Column(Boolean, default=True)
    username = Column(String(200), unique=True)
    email = Column(String(200), unique=True)
    password = Column(String(200), default='')
    admin = Column(Boolean, default=False)
    poweruser = Column(Boolean, default=False)

    def is_active(self):
        """
        Returns if user is active.
        """
        return self.active

    def is_admin(self):
        """
        Returns if user is admin.
        """
        return self.admin


class Record(db.Model):
    """
    Record model for reviewers.
    """
    __tablename__ = 'record'
    id = Column(Integer, autoincrement=True, primary_key=True)
    title = Column(String(200), nullable=False)
    artist = Column(String(200), nullable=False)
    rating = Column(Integer, default=0)

    def get_additional(self):
        url = 'https://api.discogs.com/database/search'
        params = {
            'key': 'WONRKpdcLceTWCxtHfqR',
            'secret': 'MSisOyhqhqTfbmEaJMdSfcjbkobsfHPD',
            'q': self.title,
            'release_title': self.title,
            'artist': self.artist,
            'type': 'master'
        }
        data = requests.get(url, params=params).json().get('results')[0]
        details = requests.get(data.get('resource_url')).json()
        data.update(details)
        return data