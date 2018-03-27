"""music_manager project"""

__author__ = 'Piotr Dyba'

from sqlalchemy import Column, Table
from sqlalchemy.types import Integer, String, Boolean
from main import db
import requests


# UserMixin
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
    ratings = db.relationship('Rating', backref='user')
    reviews = db.relationship('Review', backref='user')
    lists = db.relationship('List', backref='user')

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


record_list = db.Table('record_list', db.metadata,
    Column('record_id', Integer, db.ForeignKey('record.id')),
    Column('list_id', Integer, db.ForeignKey('list.id'))
)


class Record(db.Model):
    """
    Record model for reviewers.
    """
    __tablename__ = 'record'
    id = Column(Integer, autoincrement=True, primary_key=True)
    title = Column(String(200), nullable=False)
    artist = Column(String(200), nullable=False)
    ratings = db.relationship('Rating', backref='record')
    reviews = db.relationship('Review', backref='record')

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
        result = {
            'error': ''
        }
        response = requests.get(url, params=params)
        try:
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
        try:
            data = response.json().get('results')[0]
            details = requests.get(data.get('resource_url')).json()
            data.update(details)
            if data:
                result = data
            else:
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
        finally:
            return result


class List(db.Model):
    """
    List model.
    """
    __tablename__ = 'list'
    id = Column(Integer, autoincrement=True, primary_key=True)
    title = Column(String(200), nullable=False)
    # 0 - public, 1 - private, 2 - friends
    type = Column(Integer, nullable=False)
    user_id = Column(Integer, db.ForeignKey('user.id'), nullable=False)
    records = db.relationship("Record", secondary=record_list)


class Rating(db.Model):
    """
    Rating model.
    """
    __tablename__ = 'rating'
    id = Column(Integer, autoincrement=True, primary_key=True)
    rate = Column(Integer, nullable=False)
    user_id = Column(Integer, db.ForeignKey('user.id'), nullable=False)
    record_id = Column(Integer, db.ForeignKey('record.id'), nullable=True)
    review_id = Column(Integer, db.ForeignKey('review.id'), nullable=True)


class Review(db.Model):
    """
    Review model.
    """
    __tablename__ = 'review'
    id = Column(Integer, autoincrement=True, primary_key=True)
    review = Column(String(255))
    user_id = Column(Integer, db.ForeignKey('user.id'), nullable=False)
    record_id = Column(Integer, db.ForeignKey('record.id'), nullable=False)
    ratings = db.relationship('Rating', backref='review')


class Friend(db.Model):
    """
    Friend model.
    """
    __tablename__ = 'friend'
    id = Column(Integer, autoincrement=True, primary_key=True)
    user_id = Column(Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = Column(Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship("User", foreign_keys=[user_id])
    friend = db.relationship("User", foreign_keys=[friend_id])


