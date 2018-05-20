"""music_manager project"""

__author__ = 'Piotr Dyba'

from sqlalchemy import Column, Table
from sqlalchemy.types import Integer, String, Boolean
from main import db
import requests
from hashlib import md5
from datetime import datetime
from flask_login import UserMixin
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, ValidationError
from flask_wtf import FlaskForm


"""
Users Following database
"""
followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)


# UserMixin
class User(UserMixin, db.Model):
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
    about_me = db.Column(db.String(140))
    register_in = db.Column(db.DateTime, default=datetime.now)
    last_seen = db.Column(db.DateTime, default=datetime.now)
    ratings = db.relationship('Rating', backref='user')
    reviews = db.relationship('Review', backref='user')
    lists = db.relationship('List', backref='user')
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

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

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0

    def followed_review(self):
        followed = Review.query.join(
            followers, (followers.c.followed_id == Review.user_id)).filter(
                followers.c.follower_id == self.id)
        own = Review.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Review.timestamp.desc())


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
    year = Column(String(4), nullable=True)
    country = Column(String(100), nullable=True)
    genres = Column(String(255), nullable=True)
    styles = Column(String(255), nullable=True)
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

    # def save_rating(self, u_id, rate, rec_id, rev_id):
    #     r = Rating()
    #     r.user_id = u_id
    #     r.rate = rate
    #     r.record_id = rec_id
    #     r.review_id = rev_id
    #     db.session.add(r)
    #     db.session.commit()
    #
    # def get_avg_rat(self, rec_id):
    #     r = Rating.query.filter_by(record_id=rec_id).all()
    #     # r.rate
    #     r_sum = 0
    #     cnt = 0
    #     for i, v in enumerate(r):
    #         r_sum += v.rate
    #         cnt += 1
    #     return r_sum / cnt
    #     # pass


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
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    # def save_review(self, review, rec_id, usr_id):
    #     r = Review()
    #     r.record_id = rec_id
    #     r.user_id = usr_id
    #     r.review = review
    #
    #     pass
    #
    # def get_reviews(self, rec_id):
    #     r = Review.query.filter_by(record_id=rec_id).all()
    #     return r


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


class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    about_me = TextAreaField('About me', validators=[Length(min=0, max=140)])
    submit = SubmitField('Submit')

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=self.username.data).first()
            if user is not None:
                raise ValidationError("""
                Niestety ten login jest już zajęty. Proszę użyj innego.""")
