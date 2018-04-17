"""music_manager project"""

from flask import url_for, render_template, request, redirect, session, flash
from main import app, db, bcrypt, lm
from models import User, Record, Review, Rating, EditProfileForm # KZ
from sqlalchemy import func
from flask_login import current_user, login_required, login_user, logout_user
from datetime import datetime

app.secret_key = 'some_secret'


class ServerError(Exception):
    """wyjątek zostanie zwrócony, gdy cokolwiek będzie nieprawidłowe"""
    pass


@app.route('/', methods=['GET', 'POST'])
def info():
    return render_template('info.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        username_form = request.form.get('username')
        password_form = request.form.get('password')

        try:
            szukany_uzytkownik = User.query.filter_by(username=username_form).first()
        except ServerError as err:
            error = str(err)
            return render_template('login.html', error=error)

        if szukany_uzytkownik is None:
            error = "Zły login lub hasło!"
            return render_template('login.html', error=error)

        if not bcrypt.check_password_hash(szukany_uzytkownik.password, password_form):
            error = "Zły login lub hasło!"
            return render_template('login.html', error=error)

        session['username'] = username_form
        login_user(szukany_uzytkownik)
        return redirect('/profile')
    return render_template('login.html')


@app.route('/profile', methods=['GET'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html', tekst="witamy ")


@app.route('/logout')
def logout():
    session.pop('username', None)
    logout_user()
    return redirect(url_for('info'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    error_register = None

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
        new_password_verify = request.form.get('password_verify')

        new_email = request.form.get('email')

        try:
            sprawdzanie_uzytkownika_login = User.query.filter_by(username=new_username).first()
            if sprawdzanie_uzytkownika_login is not None:
                error_register = "Podany login już istnieje"
                return render_template('register.html', error_register=error_register)

            sprawdzanie_uzytkownika_email = User.query.filter_by(email=new_email).first()
            if sprawdzanie_uzytkownika_email is not None:
                error_register = "Podany przez Ciebie adres e-mail już istnieje"
                return render_template('register.html', error_register=error_register)

            if not bcrypt.check_password_hash(new_password, new_password_verify):
                error_register = "Podane hasła się nie zgadzają!"
                return render_template('register.html', error_register=error_register)

            new_user = User(username=new_username, password=new_password, email=new_email)
            db.session.add(new_user)
            db.session.commit()
            return redirect('/login')   #### czy tu RETURN ?

        except ServerError as err:
            error_register = str(err)

        return render_template('register.html', error_register=error_register)

    return render_template('register.html')


@app.route('/records/', methods=['GET'])
def get_records():
    records = Record.query.all()
    return render_template('record-list.html', records=records)


@app.route('/records/', methods=['POST'])
def new_record():
    new_artist = request.form.get('artist')
    new_title = request.form.get('title')

    if new_artist == '' or new_title == '':
        error = "Wypełnij pola!"
        records = Record.query.all()
        return render_template('record-list.html', error=error, records=records)

    new_record = Record(title=new_title, artist=new_artist)
    db.session.add(new_record)
    db.session.commit()
    return redirect('/records/')


@app.route('/records/edit', methods=['POST'])
def edit_record():
    edit_id = request.form.get("edit_id")
    edit_artist = request.form.get("artist")
    edit_title = request.form.get("title")

    record_to_edit=Record.query.get(edit_id)

    record_to_edit.artist = edit_artist
    record_to_edit.title = edit_title
    db.session.commit()
    return redirect('/records/')


@app.route("/delete_record", methods=["POST"])
def delete_record():
    id_delete = request.form.get("id_delete")
    delete_record=Record.query.get(id_delete)
    db.session.delete(delete_record)
    db.session.commit()
    return redirect('/records/')


@app.route('/records/<int:id>', methods=['GET'])
def get_record(id):
    record = Record.query.get(id)
    if not record:
        flash('Nie odnaleziono albumu: {}'.format(id), category='danger')
        return redirect('/records')
    api_data = record.get_additional()

    reviews = db.session.query(Review).filter(Review.record_id == id)

    rating_avg = db.session.query(func.avg(Rating.rate)).filter(Rating.record_id == id).scalar()

    rating_count = db.session.query(Rating.rate).filter(Rating.record_id == id).count()

    u = db.session.query(User).all()

    rats = db.session.query(Rating).filter(Rating.record_id == id)
    # k

    return render_template('record.html', record=record, api_data=api_data, reviews=reviews, avg_rat=rating_avg,
                           rat_count=rating_count, users=u, rats=rats)

    error = api_data.get('error', '')
    if error:
        flash(error, category='warning')
    return render_template('record.html', record=record, api_data=api_data)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# kz
@app.route('/review/<int:id>', methods=['POST'])
def save_review(id):
    # rat = request.form['score']
    rev_txt = request.form['ratingTxt']

    u_name = session['username']
    u = db.session.query(User.id).filter(User.username == u_name).scalar()

    rev = Review(review=rev_txt, user_id=u, record_id=id)
    db.session.add(rev)
    # db.session.merge(rev)
    # db.session.flush()
    # rev_id = rev.id
    # rating = Rating(rate=rat, user_id=u, record_id=id)  # , review_id=rev_id)
    # db.session.add(rating)
    db.session.commit()

    record = Record.query.get(id)
    api_data = record.get_additional()
    return redirect(url_for('get_record', id=id))


@app.route('/rating/<int:id>', methods=['POST'])
def save_rating(id):
    rat = request.form['score']
    u_name = session['username']
    u = db.session.query(User.id).filter(User.username == u_name).scalar()
    rating = Rating(rate=rat, user_id=u, record_id=id)  # , review_id=rev_id)
    db.session.add(rating)
    db.session.commit()
    return redirect(url_for('get_record', id=id))


@app.route('/reviews/<int:id>', methods=['POST'])
def get_reviews(id):
    reviews = db.session.query(Review).filter(Review.record_id == id)

    # score_sum = db.session.query(func.sum(Rating.rate).label('sum')).filter(Rating.record_id == id).scalar()

    rating_avg = db.session.query(func.avg(Rating.rate)).filter(Rating.record_id == id).scalar()

    rating_count = db.session.query(Rating.rate).filter(Rating.record_id == id).count()

    u = db.session.query(User).all()

    rats = db.session.query(Rating).filter(Rating.record_id == id)

    return render_template('reviews.html', reviews=reviews, avg_rat=rating_avg, rat_count=rating_count, users=u,
                           rats=rats)

@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = [
        {'author': user, 'body': 'Test post '}
    ]
    return render_template('user.html', user=user, posts=posts)


@lm.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now()
        db.session.commit()


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)


@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Użytkownik {} nie znaleziony.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('Nie możesz sam siebie obserwować!')
        return redirect(url_for('user', username=username))
    current_user.follow(user)
    db.session.commit()
    flash('Zacząłeś obserwować {}!'.format(username))
    return redirect(url_for('user', username=username))


@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Użytkownik {} nie znaleziony.'.format(username))
        return redirect(url_for('index'))
    if user == current_user:
        flash('Nie możesz sam siebie obserwować!')
        return redirect(url_for('user', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash('Przestałeś obserwować {}.'.format(username))
    return redirect(url_for('user', username=username))
