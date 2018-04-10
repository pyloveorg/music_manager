"""music_manager project"""

from flask import url_for, render_template, request, redirect, session
from main import app, db, bcrypt
from models import User, Record, Review, Rating  # KZ
from sqlalchemy import func


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
        return redirect('/profile')
    return render_template('login.html')


@app.route('/profile', methods=['GET'])
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html', tekst="Dziala! Zalogowalo sie AAAA")


@app.route('/logout')
def logout():
    session.pop('username', None)
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


@app.route('/records/<int:id>', methods=['GET'])
def get_record(id):
    record = Record.query.get(id)
    api_data = record.get_additional()

    # k
    reviews = db.session.query(Review).filter(Review.record_id == id)

    rating_avg = db.session.query(func.avg(Rating.rate)).filter(Rating.record_id == id).scalar()

    rating_count = db.session.query(Rating.rate).filter(Rating.record_id == id).count()

    u = db.session.query(User).all()

    rats = db.session.query(Rating).filter(Rating.record_id == id)
    # k

    return render_template('record.html', record=record, api_data=api_data, reviews=reviews, avg_rat=rating_avg,
                           rat_count=rating_count, users=u, rats=rats)


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



