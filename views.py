"""music_manager project"""

from flask import url_for, render_template, request, redirect, session, flash
from main import app, db, bcrypt, lm
from models import User, Record, Review, Rating, EditProfileForm, List # KZ
from sqlalchemy import func
from sqlalchemy import or_
from flask_login import current_user, login_required, login_user, logout_user
from datetime import datetime
import requests

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
            flash(str(err), 'danger')
            return render_template('login.html')

        if szukany_uzytkownik is None:
            flash("Zły login lub hasło!", 'danger')
            return render_template('login.html')

        if not bcrypt.check_password_hash(szukany_uzytkownik.password, password_form):
            flash("Zły login lub hasło!", 'danger')
            return render_template('login.html')

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

    if request.method == 'POST':
        new_username = request.form.get('username')
        new_password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
        new_password_verify = request.form.get('password_verify')
        new_email = request.form.get('email')

        try:
            sprawdzanie_uzytkownika_login = User.query.filter_by(username=new_username).first()
            if sprawdzanie_uzytkownika_login is not None:
                flash("Podany login już istnieje", 'danger')
                return render_template('register.html',username=new_username,email=new_email)

            sprawdzanie_uzytkownika_email = User.query.filter_by(email=new_email).first()
            if sprawdzanie_uzytkownika_email is not None:
                flash("Podany przez Ciebie adres e-mail już istnieje", 'danger')
                return render_template('register.html',username=new_username,email=new_email)

            if not bcrypt.check_password_hash(new_password, new_password_verify):
                flash("Podane hasła się nie zgadzają!", 'danger')
                return render_template('register.html',username=new_username,email=new_email)

            new_user = User(username=new_username, password=new_password, email=new_email)
            db.session.add(new_user)
            db.session.commit()
            return redirect('/login')   #### czy tu RETURN ?

        except ServerError as err:
            flash(str(err), 'danger')
            return render_template('register.html')

    return render_template('register.html')



@app.route('/edit_password', methods=['GET','POST'])
def edit_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = bcrypt.generate_password_hash(request.form.get('new_password')).decode('utf-8')
        new_password_verify = request.form.get('new_password_verify')

        try:
            username=session['username']
            sprawdzanie_uzytkownika_haslo = User.query.filter_by(username=username).first()

            if not bcrypt.check_password_hash(sprawdzanie_uzytkownika_haslo.password, old_password):
                flash("Podaleś błędne stare hasło!", 'danger')
                return render_template('edit_password.html')

            if not bcrypt.check_password_hash(new_password, new_password_verify):
                flash("Podane hasła się nie zgadzają!", 'danger')
                return render_template('edit_password.html')


            sprawdzanie_uzytkownika_haslo.password = new_password
            db.session.commit()
            flash("Hasło zmienione", 'success')
            return redirect('/login')

        except ServerError as err:
            flash(str(err), 'danger')
            return render_template('edit_password.html')


    return render_template('edit_password.html')

'''
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect('user/' + current_user.username)
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile',
                           form=form)
'''

@app.route('/records/', methods=['GET'])
def get_records():
    records = Record.query.all()
    #sprawdza typ listy
    #list_type = None
    #if current_user.is_authenticated:
        #u_name = session['username']
        #u = db.session.query(User.id).filter(User.username == session['username']).scalar()
        #list_type = db.session.query(List.title).filter(List.user_id == u).scalar()
    return render_template('record-list.html', records=records)
    #else:
        #tutaj trzeba dodać opcję w przypadku typu listy publicznej dla niezalogowanych
        #return render_template('record-list.html', records=records)



@app.route('/records/', methods=['POST'])
def new_record():
    new_artist = request.form.get('artist')
    new_title = request.form.get('title')
    # sprawdzanie czy ktoś zostawił puste pole
    if new_artist == '' or new_title == '':
        flash("Wypełnij pola!", 'danger')
        records = Record.query.all()
        return render_template('record-list.html', records=records)

    new_record = Record(title=new_title, artist=new_artist)
    api_check = new_record.get_additional()
    # sprawdzanie czy dany artysta/płyta są w zewnętrznym API
    if 'error' in api_check:
        flash("Nie znaleziono takiej pozycji. Podaj prawidłowe dane!", 'warning')
        records = Record.query.all()
        return render_template('record-list.html', records=records)

    # sprawdzanie czy juz istnieje w naszej bazie
    record_check = Record.query.filter_by(title=new_title, artist=new_artist).first()
    if record_check is not None:
        flash("Dana pozycja już istnieje w bazie", 'warning')
        records = Record.query.all()
        return render_template('record-list.html', records=records)

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

    rating_list = delete_record.ratings
    review_list = delete_record.reviews

    for review in review_list:
        db.session.delete(review)

    for rating in rating_list:
        db.session.delete(rating)

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


@app.route('/type-list', methods=['POST'])
def save_list_type():
    if request.method == 'POST':
        type = None
        title = ''
        u_name = session['username']
        u = db.session.query(User.id).filter(User.username == u_name).scalar()
        list_type_select = request.form['list-type']
        if list_type_select == 'publiczna':
            type = 0
            title = 'publiczna'
            flash('Twoja lista jest publiczna')
        elif list_type_select == 'prywatna':
            type = 1
            title = 'prywatna'
            flash('Twoja lista jest prywatna')
        elif list_type_select == 'dla znajomych':
            type = 2
            title = 'dla znajomych'
            flash('Twoja lista jest widoczna tylko dla znajomych')

        #sprawdzanie czy typ listy jest już określony
        check_list_type = db.session.query(List).filter(List.user_id == u).scalar()
        check_list_title = db.session.query(List).filter(List.user_id == u).scalar()
        if check_list_type and check_list_title:
            check_list_type.type = type
            check_list_title.title = title
            db.session.commit()
        else:
            tplist = List(title=title, type=type, user_id=u)
            db.session.add(tplist)
            db.session.commit()
        return redirect('/records')

        #obsługa widoczności listy w zależności od typu w templatkach - do zrobienia


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/review/<int:id>', methods=['POST'])
@login_required
def save_review(id):
    rev_txt = request.form['ratingTxt']

    u_name = session['username']
    u = db.session.query(User.id).filter(User.username == u_name).scalar()

    old_review = db.session.query(Review.id).filter(Review.user_id == u, Review.record_id == id).scalar()
    rev = Review(review=rev_txt, user_id=u, record_id=id)

    if old_review is None:
        db.session.add(rev)
        db.session.commit()
    else:
        db.session.query(Review).update({Review.review: rev_txt})
        db.session.commit()

    record = Record.query.get(id)
    api_data = record.get_additional()
    return redirect(url_for('get_record', id=id))


@app.route('/rating/<int:id>', methods=['POST'])
@login_required
def save_rating(id):
    rat = request.form['score']
    u_name = session['username']
    u = db.session.query(User.id).filter(User.username == u_name).scalar()

    old_rating = db.session.query(Rating.id).filter(Rating.user_id == u, Rating.record_id == id).scalar()
    rating = Rating(rate=rat, user_id=u, record_id=id)

    if old_rating is None:
        db.session.add(rating)
        db.session.commit()
    else:
        db.session.query(Rating).update({Rating.rate: rat})
        db.session.commit()

    return redirect(url_for('get_record', id=id))


@app.route('/reviews/<int:id>', methods=['POST'])
def get_reviews(id):
    reviews = db.session.query(Review).filter(Review.record_id == id)

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
    reviews = current_user.followed_review().all()
    return render_template("user.html", reviews=reviews, user=user)


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
        return redirect('user/' + current_user.username)
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


@app.route('/followed_list/<username>')
@login_required
def followed_list(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Użytkownik {} nie znaleziony.'.format(username))
        return redirect(url_for('index'))
    followed_group = user.followed.all()
    return render_template('followed_list.html', user=user,
                           followed_group=followed_group)


@app.route('/followers_list/<username>')
@login_required
def followers_list(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Użytkownik {} nie znaleziony.'.format(username))
        return redirect(url_for('index'))
    followers_group = user.followers.all()
    return render_template('followers_list.html', user=user,
                           followers_group=followers_group)


@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        new_search = request.form.get('search')

        # sprawdzanie czy ktoś zostawił puste pole
        if new_search == '':
            flash("Wypełnij pola!", 'warning')
            records = Record.query.all()
            return render_template('record-list.html', records=records)

        try:
            search_artist = Record.query.filter(or_(Record.title.like("%" + new_search + "%"), Record.artist.like("%" + new_search + "%"))).all()
            if search_artist is None or len(search_artist)<1:
                flash("Nie ma w bazie takiego artysty bądź tytułu!", 'warning')
                records = Record.query.all()
                return render_template('record-list.html', records=records)
            else:
                return render_template('record-list.html', records=search_artist)

        except ServerError as err:
            error_register = str(err)
            flash(str(err), 'warning')

    return render_template('info.html')

@app.route('/api', methods=['GET'])
def get_api_data():

    rows = []
    for count in range(1, 50):
        url = 'https://api.discogs.com/releases/' + str(count)
        response = requests.get(url)
        jsonText = response.json()
        artists = jsonText.get('artists')
        title = jsonText.get('title')
        genres = jsonText.get('genres')
        styles = jsonText.get('styles')
        country = jsonText.get('country')
        year = jsonText.get('year')

        genresString = ''
        if (genres is not None):
            for genre in genres:
                genresString += str(genre) + ';'

        stylesString = ''
        if (styles is not None):
            for style in styles:
                stylesString += str(style) + ';'

        names = []
        if (artists is not None):
            for artist in artists:
                artist_name = artist['name']
                dane = {
                    'artist':artist_name,
                    'title':title,
                    'genres':genresString,
                    'styles':stylesString,
                    'country':country,
                    'year':year
                }
                rows.append(dane)

                record_check = Record.query.filter_by(title=title, artist=artist_name).first()
                if record_check is None:
                    plyta = Record(title=title, artist=artist_name, country=country, year=year, styles=stylesString, genres=genresString)
                    db.session.add(plyta)
                    db.session.commit()


    return render_template('api.html', rows=rows)



