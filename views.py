"""music_manager project"""

from flask import url_for, render_template, request, redirect, session, flash
from main import app, db, bcrypt
from models import User, Record

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
    if not record:
        flash('Nie odnaleziono albumu: {}'.format(id), category='danger')
        return redirect('/records')
    api_data = record.get_additional()
    error = api_data.get('error', '')
    if error:
        flash(error, category='warning')
    return render_template('record.html', record=record, api_data=api_data)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


