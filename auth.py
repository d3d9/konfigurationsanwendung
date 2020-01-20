# -*- coding: utf-8 -*-
import flask
import flask_login
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, validators

from database import db, bcrypt


MIN_PASSWORD_LENGTH = 6

login_manager = flask_login.LoginManager()

auth = flask.Blueprint('auth', __name__)


class LoginForm(FlaskForm):
    username = StringField('Nutzername', [validators.InputRequired()])
    password = PasswordField('Passwort', [validators.InputRequired()])
    remember = BooleanField('Anmeldung merken')
    submit = SubmitField('Absenden')


class RegisterForm(FlaskForm):
    username = StringField('Nutzername', [validators.InputRequired()])
    password = PasswordField('Passwort',
        [validators.InputRequired(),
         validators.Length(min=MIN_PASSWORD_LENGTH, message=f'Passwort muss mindestens {MIN_PASSWORD_LENGTH} Zeichen lang sein.'),
         validators.EqualTo('password2', message='Passworteingaben müssen übereinstimmen.')])
    password2 = PasswordField('Passwort bestätigen', [validators.InputRequired()])
    submit = SubmitField('Absenden')


class User(db.Model, flask_login.UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Unicode,
            primary_key=True)

    pw_hash = db.Column(db.Unicode, nullable=False)

    desc = db.Column(db.Unicode, nullable=True)

    admin = db.Column(db.Boolean, default=False, nullable=False)

    @classmethod
    def get(cls, id):
        return db.session.query(cls).filter(cls.id == id).first()


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@login_manager.unauthorized_handler
def unauthorized():
    flask.flash('Unautorisiert, bitte einloggen.')
    return flask.redirect('/login')


@auth.route('/login', methods=['GET', 'POST'])
@auth.route('/', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'GET' and flask_login.current_user.is_authenticated:
        return flask.redirect(flask.url_for('dashboard'))

    form = LoginForm()
    if flask.request.method == 'POST':
        if form.validate():
            user = User.get(form.username.data)
            if not user or not bcrypt.check_password_hash(user.pw_hash, form.password.data):
                flask.flash('Benutzername oder Passwort falsch')
                return flask.redirect("/login")

            flask_login.login_user(user, remember=form.remember.data)
            flask.flash('Erfolgreich eingeloggt.')

            return flask.redirect(flask.url_for('dashboard'))
        else:
            flask.flash('Validierungsfehler:\n'+str(form.errors))
    return flask.render_template('login.html', form=form)


@auth.route("/register", methods=['GET', 'POST'])
def register():
    if flask.request.method == 'GET' and flask_login.current_user.is_authenticated:
        flask_login.logout_user()
        return flask.redirect(flask.url_for(flask.request.endpoint))

    form = RegisterForm()
    if flask.request.method == 'POST':
        if form.validate():
            if User.get(form.username.data):
                flask.flash('Benutzername wird bereits verwendet.')
                return flask.redirect(flask.url_for(flask.request.endpoint))

            user = User(
                id=form.username.data,
                pw_hash=bcrypt.generate_password_hash(form.password.data).decode("utf-8")
            )
            db.session.add(user)
            db.session.commit()

            flask_login.login_user(user)
            flask.flash('Registrierung erfolgreich.')

            return flask.redirect(flask.url_for('dashboard'))
        else:
            flask.flash('Validierungsfehler:\n'+str(form.errors))
    return flask.render_template('register.html', form=form)


@auth.route("/logout")
def logout():
    if flask_login.current_user.is_authenticated:
        flask_login.logout_user()
        flask.flash('Ausgeloggt.')
    return flask.redirect("/")


@auth.route("/admin")
@flask_login.login_required
def admin():
    if not flask_login.current_user.admin:
        flask.abort(403)
    return flask.render_template('admin.html', users=db.session.query(User).all())


class SettingsForm(FlaskForm):
    desc = StringField('Beschreibung')
    password = PasswordField('aktuelles Passwort')
    new_password = PasswordField('neues Passwort')
    new_password2 = PasswordField('neues Passwort bestätigen')
    submit = SubmitField('Speichern')
    delete = SubmitField('Nutzerkonto löschen')


@auth.route("/settings", methods=['GET', 'POST'])
@auth.route("/admin/settings/<admin_user>", methods=['GET', 'POST'])
@flask_login.login_required
def settings(admin_user=None):
    if admin_user:
        if not flask_login.current_user.admin:
            flask.abort(403)
        redirect_on_missing = flask.url_for("auth.admin")
        user = User.get(admin_user)
        if user is None:
            flask.flash(f"Nutzerkonto mit ID {admin_user} existiert nicht.")
            return flask.redirect(redirect_on_missing)
        if user == flask_login.current_user:
            return flask.redirect(flask.url_for("auth.settings"))
    else:
        redirect_on_missing = "/"
        user = flask_login.current_user
    form = SettingsForm(data={"desc": user.desc})
    # Wenn man administrierend auf Nutzereinstellungen zugreift muss man nicht das aktuelle Passwort eingeben wenn es geaendert werden soll
    if admin_user:
        del form.password
    if flask.request.method == 'POST':
        if form.delete.data:
            user_id = user.id
            db.session.delete(user)
            db.session.commit()
            flask.flash(f'Nutzerkonto {user_id} gelöscht.')
            return flask.redirect(redirect_on_missing)
        if form.validate():
            user.desc = form.desc.data
            db.session.commit()
            flask.flash('Einstellungen gespeichert.')

            # Validierungen ohne vorgegebene validators implementiert
            if (form.password is not None and form.password.data) or form.new_password.data or form.new_password2.data:
                if form.password is not None and not bcrypt.check_password_hash(user.pw_hash, form.password.data):
                    flask.flash('Das eingegebene aktuelle Passwort ist nicht gültig.')
                    return flask.redirect(flask.url_for(flask.request.endpoint))
                if form.new_password.data != form.new_password2.data:
                    flask.flash('Das neue Passwort wurde nicht korrekt bestätigt.')
                    return flask.redirect(flask.url_for(flask.request.endpoint))
                if len(form.new_password.data) < MIN_PASSWORD_LENGTH:
                    flask.flash(f'Das neue Passwort muss mindestens {MIN_PASSWORD_LENGTH} Zeichen lang sein.')
                    return flask.redirect(flask.url_for(flask.request.endpoint))
                user.pw_hash = bcrypt.generate_password_hash(form.new_password.data).decode("utf-8")
                db.session.commit()
                flask.flash('Passwort geändert.')
        else:
            flask.flash('Validierungsfehler:\n'+str(form.errors))
    return flask.render_template('settings.html', form=form, user=user)
