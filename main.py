#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-
import flask
import flask_login
from flask_wtf import FlaskForm
from wtforms import SubmitField, BooleanField
from wtforms_alchemy import model_form_factory
from sqlalchemy import event as sqla_event
from flask_talisman import Talisman
from os import urandom
from secrets import token_urlsafe
from datetime import datetime
import json

from auth import login_manager, LoginForm, User, auth as _auth_bp
from database import db, bcrypt
from configmodel import MatrixConfig


configclass = MatrixConfig
DEFAULT_ADMIN_PASSWORD = "it-unsicherheit19"

app = flask.Flask(__name__)
app.config['SECRET_KEY'] = urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

# Mit der folgenden Option werden Passwörter durch die Bibliothek vorher
# gehasht, so dass das Zeichenlimit kein Problem sein kann.
app.config['BCRYPT_HANDLE_LONG_PASSWORDS'] = True

ssl_context = None
# ssl_context = "adhoc"
# ssl_context = ("cert.pem", "privkey.pem")
if ssl_context:
    Talisman(app, strict_transport_security=False)
    app.config['REMEMBER_COOKIE_SECURE'] = True

login_manager.init_app(app)

app.register_blueprint(_auth_bp)

db.app = app
db.init_app(app)

# Foreign Keys auswerten. Quelle: https://stackoverflow.com/a/7831210
sqla_event.listen(db.engine, 'connect', lambda dbapi_con, con_record: dbapi_con.execute('pragma foreign_keys=ON'))

# db.drop_all()
db.create_all()

bcrypt.app = app
bcrypt.init_app(app)

if DEFAULT_ADMIN_PASSWORD and not db.session.query(User).filter(User.admin == True).first():
    # Interessant für eine zukünftige Erweiterung wäre, wenn eine Passwortänderung nach dem 1. Login über die Webanwendung erzwungen werden könnte.
    user_admin = User(id="admin", pw_hash=bcrypt.generate_password_hash(DEFAULT_ADMIN_PASSWORD).decode("utf-8"), admin=True, desc="Administration")
    db.session.add(user_admin)
    db.session.commit()
    print(f"\n*\n*\nAdmin-Konto (ID: admin) mit Standardpasswort {DEFAULT_ADMIN_PASSWORD} wurde erstellt, sollte sofort geändert werden." +
        "\nUm dieses Konto nicht automatisch zu erstellen wenn kein Admin-Konto besteht, die Konstante DEFAULT_ADMIN_PASSWORD leer setzen.\n*\n*\n")

BaseModelForm = model_form_factory(FlaskForm)

class ModelForm(BaseModelForm):
    @classmethod
    def get_session(self):
        return db.session

class ConfForm(ModelForm):
    '''
    Klasse für die Konfigurations-Form
    Über die model-Angabe in der Meta-Klasse werden die Felder aus dem
    angegebenen Modell übernommen. Ausgeschlossen für die direkte Bearbeitung
    werden die Spalten im Bezug zum API-Key.
    Darüber hinaus werden einige Eingabefelder für die Verarbeitung der Form
    hier unabhängig von der Konfigurationsklasse definiert.
    '''
    class Meta:
        model = configclass
        exclude = ['_api_key_hash', '_api_key_end', '_api_key_gentime']
    submit = SubmitField('Speichern')
    delete = SubmitField('Konfiguration löschen')
    delete_api_key = BooleanField('löschen')
    create_api_key = BooleanField('erstellen')


@app.route("/dashboard")
@flask_login.login_required
def dashboard():
    '''
    Stellt eine Übersicht aller Konfigurationselemente des
    aktuellen Nutzers dar.
    '''
    return flask.render_template('dashboard.html', configs=flask_login.current_user.configs)


@app.route("/newconf")
@app.route("/admin/newconf/<admin_user>")
@flask_login.login_required
def new_conf(admin_user=None):
    '''
    Erstellt eine neue Konfiguration für den aktuellen bzw. den
    administrierten Nutzer. Danach erfolgt eine Weiterleitung zu ihrer Seite.
    '''
    if admin_user:
        if not flask_login.current_user.admin:
            flask.abort(403)
        user_id = admin_user
        if not User.get(user_id):
            flask.flash(f"Nutzerkonto mit ID {admin_user} existiert nicht.")
            return flask.redirect(flask.url_for("auth.admin"))
    else:
        user_id = flask_login.current_user.id
    # Höchste verwendete Konfigurations-ID des Nutzers herausfinden:
    _firstconf = db.session.query(configclass).filter(configclass.owned_by == user_id).order_by(configclass.num.desc()).first()
    newid = (_firstconf.num + 1) if _firstconf is not None else 0
    userconfig = configclass(owned_by=user_id, num=newid)
    db.session.add(userconfig)
    db.session.commit()
    flask.flash("Konfiguration erstellt.")
    return flask.redirect(flask.url_for("conf", confid=newid, admin_user=admin_user))


@app.route("/conf/<int:confid>", methods=['GET', 'POST'])
@app.route("/admin/conf/<admin_user>/<int:confid>", methods=['GET', 'POST'])
@flask_login.login_required
def conf(confid, admin_user=None):
    '''
    Stellt die Seite für ein Konfigurationselement dar.
    '''
    if admin_user:
        if not flask_login.current_user.admin:
            flask.abort(403)
        # Admin wird im Falle einer Löschung bzw. ungültiger ID auf
        # die Admin-Übersicht umgeleitet.
        redirect_on_missing = flask.url_for("auth.admin")
        user_id = admin_user
    else:
        # normaler Nutzer wird im Falle einer Löschung bzw. ungültiger ID auf
        # die eigene Konfigurationsübersicht umgeleitet.
        redirect_on_missing = flask.url_for("dashboard")
        user_id = flask_login.current_user.id
    userconfig = db.session.query(configclass).get([user_id, confid])
    if not userconfig:
        flask.flash(f"Konfiguration von User {user_id} mit ID {confid} existiert nicht.")
        return flask.redirect(redirect_on_missing)
    form = ConfForm(obj=userconfig)
    if flask.request.method == 'POST':
        # Als erstes wird geprüft, ob eine Löschung erwünscht ist.
        if form.delete.data:
            db.session.delete(userconfig)
            db.session.commit()
            flask.flash(f'Konfiguration {confid} gelöscht.')
            return flask.redirect(redirect_on_missing)
        # Sonst folgt die Validierung der Form und die weitere Verarbeitung.
        if form.validate():
            # Anhand der Attribute der Form wird das eigentliche
            # Konfigurations-Objekt mit den Form-Daten befüllt
            form.populate_obj(userconfig)
            if userconfig.public_id == "":
                userconfig.public_id = None
            if form.create_api_key.data:
                api_key = token_urlsafe(32)
                flask.flash(f"Generierter API-Key: {api_key}. Der Key wird hiernach nicht mehr voll dargestellt.")
                userconfig._api_key_hash = bcrypt.generate_password_hash(api_key).decode("utf-8")
                userconfig._api_key_end = api_key[-6:]
                userconfig._api_key_gentime = datetime.now()
            if form.delete_api_key.data:
                userconfig._api_key_hash = None
                userconfig._api_key_end = None
                userconfig._api_key_gentime = None
            db.session.commit()
            flask.flash('Konfiguration gespeichert.')
        else:
            flask.flash('Validierungsfehler:\n'+str(form.errors))
    if userconfig._api_key_hash:
        del form.create_api_key
    else:
        del form.delete_api_key
    # Immer folgt die Darstellung der Konfigurationsseite.
    # Mitgegeben wird das Form-Objekt sowie Angaben zum API-Key, zur Darstellung.
    return flask.render_template('conf.html', form=form, apikeydata={"end": userconfig._api_key_end, "gen": userconfig._api_key_gentime} if userconfig._api_key_hash else {})


@app.route("/data")
def data():
    '''
    Datenabruf, unabhängig von flask-login.
    '''
    data_id = flask.request.args.get('id')
    user_id = flask.request.args.get('user_id')
    api_key = flask.request.args.get('api_key')
    result = {}
    # data_id (für öffentlichen Datenabruf) wird falls vorhanden zuerst probiert.
    if data_id:
        _config = db.session.query(configclass).filter(configclass.public_id == data_id).first()
        if _config:
            result = json.dumps(_config, cls=_config.JSONEncoder)
    # Falls es nicht angegeben wurde bzw. ungültig war, wird, falls angegeben,
    # die Methode mit User-ID + API-Key (gilt für genau eine Konfiguration) probiert.
    if not result:
        if not (user_id and api_key):
            flask.abort(401, description="user_id und api_key müssen angegeben werden, oder gültige öffentliche id")
        user = User.get(user_id)
        if user is None:
            flask.abort(401, description="User ID existiert nicht")
        for config in user.configs:
            if config._api_key_hash is not None and bcrypt.check_password_hash(config._api_key_hash, api_key):
                result = json.dumps(config, cls=config.JSONEncoder)
                break
        else:
            flask.abort(401, description="Ungültiger API-Key")
    return flask.Response(result, mimetype='application/json')


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        ssl_context=ssl_context
    )
