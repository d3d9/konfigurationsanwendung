# -*- coding: utf-8 -*-
from sqlalchemy_utils import ColorType, ChoiceType
from sqlalchemy.ext.declarative import declared_attr
from colour import Color
import json

from database import db
from auth import User


class ConfigBase(db.Model):
    '''
    Abstrakte Modellklasse für Konfigurationen.
    '''
    __abstract__ = True

    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()

    @declared_attr
    def __table_args__(cls):
        return (db.PrimaryKeyConstraint('owned_by', 'num', name='pkc'), )

    @declared_attr
    def owned_by(cls):
        return db.Column(db.Unicode, db.ForeignKey('users.id', ondelete="CASCADE"))

    @declared_attr
    def owner(cls):
        # Configs werden bei Löschung des Nutzerkontos ebenfalls entfernt.
        # Mit dem Attribut 'configs' werden die zugeordneten Konfigurationsobjekte auch vom User-Objekt aus zugreifbar.
        return db.relationship(User, backref=db.backref('configs', passive_deletes=True))

    num = db.Column(db.Integer)

    configname = db.Column(db.Unicode, nullable=True)

    public_id = db.Column(db.Unicode,
                           nullable=True,
                           unique=True)
    _api_key_hash = db.Column(db.Unicode, nullable=True)
    _api_key_end = db.Column(db.Unicode, nullable=True)
    _api_key_gentime = db.Column(db.DateTime, nullable=True)

    class JSONEncoder(json.JSONEncoder):
        '''
        Standard von https://stackoverflow.com/a/10664192.
        Sollte von ableitenden Klassen überschrieben werden, um möglichst passende
        JSON-Ausgaben zu erhalten.
        '''
        def default(self, obj):
            if isinstance(obj, ConfigBase):
                # an SQLAlchemy class
                fields = {}
                for field in [x for x in dir(obj) if not x.startswith('_') and x != 'metadata']:
                    data = obj.__getattribute__(field)
                    try:
                        json.dumps(data) # this will fail on non-encodable values, like other classes
                        fields[field] = data
                    except TypeError:
                        fields[field] = None
                # a json-encodable dict
                return fields

            return json.JSONEncoder.default(self, obj)


class MatrixConfig(ConfigBase):
    '''
    Beispielimplementierung einer Konfigurationsklasse für ein dynamisches
    Fahrgastinformationssystem.
    '''

    lauftextsymbol_choices = [
        ('', "- ohne -"),
        ('info', "Information"),
        ('warn', "Warnung"),
        ('stop', "Haltestelle"),
        ('smile', "Smiley"),
        ('ad', "Werbung"),
        ('delay', "Verspätung"),
        ('earlyterm', "frühes Fahrtende"),
        ('nort', "keine Echtzeitdaten"),
        ('nodeps', "keine Abfahrten"),
    ]
    lauftextsymbol = db.Column(
            ChoiceType(lauftextsymbol_choices),
            info={'label': 'Symbol'})

    lauftext = db.Column(
            db.Unicode,
            server_default="", nullable=True,
            info={'label': 'Lauftext'})
    farbe = db.Column(
            ColorType(),
            nullable=True,
            info={'label': 'Farbe',
                  'description': 'schwarz: Standardwert wird verwendet'})
    helligkeit = db.Column(
            db.Integer,
            server_default="30", nullable=False,
            info={'label': 'Helligkeit',
                  'min': 8, 'max': 90})

    class JSONEncoder(json.JSONEncoder):
        def default(self, userconfig):
            fields = {}
            if isinstance(userconfig, MatrixConfig):
                fields["messages"] = []
                if userconfig.lauftext:
                    fields["messages"].append(
                        {
                            "symbol": userconfig.lauftextsymbol.code if userconfig.lauftextsymbol else None,
                            "text": userconfig.lauftext,
                            "color": userconfig.farbe.hex if userconfig.farbe != Color("black") else None,
                        }
                    )
                fields["config"] = {}
                fields["config"]["brightness"] = userconfig.helligkeit
                fields["command"] = "" # aktuell nicht implementiert
            return fields
