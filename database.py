# -*- coding: utf-8 -*-
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

# Gemeinsam verwendete Objekte

db = SQLAlchemy()
bcrypt = Bcrypt()
