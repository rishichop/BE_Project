from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from flask_bcrypt import Bcrypt
from itsdangerous.serializer import Serializer
from itsdangerous.url_safe import TimedSerializer as TimedJSONWebSignatureSerializer
import pyotp

bcrypt = Bcrypt()

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20))
    is_admin = db.Column(db.Boolean, default=False)
    totp_secret = db.Column(db.String(120))
    totp_enabled = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    safe_zones = db.relationship('SafeZone', backref='user', lazy=True)
    authentication_logs = db.relationship('AuthenticationLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return pyotp.TOTP(self.totp_secret).provisioning_uri(
            name=self.username,
            issuer_name="GeoMFA"
        )

    def verify_totp(self, token):
        return pyotp.TOTP(self.totp_secret).verify(token)

class SafeZone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    zone_name = db.Column(db.String(120), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    radius = db.Column(db.Float, nullable=False)

class AuthenticationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)
    location_used = db.Column(db.String(120))
    totp_used = db.Column(db.Boolean, default=False)