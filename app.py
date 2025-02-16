import os
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_wtf.csrf import CSRFProtect
import pyotp
import requests
from models import db, User, SafeZone, AuthenticationLog
from config import Config
from itsdangerous import URLSafeTimedSerializer

# Initialize extensions
app = Flask(__name__)
app.config.from_object(Config)

csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)
login_manager = LoginManager(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Admin panel
admin = Admin(app, name='GeoMFA Admin', template_mode='bootstrap3')
class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(SafeZone, db.session))
admin.add_view(AdminModelView(AuthenticationLog, db.session))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Geolocation functions
def get_ip_geolocation(ip_address):
    try:
        response = requests.get(
            f"https://www.googleapis.com/geolocation/v1/geolocate?key={app.config['GOOGLE_MAPS_API_KEY']}",
            json={"considerIp": True}
        )
        data = response.json()
        return {
            'latitude': data['location']['lat'],
            'longitude': data['location']['lng'],
            'accuracy': data['accuracy']
        }
    except Exception as e:
        app.logger.error(f"IP Geolocation error: {str(e)}")
        return None

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Get location from browser or IP
            location = {'latitude': latitude, 'longitude': longitude} if latitude and longitude \
                else get_ip_geolocation(request.remote_addr)
            
            if not location:
                flash('Could not determine your location')
                return redirect(url_for('login'))
            
            if is_within_safe_zone(user, location):
                login_user(user)
                log_authentication(user.id, True, location)
                return redirect(url_for('dashboard'))
            else:
                session['requires_2fa'] = True
                session['user_id'] = user.id
                return redirect(url_for('totp_verify'))
        else:
            flash('Invalid credentials')
    
    print(get_ip_geolocation(request.remote_addr))
    return render_template('login.html')

@app.route('/totp_verify', methods=['GET', 'POST'])
def totp_verify():
    if not session.get('requires_2fa'):
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        totp_code = request.form['totp_code']
        if user and user.totp_enabled and user.verify_totp(totp_code):
            login_user(user)
            log_authentication(user.id, True, get_ip_geolocation(), True)
            session.pop('requires_2fa', None)
            return redirect(url_for('dashboard'))
        flash('Invalid TOTP code')
    return render_template('totp_setup.html', user=user)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/safe_zones', methods=['GET', 'POST'])
@login_required
def safe_zones():
    if request.method == 'POST':
        # Handle safe zone creation
        pass
    return render_template('safe_zones.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Security functions
def is_within_safe_zone(user, location):
    for zone in user.safe_zones:
        if haversine(location['latitude'], location['longitude'], 
                    zone.latitude, zone.longitude) <= zone.radius:
            return True
    return False

def haversine(lat1, lon1, lat2, lon2):
    from math import radians, sin, cos, sqrt, atan2
    R = 6371.0  # Earth radius in kilometers
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = R * c
    return distance

def log_authentication(user_id, status, location, totp_used=False):
    log = AuthenticationLog(user_id=user_id, status='success' if status else 'failed', location_used=f"{location['latitude']}, {location['longitude']}", totp_used=totp_used)
    db.session.add(log)
    db.session.commit()

# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('login.html'), 404

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # For HTTPS testing