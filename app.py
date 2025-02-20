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
from flask_cors import CORS
import pyotp
import requests
from models import db, User, SafeZone, AuthenticationLog
from config import Config
from itsdangerous import URLSafeTimedSerializer
import subprocess
import time

# Initialize extensions
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)  # Allow all origins (for testing)
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

# # Geolocation functions
# def get_ip_geolocation(ip_address):
#     # try:
#     #     response = requests.post(
#     #         f"https://www.googleapis.com/geolocation/v1/geolocate?key={app.config['GOOGLE_MAPS_API_KEY']}",
#     #         json={"considerIp": True}
#     #     )
#     #     data = response.json()
#     #     return {
#     #         'latitude': data['location']['lat'],
#     #         'longitude': data['location']['lng'],
#     #         'accuracy': data['accuracy']
#     #     }
#     # except Exception as e:
#     #     app.logger.error(f"IP Geolocation error: {str(e)}")
#     #     return None
#     # try:
#     #     response = requests.get(f"https://ipinfo.io/{ip_address}/json")
#     #     data = response.json()
#     #     lat, lon = data["loc"].split(",")
#     #     return {
#     #         'ip': ip_address,
#     #         'latitude': float(lat),
#     #         'longitude': float(lon),
#     #         'city': data.get("city"),
#     #         'region': data.get("region"),
#     #         'country': data.get("country")
#     #     }
#     # except Exception as e:
#     #     app.logger.error(f"IP Geolocation error: {str(e)}")
#     #     return None

def send_verification_email(user):
    token = user.get_verification_token()
    msg = Message('Verify Your Email', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{url_for('verify_email', token=token, _external=True)}

If you did not make this request, simply ignore this email.
'''
    mail.send(msg)

@app.route('/update_location', methods=['GET', 'POST'])
def update_location():
    data = request.get_json()
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    # Store location in session, database, or logs
    print(f"Received Location: {latitude}, {longitude}")

    return jsonify({"status": "success", "latitude": latitude, "longitude": longitude})

@app.route('/verify_email/<token>')
def verify_email(token):
    user = User.verify_verification_token(token)
    if user is None:
        flash('Invalid or expired token.')
        return redirect(url_for('login'))
    user.email_verified = True
    db.session.commit()
    flash('Email verified. You can now login.')
    return redirect(url_for('login'))

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        flash('Registration successful. Please check your email to verify your account.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
# @limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        print("ip: ", request.headers.get('X-Forwarded-For', request.remote_addr))

        print(username, password, latitude, longitude)
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Get location from browser or IP
            # location = {'latitude': latitude, 'longitude': longitude} if latitude and longitude \
            #     else get_ip_geolocation(request.headers.get('X-Forwarded-For', request.remote_addr))
            location = {'latitude': latitude, 'longitude': longitude}
            session['location'] = location
            print(location)
            
            if not location:
                flash('Could not determine your location')
                return redirect(url_for('login'))
            
            if is_within_safe_zone(user, location):
                login_user(user)
                log_authentication(user.id, True, location)
                return redirect(url_for('dashboard'))
            
            elif user.totp_enabled:
                session['requires_2fa'] = True
                session['user_id'] = user.id
                return redirect(url_for('totp_verify'))
            
            else:
                flash("Not within location")
                return redirect(url_for('login'))
        else:
            flash('Invalid credentials')
            return redirect(url_for('login'))
    
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
            log_authentication(user.id, True, session.get('location'), True)
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
        zone_name = request.form['zone_name']
        latitude = float(request.form['latitude'])
        longitude = float(request.form['longitude'])
        radius = float(request.form['radius'])
        safe_zone = SafeZone(user_id=current_user.id, zone_name=zone_name, latitude=latitude, longitude=longitude, radius=radius)
        db.session.add(safe_zone)
        db.session.commit()
        flash('Safe zone added successfully')
    safe_zones = SafeZone.query.filter_by(user_id=current_user.id).all()
    return render_template('safe_zones.html', safe_zones=safe_zones)

@app.route('/login_history')
@login_required
def login_history():
    logs = AuthenticationLog.query.filter_by(user_id=current_user.id).all()
    return render_template('login_history.html', logs=logs)

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
    lat1, lon1, lat2, lon2 = map(float, [lat1, lon1, lat2, lon2])
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = R * c
    print("distance: ", distance)
    return distance

def log_authentication(user_id, status, location, totp_used=False):
    log = AuthenticationLog(user_id=user_id, status='success' if status else 'failed', location_used=f"{location['latitude']}, {location['longitude']}", totp_used=totp_used)
    db.session.add(log)
    db.session.commit()

# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('login.html'), 404

# Function to start ngrok
def start_ngrok(port=5000):
    # Run ngrok in the background
    ngrok_process = subprocess.Popen(["ngrok", "http", f"--url={app.config['NGROK_LINK']}", str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"\n\n\n\nngrok_link: https://{app.config['NGROK_LINK']}\n\n\n\n\n")

    # Wait for Ngrok to start
    time.sleep(3)
    
    return ngrok_process

# Start ngrok automatically
ngrok_process = start_ngrok(port=5000)

if __name__ == "__main__":
    try:
        app.run(debug=True, host="0.0.0.0", port=5000)
    finally:
        # Kill Ngrok process when Flask stops
        ngrok_process.terminate()