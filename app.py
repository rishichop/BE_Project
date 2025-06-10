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
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.menu import MenuLink
from flask_admin.contrib.sqla import ModelView
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
import pyotp
import requests
from models import db, User, SafeZone, AuthenticationLog, PendingSafeZone
from config import Config
from itsdangerous import URLSafeTimedSerializer
import subprocess
import time

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)
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
    default_limits=["200 per day", "100 per hour"]
)

# Admin panel
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not (current_user.is_authenticated and current_user.is_admin):
            return redirect(url_for('login'))  # Adjust as per your app
        return super(MyAdminIndexView, self).index()
    
admin = Admin(app, name='GeoMFA Admin', index_view=MyAdminIndexView(), template_mode='bootstrap3')
class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
class UserModelView(ModelView):
    can_create = False
    can_edit = True
    can_delete = False

    column_searchable_list = ('username',)
    form_columns = ('totp_enabled',)
    column_list = ('id', 'username', 'email', 'is_admin', 'totp_enabled')

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
class SafeZoneView(ModelView):
    form_columns = ('user', 'zone_name', 'latitude', 'longitude', 'radius')
    column_list = ('s_user.username', 'zone_name', 'latitude', 'longitude', 'radius')
    column_searchable_list = ('zone_name',)
    column_filters = ('user_id', 'zone_name')

    
    form_ajax_refs = {
        'user': {
            'fields': ['username'],
            'page_size': 10
        }
    }

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
class LogModelView(ModelView):
    can_create = False

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

admin.add_view(UserModelView(User, db.session))
admin.add_view(SafeZoneView(SafeZone, db.session))
admin.add_view(LogModelView(AuthenticationLog, db.session))
admin.add_link(MenuLink(name='Back to Dashboard', url='/dashboard'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/admin/pending-safezones')
@login_required
def pending_safezones():
    if not current_user.is_admin:
        flash("Access denied: Admins only.", "danger")
        return redirect(url_for('index'))

    zones = PendingSafeZone.query.all()
    return render_template('pending_safezones.html', zones=zones)

@app.route('/admin/approve-safezone/<int:zone_id>', methods=['POST'])
@login_required
def approve_safezone(zone_id):
    if not current_user.is_admin:
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    zone = PendingSafeZone.query.get_or_404(zone_id)
    user = User.query.get(zone.user_id)

    new_zone = SafeZone(
        user_id=zone.user_id,
        zone_name=zone.zone_name,
        latitude=zone.latitude,
        longitude=zone.longitude,
        radius=zone.radius
    )
    db.session.add(new_zone)
    db.session.delete(zone)
    db.session.commit()

    if user and user.email:
        msg = Message(subject="Safe Zone Approved",
                      sender="no-reply@example.com",
                      recipients=[user.email])
        msg.body = f"Hello {user.username},\n\nYour safe zone '{zone.zone_name}' has been approved by the admin."
        mail.send(msg)

    flash("Safe zone approved and user notified.", "success")
    return redirect(url_for('pending_safezones'))

def send_totp(user, totp):
    msg = Message('Totp', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''Totp of login Time limit: 60 secs {totp}'''
    mail.send(msg)

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']

            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already exists. Please choose a different one.', 'danger')
                return redirect(url_for('register'))

            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            pending_zone = PendingSafeZone(
                user_id=user.id,
                zone_name=request.form['zone_name'],
                latitude=float(request.form['latitude']),
                longitude=float(request.form['longitude']),
                radius=float(request.form['radius']) / 1000
            )
            db.session.add(pending_zone)
            db.session.commit()

            flash('Registration successful. Your safe zone is pending approval by the admin.', 'info')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            db.session.delete(user)
            db.session.commit()
            app.logger.error(f"Registration error: {e}")
            flash(f'{e}. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form['username']
            password = request.form['password']
            latitude = request.form.get('latitude')
            longitude = request.form.get('longitude')

            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                location = {'latitude': latitude, 'longitude': longitude}
                session['location'] = location

                if user.totp_enabled:
                    session['requires_2fa'] = True
                    session['user_id'] = user.id
                    totp = user.get_totp()
                    send_totp(user, totp)
                    return redirect(url_for('totp_verify'))

                if not location or location['latitude'] == '' or location['longitude'] == '':
                    flash('Could not determine your location. Make sure your GPS is on.', 'warning')
                    return redirect(url_for('login'))

                if is_within_safe_zone(user, location):
                    login_user(user)
                    log_authentication(user.id, True, location)
                    return redirect(url_for('dashboard'))
                else:
                    flash("You are not within your safe zone.", 'danger')
                    log_authentication(user.id, False, location)
                    return redirect(url_for('login'))
            else:
                flash('Invalid credentials', 'danger')
                return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            flash(f'{e}. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/totp_verify', methods=['GET', 'POST'])
def totp_verify():
    if not session.get('requires_2fa'):
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        try:
            totp_code = request.form['totp_code']
            if user and user.totp_enabled and user.verify_totp(totp_code):
                login_user(user)
                log_authentication(user.id, True, session.get('location'), True)
                session.pop('requires_2fa', None)
                return redirect(url_for('dashboard'))
            flash('Invalid TOTP code', 'danger')
        except Exception as e:
            app.logger.error(f"TOTP verification error: {e}")
            flash(f'{e}.', 'danger')

    return render_template('totp_setup.html', user=user)


@app.route('/dashboard')
@login_required
def dashboard():
    safe_zone = session.get("safe_zone")
    if not safe_zone:
        safe_zone = None

    return render_template('dashboard.html', safe_zone=safe_zone, user_location=session.get('location', {'latitude': 0, 'longitude': 0}))

@app.route('/safe_zones', methods=['GET', 'POST'])
@login_required
def safe_zones():
    if request.method == 'POST':
        try:
            zone_name = request.form['zone_name']
            latitude = float(request.form['latitude'])
            longitude = float(request.form['longitude'])
            radius = float(request.form['radius']) / 1000

            safe_zone = SafeZone(
                user_id=current_user.id,
                zone_name=zone_name,
                latitude=latitude,
                longitude=longitude,
                radius=radius
            )
            db.session.add(safe_zone)
            db.session.commit()
            flash('Safe zone added successfully', 'success')
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Safe zone creation error: {e}")
            flash(f'{e}. Please try again.', 'danger')

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
            
            session["safe_zone"] = {
            "user_lat": float(session.get("location")["latitude"]),
            "user_lng": float(session.get("location")["longitude"]),
            "latitude": zone.latitude,
            "longitude": zone.longitude,
            "radius": zone.radius
        }
            return True
    return False

def haversine(lat1, lon1, lat2, lon2):
    from math import radians, sin, cos, sqrt, atan2
    R = 6371.0
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
    try:
        log = AuthenticationLog(
            user_id=user_id,
            status='success' if status else 'failed',
            location_used=f"{location['latitude']}, {location['longitude']}",
            totp_used=totp_used
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to log authentication: {e}")


# Error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template('login.html'), 404

# Function to start ngrok
def start_ngrok(port=5000):
    ngrok_process = subprocess.Popen(["ngrok", "http", f"--url={app.config['NGROK_LINK']}", str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"\n\n\n\nngrok_link: https://{app.config['NGROK_LINK']}\n\n\n\n\n")
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