from datetime import datetime
from flask import Flask, flash, redirect,render_template, request, session, url_for, jsonify, make_response
from flask.cli import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
import os
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
from werkzeug.utils import secure_filename
import uuid # For unique filenames
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)

# Load environment variables from a .env file if present
env_path = "E:/IDEAS IOT Dashboard/IDEAS-IOT/.env"
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# --- Add CSRF Protection ---
csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20000000 per day", "500000000 per hour"],
    storage_uri="memory://"
)

print(f"✅ DATABASE_URL loaded: {os.getenv('DATABASE_URL')}")

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- Add App Configuration for File Uploads ---
app.config['UPLOAD_FOLDER'] = 'E:/IDEAS IOT Dashboard/IDEAS-IOT/static/avatars'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
    # This claims_options block is the critical fix for the 'iss' error
    claims_options={
        'iss': {
            'essential': True,
            'values': ['https://accounts.google.com', 'accounts.google.com']
        }
    }
)

# Load the API key from environment variables
VALID_API_KEY = os.getenv('VALID_API_KEY')

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    avatar = db.Column(db.String(100), nullable=True, default='default.png') # New avatar field
    
    # Relationship to LoginHistory
    logins = db.relationship('LoginHistory', backref='user', lazy=True, cascade="all, delete-orphan")

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Add a relationship to the MotorData model so we can easily delete a user's motor data
class MotorData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    motor_id = db.Column(db.String(50), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    voltage = db.Column(db.Float, nullable=False)
    current = db.Column(db.Float, nullable=False)
    power = db.Column(db.Float, nullable=False)
    over_voltage = db.Column(db.Boolean, nullable=False, default=False)
    over_load_details = db.Column(db.Boolean, nullable=True, default=False)
    def to_dict(self):
        """Helper method to convert model instance to dictionary for JSON serialization."""
        return {
            'motor_id': self.motor_id,
            'timestamp': self.timestamp.isoformat(),
            'voltage': self.voltage,
            'current': self.current,
            'power': self.power,
            'over_voltage': self.over_voltage,
            'over_load_details': self.over_load_details
        }

@app.after_request
def add_security_headers(response):
    
    # 1. Content-Security-Policy (CSP)
    # ---
    # This is the most important one. It tells the browser to ONLY 
    # load resources (scripts, styles, images) from your own domain ('self').
    # This is a primary defense against XSS.
    # (This is a basic policy; it can get very complex)
    csp_policy = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://developers.google.com;"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    
    # 2. Missing Anti-Clickjacking Header (X-Frame-Options)
    # ---
    # Prevents your site from being loaded in an <iframe> on another 
    # website. This stops "Clickjacking" attacks.
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # 3. X-Content-Type-Options Header Missing
    # ---
    # Prevents the browser from "MIME sniffing" (guessing) the content type.
    # If you upload a text file named "styles.css", the browser will
    # treat it as text, not a stylesheet.
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    return response


# --- Main Page Routes ---
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return dict(current_user=user)  # Change from 'user' to 'current_user'
    return dict(current_user=None)

# --- NEW: Profile Page Route ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS'] and \
           filename != '' and \
           secure_filename(filename) == filename


# --- NEW: Profile Routes ---

@app.route('/profile')
def profile():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    # Get last 5 logins, most recent first
    login_history = LoginHistory.query.filter_by(user_id=user.id).order_by(LoginHistory.timestamp.desc()).limit(5).all()
    return render_template('profile.html', user=user, login_history=login_history)

@app.route('/profile/edit', methods=['POST'])
def edit_profile():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    
    # Handle username change
    new_username = request.form.get('username')
    if new_username and new_username != user.username:
        # Check if new username is already taken
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user:
            flash('Username is already taken.', 'danger')
            return redirect(url_for('profile'))
        user.username = new_username
        flash('Username updated successfully!', 'success')

    # Handle avatar upload
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename != '' and allowed_file(file.filename):
            # --- START: ADD THIS BLOCK ---
            upload_folder = app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True) # This creates the folder if it's missing
            # --- END: ADD THIS BLOCK ---

            filename = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4()) + os.path.splitext(filename)[1]
            # Use the local variable for the path
            file_path = os.path.join(upload_folder, unique_filename)
            file.save(file_path)
            user.avatar = unique_filename
            flash('Avatar updated successfully!', 'success')
    
    db.session.commit()
    return redirect(url_for('profile'))


@app.route('/profile/password', methods=['POST'])
def change_password():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])

    if not user.password_hash:
        flash('Cannot change password for accounts signed in with Google.', 'warning')
        return redirect(url_for('profile'))

    if not check_password_hash(user.password_hash, request.form.get('current_password')):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('profile'))

    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('profile'))

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    flash('Password updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/profile/delete', methods=['POST'])
def delete_account():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])

    # For password-based accounts, confirm password before deleting
    if user.password_hash:
        if not check_password_hash(user.password_hash, request.form.get('password_confirm')):
            flash('Password incorrect. Account not deleted.', 'danger')
            return redirect(url_for('profile'))
    
    # Delete user and all their related data (cascade takes care of login history)
    db.session.delete(user)
    db.session.commit()
    session.clear()
    flash('Your account has been permanently deleted.', 'success')
    return redirect(url_for('home'))

@app.route('/google/login')
def google_login():
    # The URL in your app that Google will redirect to after the user signs in
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/google/callback')
def google_callback():
    token = google.authorize_access_token()
    user_info = token['userinfo']
    user_email = user_info['email']

    user = User.query.filter_by(email=user_email).first()
    if not user:
        user = User(email=user_email, username=user_email, password_hash=None)
        db.session.add(user)
        db.session.commit()

    session.clear()
    session['user_id'] = user.id
    
    # --- ADD THIS: Record login history ---
    login_record = LoginHistory(user_id=user.id, ip_address=request.remote_addr)
    db.session.add(login_record)
    db.session.commit()

    flash('Successfully logged in with Google!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    motor_id_tuples = db.session.query(MotorData.motor_id).distinct().order_by(MotorData.motor_id).all()
    motor_list = [m[0] for m in motor_id_tuples]
    initial_data = None
    if motor_list:
        initial_data = MotorData.query.filter_by(motor_id=motor_list[0]).order_by(MotorData.timestamp.desc()).first()

    return render_template('dashboard.html', motors=motor_list, data=initial_data, max_voltage=300.0, max_current=10.0, max_power=2000.0)

# --- API Routes ---
@app.route('/api/motor_data/<string:motor_id>')
def get_motor_data(motor_id):
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    
    latest_data = MotorData.query.filter_by(motor_id=motor_id).order_by(MotorData.timestamp.desc()).first()

    if latest_data:
        # Create a JSON response from our data
        response = make_response(jsonify(latest_data.to_dict()))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    else:
        return jsonify({'error': f'No data found for {motor_id}'}), 404

@app.route('/add_data', methods=['POST'])
@csrf.exempt
def add_data():
    # --- Your excellent authentication ---
    request_api_key = request.headers.get('X-API-KEY')
    if not request_api_key or request_api_key != VALID_API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON body'}), 400
    
    # --- Your excellent validation ---
    required_fields = ['motor_id', 'voltage', 'current', 'power']
    if not all(key in data for key in required_fields):
        return jsonify({'error': 'Missing one or more required fields'}), 400

    try:
        # Use the 'data' variable you already created
        new_data = MotorData(
            motor_id=data.get('motor_id'),
            voltage=float(data.get('voltage')),
            current=float(data.get('current')),
            power=float(data.get('power')),
            over_voltage=str(data.get('over_voltage', False)).lower() == 'true',
            over_load_details=str(data.get('over_load_details', False)).lower() == 'true'
        )
        db.session.add(new_data)
        db.session.commit()
        
        # POLISH #1: Return a JSON response with a 201 status code
        return jsonify({'message': 'Data added successfully'}), 201

    except (TypeError, ValueError) as e:
        # POLISH #2: Rollback the session and hide the raw error
        db.session.rollback()
        logging.error(f"Error processing data submission: {e}") # Log the actual error for your records
        return jsonify({'error': 'Invalid data format for one or more fields.'}), 400

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.password_hash and check_password_hash(user.password_hash, request.form['password']):
            session['user_id'] = user.id
            
            # --- ADD THIS: Record login history ---
            login_record = LoginHistory(user_id=user.id, ip_address=request.remote_addr)
            db.session.add(login_record)
            db.session.commit()
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # --- SOLUTION: Add these validation blocks ---
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('An account with that email already exists.', 'danger')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')
        # --- End of validation ---

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error during registration: {e}")
            flash('An error occurred during registration. Please try again.', 'danger')

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host = "0.0.0.0",port=5000,debug=False)