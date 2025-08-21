from datetime import datetime
from flask import Flask, flash, redirect,render_template, request, session, url_for, jsonify, make_response
from flask.cli import load_dotenv
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

logging.basicConfig(level=logging.INFO)


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

load_dotenv()

# Configure database (fallback to sqlite for local testing)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

VALID_API_KEY = os.getenv('VALID_API_KEY')

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='Student')  # Default role to 'Student'
    last_login = db.Column(db.DateTime, nullable=True)
 
class MotorData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    motor_id = db.Column(db.String(50), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    voltage = db.Column(db.Float, nullable=False)
    current = db.Column(db.Float, nullable=False)
    power = db.Column(db.Float, nullable=False)
    speed = db.Column(db.Float, nullable=True)
    torque = db.Column(db.Float, nullable=True)
    field_current = db.Column(db.Float, nullable=True)
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
            'speed': self.speed,
            'torque': self.torque,
            'field_current': self.field_current,
            'over_voltage': self.over_voltage,
            'over_load_details': self.over_load_details
        }


# --- Main Page Routes ---
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

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

@app.route('/analytics')
def analytics():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    motor_id_tuples = db.session.query(MotorData.motor_id).distinct().order_by(MotorData.motor_id).all()
    motor_list = [m[0] for m in motor_id_tuples]
    return render_template('analytics.html', motors=motor_list)


# --- API Routes ---
@app.route('/api/motor_data/<string:motor_id>')
def get_motor_data(motor_id):
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    
    latest_data = MotorData.query.filter_by(motor_id=motor_id).order_by(MotorData.timestamp.desc()).first()

    if latest_data:
        # Create a JSON response from our data
        response = make_response(jsonify(latest_data.to_dict()))
        
        # --- THIS IS THE KEY FIX ---
        # Add headers to the response to prevent caching
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response
    else:
        return jsonify({'error': f'No data found for {motor_id}'}), 404

@app.route('/api/graph_data')
def get_graph_data():
    if 'user_id' not in session: return jsonify({'error': 'Unauthorized'}), 401
    
    motor_id = request.args.get('motor_id')
    x_axis_param = request.args.get('x_axis', 'timestamp')
    y_axis_param = request.args.get('y_axis', 'voltage')
    
    ALLOWED_AXES = ['timestamp', 'voltage', 'current', 'power', 'speed', 'torque', 'field_current']
    if x_axis_param not in ALLOWED_AXES or y_axis_param not in ALLOWED_AXES:
        return jsonify({'error': 'Invalid axis parameters'}), 400

    x_axis_col = getattr(MotorData, x_axis_param)
    y_axis_col = getattr(MotorData, y_axis_param)

    sort_column = MotorData.timestamp if x_axis_param == 'timestamp' else x_axis_col

    graph_data = db.session.query(x_axis_col, y_axis_col)\
        .filter(MotorData.motor_id == motor_id, x_axis_col.isnot(None), y_axis_col.isnot(None))\
        .order_by(sort_column.asc()).limit(200).all()

    if not graph_data: return jsonify({'x_values': [], 'y_values': []})
        
    x_values, y_values = zip(*graph_data)

    if x_axis_param == 'timestamp':
        x_values = [ts.isoformat() for ts in x_values]

    return jsonify({'x_values': x_values, 'y_values': y_values})

@app.route('/add_data', methods=['POST'])
def add_data():
    # --- Your excellent authentication ---
    request_api_key = request.headers.get('X-API-KEY')
    if not request_api_key or request_api_key != VALID_API_KEY:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON body'}), 400
    
    # --- Your excellent validation ---
    required_fields = ['motor_id', 'voltage', 'current', 'power', 'speed', 'torque', 'field_current']
    if not all(key in data for key in required_fields):
        return jsonify({'error': 'Missing one or more required fields'}), 400

    try:
        # Use the 'data' variable you already created
        new_data = MotorData(
            motor_id=data.get('motor_id'),
            voltage=float(data.get('voltage')),
            current=float(data.get('current')),
            power=float(data.get('power')),
            speed=float(data.get('speed')),
            torque=float(data.get('torque')),
            field_current=float(data.get('field_current')),
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
        if user and check_password_hash(user.password_hash, request.form['password']):
            session['user_id'] = user.id
            user.last_login = datetime.utcnow()
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
        role = request.form.get('role', 'Student')  # Default role to 'Student'

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
        new_user = User(username=username, email=email, password_hash=hashed_password, role=role,last_login=datetime.utcnow())

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
    app.run(debug=True)