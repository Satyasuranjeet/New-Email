from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from bson import ObjectId
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import secrets
import functools

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'fallback-secret-key')
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Initialize extensions
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# MongoDB Connection with connection pooling optimization
MONGO_URI = os.getenv("MONGO_URI")
client = None
db = None
users_collection = None

def get_db_connection():
    """Lazy database connection initialization"""
    global client, db, users_collection
    if client is None:
        client = MongoClient(
            MONGO_URI,
            maxPoolSize=10,
            minPoolSize=1,
            maxIdleTimeMS=30000,
            serverSelectionTimeoutMS=5000,
            socketTimeoutMS=20000
        )
        db = client['user_authentication']
        users_collection = db['users']
    return users_collection

# Email Configuration
SMTP_CONFIG = {
    'server': os.getenv("SMTP_SERVER"),
    'port': int(os.getenv("SMTP_PORT", 587)),
    'email': os.getenv("SENDER_EMAIL"),
    'password': os.getenv("SENDER_PASSWORD")
}

# Utility Functions
def validate_email(email):
    """Validate email format"""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

def send_email_util(to_email, subject, body):
    """Utility function to send emails"""
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_CONFIG['email']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        with smtplib.SMTP(SMTP_CONFIG['server'], SMTP_CONFIG['port']) as server:
            server.starttls()
            server.login(SMTP_CONFIG['email'], SMTP_CONFIG['password'])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email sending error: {e}")
        return False

def validate_api_key(api_key):
    """Validate API key and return user"""
    collection = get_db_connection()
    return collection.find_one({"api_key": api_key})

def admin_required(f):
    """Decorator to check admin privileges"""
    @functools.wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        user_id = get_jwt_identity()
        collection = get_db_connection()
        user = collection.find_one({"_id": ObjectId(user_id)})
        
        if not user or not user.get('is_admin', False):
            return jsonify({"error": "Unauthorized"}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/register', methods=['POST'])
def register():
    collection = get_db_connection()
    data = request.json
    
    # Input validation
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400
    
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    
    # Check existing user
    if collection.find_one({"email": email}):
        return jsonify({"error": "User already exists"}), 409
    
    # Create user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    verification_code = secrets.token_hex(4)
    
    user_doc = {
        "email": email,
        "password": hashed_password,
        "verified": False,
        "verification_code": verification_code,
        "api_usage_limit": 1000,
        "current_usage": 0
    }
    
    # Send verification email
    if send_email_util(email, 'Account Verification', f'Your verification code is: {verification_code}'):
        collection.insert_one(user_doc)
        return jsonify({"message": "Registration successful. Check your email for verification."}), 201
    else:
        return jsonify({"error": "Failed to send verification email"}), 500

@app.route('/login', methods=['POST'])
def login():
    collection = get_db_connection()
    data = request.json
    
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    user = collection.find_one({"email": email})
    
    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    if not user.get('verified', False):
        return jsonify({"error": "Please verify your email first"}), 403
    
    access_token = create_access_token(identity=str(user['_id']))
    user_role = 'admin' if user.get('is_admin', False) else 'user'
    
    return jsonify({
        "access_token": access_token,
        "user_role": user_role
    }), 200

@app.route('/verify', methods=['POST'])
def verify_email():
    collection = get_db_connection()
    data = request.json
    
    email = data.get('email', '').strip().lower()
    verification_code = data.get('verification_code', '')
    
    if not email or not verification_code:
        return jsonify({"error": "Email and verification code are required"}), 400
    
    user = collection.find_one({"email": email, "verification_code": verification_code})
    
    if user:
        collection.update_one(
            {"_id": user['_id']}, 
            {"$set": {"verified": True}, "$unset": {"verification_code": ""}}
        )
        return jsonify({"message": "Email verified successfully"}), 200
    
    return jsonify({"error": "Invalid verification code"}), 400

@app.route('/generate-api-key', methods=['POST'])
@jwt_required()
def generate_api_key():
    collection = get_db_connection()
    user_id = get_jwt_identity()
    
    user = collection.find_one({"_id": ObjectId(user_id)})
    
    if user and user.get("api_key"):
        return jsonify({"message": "You already have an API key."}), 400
    
    api_key = secrets.token_hex(16)
    
    collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {
            "api_key": api_key, 
            "api_usage_limit": 1000,
            "current_usage": 0
        }}
    )
    
    return jsonify({"api_key": api_key}), 200

@app.route('/get-api-details', methods=['GET'])
@jwt_required()
def get_api_details():
    collection = get_db_connection()
    user_id = get_jwt_identity()
    user = collection.find_one({"_id": ObjectId(user_id)})
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "api_key": user.get('api_key', ''),
        "usage_limit": user.get('api_usage_limit', 0),
        "current_usage": user.get('current_usage', 0)
    }), 200

@app.route('/user-details', methods=['GET'])
@jwt_required()
def user_details():
    collection = get_db_connection()
    user_id = get_jwt_identity()
    user = collection.find_one({"_id": ObjectId(user_id)}, {"password": 0})
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "email": user.get("email"),
        "verified": user.get("verified", False),
        "api_key": user.get("api_key", None),
        "api_usage_limit": user.get("api_usage_limit", 0),
        "current_usage": user.get("current_usage", 0)
    }), 200

@app.route('/send-email', methods=['POST'])
def send_email():
    collection = get_db_connection()
    
    # Get API key
    api_key = request.args.get('apikey')
    if not api_key:
        return jsonify({"error": "API key is required"}), 400
    
    # Remove Bearer prefix if present
    if api_key.startswith('Bearer '):
        api_key = api_key[7:]
    
    # Validate API key
    user = validate_api_key(api_key)
    if not user:
        return jsonify({"error": "Invalid API key"}), 403
    
    # Check usage limits
    if user.get('current_usage', 0) >= user.get('api_usage_limit', 1000):
        return jsonify({'error': 'API limit reached'}), 403
    
    if user.get('api_usage_disabled', False):
        return jsonify({'error': 'API access disabled'}), 403
    
    # Get email data
    data = request.json
    receiver_email = data.get('receiver_email', '').strip()
    subject = data.get('subject', '').strip()
    message = data.get('message', '').strip()
    
    if not all([receiver_email, subject, message]):
        return jsonify({"error": "receiver_email, subject, and message are required"}), 400
    
    if not validate_email(receiver_email):
        return jsonify({"error": "Invalid receiver email format"}), 400
    
    try:
        # Send email
        if send_email_util(receiver_email, subject, message):
            # Update usage
            collection.update_one(
                {"_id": ObjectId(user['_id'])},
                {"$inc": {"current_usage": 1}}
            )
            return jsonify({"message": "Email sent successfully!"}), 200
        else:
            return jsonify({"error": "Failed to send email"}), 500
    
    except Exception as e:
        return jsonify({"error": f"Email sending failed: {str(e)}"}), 500

# Admin Routes
@app.route('/admin/users', methods=['GET'])
@admin_required
def get_all_users():
    collection = get_db_connection()
    
    users = list(collection.find({}, {"password": 0, "verification_code": 0}))
    for user in users:
        user['_id'] = str(user['_id'])
    
    return jsonify(users), 200

@app.route('/admin/enable-user', methods=['POST'])
@admin_required
def enable_user():
    collection = get_db_connection()
    data = request.json
    target_user_id = data.get('user_id')
    
    if not target_user_id:
        return jsonify({"error": "user_id is required"}), 400
    
    try:
        collection.update_one(
            {"_id": ObjectId(target_user_id)},
            {"$unset": {"api_usage_disabled": ""}}
        )
        return jsonify({"message": "User API access enabled"}), 200
    except Exception as e:
        return jsonify({"error": "Invalid user ID"}), 400

@app.route('/admin/disable-user', methods=['POST'])
@admin_required
def disable_user():
    collection = get_db_connection()
    data = request.json
    target_user_id = data.get('user_id')
    
    if not target_user_id:
        return jsonify({"error": "user_id is required"}), 400
    
    try:
        collection.update_one(
            {"_id": ObjectId(target_user_id)},
            {"$set": {"api_usage_disabled": True}}
        )
        return jsonify({"message": "User API access disabled"}), 200
    except Exception as e:
        return jsonify({"error": "Invalid user ID"}), 400

@app.route('/admin/set-user-limit', methods=['POST'])
@admin_required
def set_user_api_limit():
    collection = get_db_connection()
    data = request.json
    target_user_id = data.get('user_id')
    new_limit = data.get('api_usage_limit')
    
    if not target_user_id or new_limit is None:
        return jsonify({"error": "user_id and api_usage_limit are required"}), 400
    
    if not isinstance(new_limit, int) or new_limit < 0:
        return jsonify({"error": "api_usage_limit must be a non-negative integer"}), 400
    
    try:
        collection.update_one(
            {"_id": ObjectId(target_user_id)},
            {"$set": {"api_usage_limit": new_limit}}
        )
        return jsonify({"message": "API usage limit updated"}), 200
    except Exception as e:
        return jsonify({"error": "Invalid user ID"}), 400

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "email-api"}), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# For Vercel serverless deployment
def handler(request):
    return app(request.environ, lambda *args: None)

if __name__ == '__main__':
    # For local development
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)