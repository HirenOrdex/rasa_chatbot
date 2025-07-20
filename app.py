from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import datetime, timedelta
import asyncio
import json
import uuid
import os
import secrets
import jwt
from functools import wraps
from rasa.core.agent import Agent
from dotenv import load_dotenv

app = Flask(__name__)
CORS(app)

# Load environment variables from .env file
load_dotenv()
# Email configuration
app.secret_key = os.getenv('FLASK_SECRET_KEY') # Load from .env

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = (os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
mail = Mail(app)
app.config['MONGO_URI']= os.getenv('MONGO_URI')
# MongoDB Configuration
class MongoHandler:
    def __init__(self):
        try:            
            mongo_uri = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
            db_name = os.getenv('MONGO_DB_NAME', 'logistics_chatbot')
            self.client = MongoClient(mongo_uri)
            self.db = self.client[db_name]

            self.conversations = self.db['conversations']
            self.analytics = self.db['analytics']
            self.users = self.db['users']
            print(f"✅ Connected to MongoDB at {mongo_uri}")
        except Exception as e:
            print(f"❌ MongoDB connection error: {e}")

    def save_user(self, username, email, password_hash, verification_token):
        try:
            user_data = {
                'username': username,
                'email': email,
                'password_hash': password_hash,
                'verification_token': verification_token,
                'is_verified': False,
                'created_at': datetime.now(),
                'last_login': None
            }
            self.users.insert_one(user_data)
            return True
        except Exception as e:
            print(f"Error saving user: {e}")
            return False

    def get_user_by_email(self, email):
        return self.users.find_one({'email': email})

    def get_user_by_username(self, username):
        return self.users.find_one({'username': username})

    def verify_user_email(self, token):
        user = self.users.find_one({'verification_token': token})
        if user:
            self.users.update_one(
                {'_id': user['_id']},
                {'$set': {'is_verified': True, 'verification_token': None}}
            )
            return True
        return False

    def update_last_login(self, email):
        self.users.update_one(
            {'email': email},
            {'$set': {'last_login': datetime.now()}}
        )

    def save_conversation(self, user_id, user_message, bot_response, intent, confidence):
        try:
            conversation = {
                'user_id': user_id,
                'user_message': user_message,
                'bot_response': bot_response,
                'intent': intent,
                'confidence': confidence,
                'timestamp': datetime.now()
            }
            self.conversations.insert_one(conversation)
        except Exception as e:
            print(f"Error saving conversation: {e}")

    def save_analytics(self, intent):
        try:
            # Update or insert intent count
            self.analytics.update_one(
                {'intent': intent},
                {'$inc': {'count': 1}, '$set': {'last_used': datetime.now()}},
                upsert=True
            )
        except Exception as e:
            print(f"Error saving analytics: {e}")

    def get_user_history(self, user_id):
        return list(self.conversations.find(
            {'user_id': user_id},
            {'_id': 0}
        ).sort('timestamp', -1).limit(50))

mongo_handler = MongoHandler()

# Load trained Rasa model
try:
    model_dir = os.getenv('RASA_MODEL_PATH', 'temp_rasa_project/models') # Default if not in .env
    if os.path.exists(model_dir):
        models = [f for f in os.listdir(model_dir) if f.endswith('.tar.gz')]
        if models:
            latest_model = max(models, key=lambda x: os.path.getctime(os.path.join(model_dir, x)))
            model_path = os.path.join(model_dir, latest_model)
            agent = Agent.load(model_path)
            print(f"✅ Model loaded: {latest_model}")
        else:
            print("❌ No trained models found")
            agent = None
    else:
        print("❌ Models directory not found")
        agent = None
except Exception as e:
    print(f"❌ Error loading model: {e}")
    agent = None

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Routes for authentication
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    data = request.get_json() if request.is_json else request.form
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return "<p>Email and password are required</p>", 400

    user = mongo_handler.get_user_by_email(email)
    if user and check_password_hash(user['password_hash'], password):
        if not user['is_verified']:
            return "<p>Please verify your email first</p>", 401

        session['user_id'] = str(user['_id'])
        session['username'] = user['username']
        session['email'] = user['email']
        mongo_handler.update_last_login(email)

        # HTMX redirect header
        return '', 204, {'HX-Redirect': '/chat'}

    return "<p>Invalid credentials</p>", 401
    

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    data = request.get_json() if request.is_json else request.form
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400

    # Check if user already exists
    if mongo_handler.get_user_by_email(email):
        return jsonify({'error': 'Email already registered'}), 400

    if mongo_handler.get_user_by_username(username):
        return jsonify({'error': 'Username already taken'}), 400

    # Generate verification token
    verification_token = secrets.token_urlsafe(32)
    password_hash = generate_password_hash(password)

    # Save user
    if mongo_handler.save_user(username, email, password_hash, verification_token):
        # Send verification email
        try:
            msg = Message(
                'Verify Your Email - Logistics Chatbot',
                sender=app.config['MAIL_USERNAME'],
                recipients=[email]
            )
            verification_url = url_for('verify_email', token=verification_token, _external=True)
            msg.html = f"""
            <h2>Welcome to Logistics Chatbot!</h2>
            <p>Please click the link below to verify your email:</p>
            <a href="{verification_url}">Verify Email</a>
            <p>If you didn't register for this account, please ignore this email.</p>
            """
            mail.send(msg)
            return jsonify({'message': 'Registration successful! Please check your email to verify your account.'})
        except Exception as e:
            print(f"Email sending error: {e}")
            return jsonify({'error': 'Registration successful but email verification failed. Please contact support.'}), 500
    else:
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/verify-email/<token>')
def verify_email(token):
    if mongo_handler.verify_user_email(token):
        return render_template('email_verified.html')
    else:
        return render_template('verification_failed.html')

@app.route('/logout')
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', username=session.get('username'))

# Chatbot routes

# Chatbot routes
@app.route('/webhook', methods=['POST'])
@login_required
def webhook():
    try:
        data = request.get_json()
        user_message = data.get('message', '')
        user_id = session.get('user_id')

        if not agent:
            return jsonify({
                'response': 'Sorry, the chatbot model is not available. Please check the training logs.',
                'intent': 'error',
                'confidence': 0.0
            })

        # --- Get NLU prediction for the user's message ---
        nlu_result = asyncio.run(agent.parse_message(user_message))
        
        intent_name = nlu_result.get('intent', {}).get('name', 'unknown')
        intent_confidence = nlu_result.get('intent', {}).get('confidence', 0.0)

        # --- Get bot's response ---
        bot_responses = asyncio.run(agent.handle_text(user_message))
        response_texts = [e['text'] for e in bot_responses if 'text' in e]
        bot_response_text = '\n'.join(response_texts) if response_texts else "I'm not sure how to help with that."

        # If no text response was found, use a fallback
        if bot_response_text == "I'm not sure how to help with that." and not bot_responses:
            bot_response_text = "I'm still learning. Could you rephrase your question about logistics optimization?"


        # Save to MongoDB
        try:
            mongo_handler.save_conversation(user_id, user_message, bot_response_text, intent_name, intent_confidence)
            mongo_handler.save_analytics(intent_name)
        except Exception as mongo_error:
            print(f"MongoDB save error: {mongo_error}")

        return jsonify({
            'response': bot_response_text,
            'intent': intent_name,
            'confidence': intent_confidence,
            'user_id': user_id
        })

    except Exception as e:
        print(f"Webhook error: {e}")
        return jsonify({
            'response': 'Sorry, I encountered an error. Please try again.',
            'intent': 'error',
            'confidence': 0.0
        }), 500


@app.route('/analytics', methods=['GET'])
@login_required
def get_analytics():
    try:
        analytics = list(mongo_handler.analytics.find({}, {'_id': 0}).sort('count', -1))
        return jsonify(analytics)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/history', methods=['GET'])
@login_required
def get_user_history():
    try:
        user_id = session.get('user_id')
        history = mongo_handler.get_user_history(user_id)
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'model_loaded': agent is not None,
        'mongodb_connected': True
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)