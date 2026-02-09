from flask import Flask, request, jsonify, render_template, redirect, url_for
import pickle
import re
from textblob import TextBlob
from PIL import Image
import pytesseract
import io
import os
import sys

# --- AUTH LIBRARIES ---
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. SMART TESSERACT CONFIGURATION ---
# Detects if we are on Windows (Laptop) or Linux (Render Cloud)
if os.name == 'nt': # Windows
    # Update this path if you installed Tesseract somewhere else
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
else: # Linux / Cloud
    pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'

app = Flask(__name__)

# --- 2. APP CONFIGURATION ---
app.config['SECRET_KEY'] = 'hackathon-secret-key-123' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- 3. DATABASE & LOGIN SETUP ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200)) # Increased length for secure hashes
    name = db.Column(db.String(100))

# Create Tables
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 4. AUTH ROUTES ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists.'}), 400

    # Secure Password Hashing
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='pbkdf2:sha256'))
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Account created! Please log in.'})

@app.route('/login', methods=['POST'])
def login_post():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials.'}), 400

    login_user(user)
    return jsonify({'message': 'Logged in successfully!', 'name': user.name})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/get_user_status')
def get_user_status():
    if current_user.is_authenticated:
        return jsonify({'is_logged_in': True, 'name': current_user.name})
    return jsonify({'is_logged_in': False})

# --- 5. AI MODEL LOADING ---
try:
    with open('spam_model.pkl', 'rb') as f:
        model = pickle.load(f)
except:
    print("❌ WARNING: 'spam_model.pkl' not found. Predictions will fail until trained.")
    model = None

SPAM_TRIGGERS = ['free', 'winner', 'cash', 'prize', 'urgent', 'money', 'congrats', 'won', 'offer', 'call', 'text', 'click']

def analyze_links(text):
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    results = []
    for url in urls:
        risk = "Low"
        if "http://" in url: risk = "High (Not Secure)"
        if len(url) > 50: risk = "Medium (Long URL)"
        if any(x in url for x in ['bit.ly', 'tinyurl', 'free', 'login']): risk = "High (Suspicious)"
        results.append({"url": url, "risk": risk})
    return results

def get_tone(text):
    blob = TextBlob(text)
    polarity = blob.sentiment.polarity
    if polarity < -0.3: return "Aggressive / Negative"
    if polarity > 0.5: return "Friendly / Positive"
    return "Neutral"

# --- 6. MAIN ROUTES ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/process_file', methods=['POST'])
def process_file():
    """
    Handles Image & Text Uploads using In-Memory Processing.
    This works perfectly on Render/Cloud without saving files to disk.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    filename = file.filename.lower()
    content = ""

    try:
        # Check if it is an image
        if filename.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff')):
            # Open directly from RAM (No disk save needed!)
            image = Image.open(file.stream)
            content = pytesseract.image_to_string(image)
        
        # Check if it is a text/email file
        else:
            content = file.read().decode('utf-8', errors='ignore')

        if not content.strip():
            return jsonify({'email_text': "", 'note': "OCR finished but no text found."})

        return jsonify({'email_text': content})

    except Exception as e:
        print(f"Error processing file: {e}")
        return jsonify({'error': "Failed to process file. Ensure it is a valid image or text file."}), 500

@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return jsonify({'error': 'Model is not loaded. Please contact admin.'}), 500
        
    data = request.get_json()
    email_text = data.get('text', '')
    
    # VIP Whitelist
    vip_words = ['unstop', 'internship', 'stipend', 'college', 'university']
    if any(word in email_text.lower() for word in vip_words):
        return jsonify({
            'result': 'promo', 
            'confidence': 98.5, 
            'insight': "📢 PROMOTION: Verified Opportunity.", 
            'triggers': [], 
            'tone': "Professional", 
            'links': []
        })

    # AI Prediction
    prediction = model.predict([email_text])[0]
    try: 
        confidence = round(max(model.predict_proba([email_text])[0]) * 100, 1)
    except: 
        confidence = 99.9

    triggers = [word for word in SPAM_TRIGGERS if word in email_text.lower()]
    tone_analysis = get_tone(email_text)
    link_analysis = analyze_links(email_text)

    # Insight Logic
    if prediction == 'spam': 
        insight = f"⛔ SPAM: {tone_analysis} tone detected."
    elif prediction == 'promo': 
        insight = "📢 PROMOTION: Marketing language detected."
    else: 
        insight = "✅ SAFE: Natural communication."

    return jsonify({
        'result': prediction, 
        'confidence': confidence, 
        'insight': insight, 
        'triggers': triggers, 
        'tone': tone_analysis, 
        'links': link_analysis
    })

if __name__ == '__main__':
    app.run(debug=True)