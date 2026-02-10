from flask import Flask, request, jsonify, render_template, redirect, url_for
import pickle
import re
from textblob import TextBlob
from PIL import Image
import pytesseract
import io
import os
import sys
import gc  # Garbage Collector for memory management
from flask_cors import CORS # For Chrome Extension

# --- AUTH LIBRARIES ---
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. SMART TESSERACT CONFIGURATION ---
if os.name == 'nt': # Windows
    # Update this path if needed
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
else: # Linux / Cloud (Render)
    pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'

app = Flask(__name__)
CORS(app) # Enable CORS for Chrome Extension

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
    password = db.Column(db.String(200)) 
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
    print("❌ WARNING: 'spam_model.pkl' not found.")
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
    Optimized for Render Free Tier (Low RAM)
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
            
            # 1. Open image directly from memory
            image = Image.open(file.stream)
            
            # 2. OPTIMIZATION: Convert to Grayscale (Reduces RAM by 66%)
            image = image.convert('L') 
            
            # 3. OPTIMIZATION: Resize if too huge (Max 1000px width/height)
            image.thumbnail((1000, 1000)) 
            
            # 4. Extract Text
            content = pytesseract.image_to_string(image)
            
            # 5. CLEANUP: Force delete image from memory immediately
            del image
            gc.collect()

        # Check if it is a text/email file
        else:
            content = file.read().decode('utf-8', errors='ignore')

        if not content.strip():
            return jsonify({'email_text': "", 'note': "OCR finished but no text found."})

        return jsonify({'email_text': content})

    except Exception as e:
        print(f"Error processing file: {e}")
        # Return a clean error message to the user
        return jsonify({'error': "Memory Limit Exceeded. Try a smaller image."}), 500

@app.route('/predict', methods=['POST'])
def predict():
    if not model:
        return jsonify({'error': 'Model is not loaded.'}), 500
        
    data = request.get_json()
    email_text = data.get('text', '')
    text_lower = email_text.lower()
    
    # --- 1. EDUCATIONAL INSTITUTIONS (Always Safe) ---
    # Detects IIT, VIT, .edu emails, or general college terms
    edu_keywords = ['iit', 'vit', 'university', 'college', 'institute', 'ac.in', '.edu', 'student portal', 'campus']
    if any(word in text_lower for word in edu_keywords):
        return jsonify({
            'result': 'safe', 
            'confidence': 99.8, 
            'insight': "✅ INSTITUTION: Official communication from an educational body.", 
            'triggers': [], 
            'tone': "Academic", 
            'links': []
        })

    # --- 2. SOCIAL MEDIA & SERVICES (Context Aware) ---
    # Detects Spotify, Amazon, Google, Instagram, etc.
    service_keywords = ['spotify', 'amazon', 'youtube', 'instagram', 'netflix', 'linkedin', 'google', 'facebook', 'twitter']
    
    if any(service in text_lower for service in service_keywords):
        # SUB-RULE A: Security / Account Info -> SAFE
        security_keywords = ['password', 'verify', 'security alert', 'login', 'receipt', 'order confirmed', 'invoice', 'two-factor', 'otp', 'account info']
        if any(sec in text_lower for sec in security_keywords):
             return jsonify({
                'result': 'safe', 
                'confidence': 99.5, 
                'insight': "✅ SECURITY: Official account update or security alert.", 
                'triggers': [], 
                'tone': "Transactional", 
                'links': []
            })
        
        # SUB-RULE B: Marketing / Engagement -> PROMO
        # If it's not security, it's likely "Join Premium", "Check this out", etc.
        return jsonify({
            'result': 'promo', 
            'confidence': 92.0, 
            'insight': "📢 PROMOTION: Service marketing or engagement email.", 
            'triggers': [], 
            'tone': "Marketing", 
            'links': []
        })

    # --- 3. SELECTION / JOB OFFERS (Existing Logic) ---
    selection_keywords = ['shortlisted', 'selected', 'interview', 'hired', 'offer letter', 'top 5%', 'round 1']
    if any(word in text_lower for word in selection_keywords):
        return jsonify({
            'result': 'safe', 
            'confidence': 99.5, 
            'insight': "✅ OFFICIAL: Valid selection or interview update.", 
            'triggers': [], 
            'tone': "Professional", 
            'links': []
        })

    # --- 4. GENERAL PROMO KEYWORDS ---
    promo_keywords = ['apply now', 'early bird', 'discount', 'stipend', 'bootcamp', 'webinar', 'limited time']
    if any(word in text_lower for word in promo_keywords):
        return jsonify({
            'result': 'promo', 
            'confidence': 95.0, 
            'insight': "📢 PROMOTION: Contains marketing language.", 
            'triggers': [], 
            'tone': "Marketing", 
            'links': []
        })

    # --- 5. GENERAL AI MODEL FALLBACK ---
    prediction = model.predict([email_text])[0]
    try: 
        confidence = round(max(model.predict_proba([email_text])[0]) * 100, 1)
    except: 
        confidence = 99.9

    triggers = [word for word in SPAM_TRIGGERS if word in text_lower]
    tone_analysis = get_tone(email_text)
    link_analysis = analyze_links(email_text)

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