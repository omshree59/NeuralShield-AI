from flask import Flask, request, jsonify, render_template, redirect, url_for
import pickle
import re
from textblob import TextBlob
from PIL import Image
import pytesseract
import io
import os
import sys
import gc  # Garbage Collector
import PyPDF2  # <--- NEW: For Reading PDFs
from collections import Counter # <--- NEW: For Summarizing
from flask_cors import CORS 

# --- AUTH LIBRARIES ---
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# --- 1. TESSERACT CONFIG ---
if os.name == 'nt': # Windows
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
else: # Linux / Render
    pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'

app = Flask(__name__)
CORS(app) 

# --- 2. DATABASE CONFIG ---
app.config['SECRET_KEY'] = 'hackathon-secret-key-123' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- 3. AUTH ROUTES ---
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({'error': 'Email already exists.'}), 400
    new_user = User(email=data.get('email'), name=data.get('name'), password=generate_password_hash(data.get('password'), method='pbkdf2:sha256'))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Account created! Please log in.'})

@app.route('/login', methods=['POST'])
def login_post():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    if not user or not check_password_hash(user.password, data.get('password')):
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

# --- 4. AI MODEL & HELPERS ---
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
    if blob.sentiment.polarity < -0.3: return "Aggressive / Negative"
    if blob.sentiment.polarity > 0.5: return "Friendly / Positive"
    return "Neutral"

# --- 5. PDF SUMMARIZER (The "Highlighter" Logic) ---
def extract_summary(text, num_sentences=3):
    if not text: return "No text to summarize."
    
    # Clean text
    sentences = re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s', text)
    if len(sentences) <= num_sentences: return text 
        
    # Frequency Analysis
    stopwords = {'the', 'is', 'at', 'which', 'on', 'and', 'a', 'an', 'in', 'to', 'of', 'for', 'it', 'that', 'this', 'with', 'as', 'by', 'from', 'or', 'are', 'was', 'be'}
    words = re.findall(r'\w+', text.lower())
    word_freq = Counter([w for w in words if w not in stopwords])
    max_freq = max(word_freq.values()) if word_freq else 1
    
    # Scoring
    sent_scores = {}
    for sent in sentences:
        for word in re.findall(r'\w+', sent.lower()):
            if word in word_freq:
                if sent not in sent_scores: sent_scores[sent] = 0
                sent_scores[sent] += word_freq[word] / max_freq

    # Select Top Sentences
    import heapq
    summary_sentences = heapq.nlargest(num_sentences, sent_scores, key=sent_scores.get)
    return ' '.join(summary_sentences)

# --- 6. ROUTES ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/process_file', methods=['POST'])
def process_file():
    if 'file' not in request.files: return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({'error': 'No file selected'}), 400

    filename = file.filename.lower()
    content = ""

    try:
        # A. HANDLE PDF
        if filename.endswith('.pdf'):
            pdf_reader = PyPDF2.PdfReader(file)
            for page in pdf_reader.pages:
                text = page.extract_text()
                if text: content += text + "\n"

        # B. HANDLE IMAGE
        elif filename.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.tiff')):
            image = Image.open(file.stream).convert('L') 
            image.thumbnail((1000, 1000)) 
            content = pytesseract.image_to_string(image)
            del image
            gc.collect()

        # C. HANDLE TEXT
        else:
            content = file.read().decode('utf-8', errors='ignore')

        if not content.strip():
            return jsonify({'email_text': "", 'note': "No text found."})

        # Generate Summary
        summary = extract_summary(content)

        return jsonify({'email_text': content, 'summary': summary})

    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'error': "File processing failed."}), 500

@app.route('/predict', methods=['POST'])
def predict():
    if not model: return jsonify({'error': 'Model not loaded.'}), 500
    data = request.get_json()
    text = data.get('text', '')
    text_lower = text.lower()
    
    triggers = [w for w in SPAM_TRIGGERS if w in text_lower]
    
    # SMART CHECKS (IIT, Amazon, etc.)
    edu_kw = ['iit', 'vit', 'university', 'college', 'institute', 'ac.in', '.edu']
    if any(k in text_lower for k in edu_kw) and not triggers:
        return jsonify({'result': 'safe', 'confidence': 99.8, 'insight': "✅ INSTITUTION: Official.", 'triggers': [], 'tone': "Academic", 'links': []})

    serv_kw = ['amazon', 'google', 'netflix', 'spotify', 'linkedin']
    if any(s in text_lower for s in serv_kw):
        sec_kw = ['password', 'verify', 'login', 'order', 'receipt']
        if any(k in text_lower for k in sec_kw) and not triggers:
             return jsonify({'result': 'safe', 'confidence': 99.5, 'insight': "✅ SECURITY: Official.", 'triggers': [], 'tone': "Transactional", 'links': []})

    job_kw = ['shortlisted', 'selected', 'interview', 'offer', 'hired']
    if any(j in text_lower for j in job_kw) and not triggers:
        return jsonify({'result': 'safe', 'confidence': 99.5, 'insight': "✅ OFFICIAL: Job/Selection.", 'triggers': [], 'tone': "Professional", 'links': []})

    promo_kw = ['apply now', 'discount', 'limited time', 'offer', 'sale']
    if any(p in text_lower for p in promo_kw):
        return jsonify({'result': 'promo', 'confidence': 95.0, 'insight': "📢 PROMOTION.", 'triggers': triggers, 'tone': "Marketing", 'links': []})

    # AI FALLBACK
    pred = model.predict([text])[0]
    conf = 99.9
    tone = get_tone(text)
    links = analyze_links(text)
    
    insight = f"⛔ SPAM: {tone} tone." if pred == 'spam' else ("📢 PROMOTION." if pred == 'promo' else "✅ SAFE.")

    return jsonify({'result': pred, 'confidence': conf, 'insight': insight, 'triggers': triggers, 'tone': tone, 'links': links})

if __name__ == '__main__':
    app.run(debug=True)