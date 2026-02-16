print("--- 🚀 STARTING NEURALSHIELD SERVER ---")

from flask import Flask, request, jsonify, render_template, redirect, url_for
import pickle
import re
from textblob import TextBlob
from PIL import Image
import pytesseract
import io
import os
import sys
import gc
import PyPDF2
from flask_cors import CORS

# --- DATABASE & AUTH ---
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

print("--- 📚 IMPORTING LIBRARIES COMPLETE ---")

# --- NEW: SMARTER SUMMARIZATION LIBRARIES ---
import nltk
from sumy.parsers.plaintext import PlaintextParser
from sumy.nlp.tokenizers import Tokenizer
from sumy.summarizers.lex_rank import LexRankSummarizer

print("--- 🧠 CHECKING NLTK DATA (This might take a moment...) ---")
try:
    nltk.data.find('tokenizers/punkt')
    print("--- ✅ NLTK DATA FOUND ---")
except LookupError:
    print("--- ⬇️ DOWNLOADING NLTK DATA... (Please wait) ---")
    nltk.download('punkt')
    print("--- ✅ DOWNLOAD COMPLETE ---")

# --- CONFIGURATION ---
if os.name == 'nt': # Windows
    pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
else: # Linux / Cloud
    pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'hackathon-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- DB SETUP ---
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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

# --- AUTH ROUTES ---
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

# --- AI MODEL LOADING ---
print("--- 🤖 LOADING SPAM MODEL... ---")
try:
    with open('spam_model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("--- ✅ MODEL LOADED SUCCESSFULLY ---")
except:
    print("❌ WARNING: 'spam_model.pkl' not found. Predictions will fail.")
    model = None

SPAM_TRIGGERS = ['free', 'winner', 'cash', 'prize', 'urgent', 'money', 'congrats', 'won', 'offer', 'call', 'text', 'click']

# --- HELPER FUNCTIONS ---
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

# --- SMART SUMMARIZER (TextRank) ---
def smart_summary(text, sentences_count=3):
    if not text or len(text) < 100: 
        return "Document too short to summarize."
    
    try:
        # Clean text: Remove extra whitespace and empty lines
        clean_text = ' '.join(text.split())
        
        parser = PlaintextParser.from_string(clean_text, Tokenizer("english"))
        
        # LexRank is smarter than LSA but uses less RAM than TextRank
        summarizer = LexRankSummarizer()
        
        summary = summarizer(parser.document, sentences_count)
        
        if not summary:
            return "Could not identify key sentences. Try a longer document."

        return "• " + "\n\n• ".join([str(sentence) for sentence in summary])
        
    except Exception as e:
        print(f"Summarizer Error: {e}")
        # Return a slightly better fallback than just the first 500 chars
        return "⚠️ Summary generation failed due to server memory limits."

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/process_file', methods=['POST'])
def process_file():
    """ STEP 1: EXTRACT TEXT ONLY (Do not summarize yet) """
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

        return jsonify({'email_text': content})

    except Exception as e:
        return jsonify({'error': "File processing failed."}), 500

@app.route('/generate_summary', methods=['POST'])
def generate_summary():
    """ STEP 2: GENERATE SUMMARY (Only when button is clicked) """
    data = request.get_json()
    text = data.get('text', '')
    # Run Smart Summarizer
    summary = smart_summary(text, sentences_count=4)
    return jsonify({'summary': summary})

@app.route('/predict', methods=['POST'])
def predict():
    if not model: return jsonify({'error': 'Model not loaded.'}), 500
    
    data = request.get_json()
    email_text = data.get('text', '')
    text_lower = email_text.lower()
    
    # 0. FIND TRIGGERS FIRST
    triggers = [word for word in SPAM_TRIGGERS if word in text_lower]
    
    # --- 1. EDUCATIONAL INSTITUTIONS (Smart Check) ---
    edu_keywords = ['iit', 'vit', 'university', 'college', 'institute', 'ac.in', '.edu', 'student portal', 'campus']
    is_edu = any(word in text_lower for word in edu_keywords)
    
    if is_edu and not triggers:
        return jsonify({
            'result': 'safe', 
            'confidence': 99.8, 
            'insight': "✅ INSTITUTION: Official communication from an educational body.", 
            'triggers': [], 'tone': "Academic", 'links': []
        })

    # --- 2. SOCIAL MEDIA & SERVICES ---
    service_keywords = ['spotify', 'amazon', 'youtube', 'instagram', 'netflix', 'linkedin', 'google', 'facebook', 'twitter']
    if any(service in text_lower for service in service_keywords):
        security_keywords = ['password', 'verify', 'security alert', 'login', 'receipt', 'order confirmed', 'invoice', 'otp']
        
        if any(sec in text_lower for sec in security_keywords) and not triggers:
             return jsonify({
                'result': 'safe', 
                'confidence': 99.5, 
                'insight': "✅ SECURITY: Official account update or security alert.", 
                'triggers': [], 'tone': "Transactional", 'links': []
            })

    # --- 3. SELECTION / JOB OFFERS ---
    selection_keywords = ['shortlisted', 'selected', 'interview', 'hired', 'offer letter']
    if any(word in text_lower for word in selection_keywords) and not triggers:
        return jsonify({
            'result': 'safe', 
            'confidence': 99.5, 
            'insight': "✅ OFFICIAL: Valid selection or interview update.", 
            'triggers': [], 'tone': "Professional", 'links': []
        })

    # --- 4. GENERAL PROMO KEYWORDS ---
    promo_keywords = ['apply now', 'early bird', 'discount', 'stipend', 'bootcamp', 'webinar', 'limited time', 'sale', 'off']
    if any(word in text_lower for word in promo_keywords):
        return jsonify({
            'result': 'promo', 
            'confidence': 95.0, 
            'insight': "📢 PROMOTION: Contains marketing language.", 
            'triggers': triggers, 'tone': "Marketing", 'links': []
        })

    # --- 5. GENERAL AI MODEL FALLBACK ---
    pred = model.predict([email_text])[0]
    
    try: 
        confidence = round(max(model.predict_proba([email_text])[0]) * 100, 1)
    except: 
        confidence = 99.9

    tone = get_tone(email_text)
    links = analyze_links(email_text)

    if pred == 'spam': insight = f"⛔ SPAM: {tone} tone detected."
    elif pred == 'promo': insight = "📢 PROMOTION: Marketing language detected."
    else: insight = "✅ SAFE: Natural communication."

    return jsonify({'result': pred, 'confidence': confidence, 'insight': insight, 'triggers': triggers, 'tone': tone, 'links': links})

if __name__ == '__main__':
    print("--- 🌐 SERVER READY! Open http://127.0.0.1:5000 ---")
    app.run(debug=True)