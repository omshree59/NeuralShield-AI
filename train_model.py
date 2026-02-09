import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
import pickle

# 1. Load Data
try:
    df = pd.read_csv('spam.csv', encoding='latin-1')
    df.dropna(how="any", inplace=True, axis=1)
    df.columns = ['label', 'message']
except FileNotFoundError:
    print("❌ Error: 'spam.csv' not found.")
    exit()

# 2. FEATURE ENGINEERING: Create the "Promotional" Category
# We look for "Ham" emails that sound like Newsletters/Marketing
def refine_label(row):
    text = row['message'].lower()
    label = row['label']
    
    # Keywords that suggest an email is Promotional/Newsletter
    promo_keywords = ['unsubscribe', 'offer', 'sale', 'discount', 'newsletter', 'subscribe', 'updates', 'daily', 'weekly']
    
    if label == 'ham':
        if any(word in text for word in promo_keywords):
            return 'promo'  # New Category!
    return label

print("⚙️ Refining dataset labels (creating 'Promo' category)...")
df['label'] = df.apply(refine_label, axis=1)

print(f"📊 New Label Counts:\n{df['label'].value_counts()}")

# 3. Split Data
X_train, X_test, y_train, y_test = train_test_split(df['message'], df['label'], test_size=0.2, random_state=42)

# 4. Build "Calibrated" Pipeline
# LinearSVC is fast but doesn't give good probabilities by default.
# CalibratedClassifierCV fixes this, making the "Confidence Score" accurate.
svm = LinearSVC(class_weight='balanced')
clf = CalibratedClassifierCV(svm, method='sigmoid') # This enables probability output

pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(stop_words='english', max_df=0.7)),
    ('classifier', clf)
])

# 5. Train
print("🧠 Training 3-Class Calibrated Model...")
pipeline.fit(X_train, y_train)

# 6. Test & Save
score = pipeline.score(X_test, y_test)
print(f"🎯 Accuracy: {score * 100:.2f}%")

with open('spam_model.pkl', 'wb') as f:
    pickle.dump(pipeline, f)

print("💾 Model saved!")