import pandas as pd
import sys

# --- CONFIGURATION ---
NEW_FILE = 'emails.csv'       # The file you just uploaded (Number-based)
OLD_FILE = 'spam.csv'         # Your previous file (Text-based)
OUTPUT_FILE = 'combined_data.csv'

print(f"🚀 Processing '{NEW_FILE}' (converting numbers back to text)...")

# 1. Load the new number-based dataset
try:
    df_counts = pd.read_csv(NEW_FILE)
    print(f"   Found {len(df_counts)} emails in {NEW_FILE}.")
except FileNotFoundError:
    print(f"❌ Error: '{NEW_FILE}' not found.")
    sys.exit()

# 2. Identify Word Columns (Everything except 'Email No.' and 'Prediction')
# We need to turn columns: {'the': 2, 'cat': 1} -> into text: "the the cat"
ignore_cols = ['Email No.', 'Prediction', 'Email No', 'prediction']
word_cols = [c for c in df_counts.columns if c not in ignore_cols]

def counts_to_text(row):
    # This rebuilds the message from the word counts
    words = []
    for word in word_cols:
        count = row[word]
        if count > 0:
            # Repeat the word 'count' times
            words.append((str(word) + " ") * int(count))
    return "".join(words).strip()

# Apply the conversion (This might take 10-20 seconds)
print("   ⏳ Reconstructing text messages (this takes a moment)...")
df_counts['Message'] = df_counts.apply(counts_to_text, axis=1)

# 3. Standardize Labels (0 -> ham, 1 -> spam)
if 'Prediction' in df_counts.columns:
    df_counts['Category'] = df_counts['Prediction'].apply(lambda x: 'spam' if x == 1 else 'ham')

# Keep only the standardized columns
df_new_ready = df_counts[['Category', 'Message']]

# 4. Merge with Old Data
print(f"   ✅ Successfully processed new data. Now looking for '{OLD_FILE}'...")

try:
    df_old = pd.read_csv(OLD_FILE, encoding='latin-1')
    
    # Fix old columns if needed (v1/v2 -> Category/Message)
    if 'v1' in df_old.columns: 
        df_old.rename(columns={'v1':'Category', 'v2':'Message'}, inplace=True)
    
    # Ensure it has the right columns
    if 'Category' in df_old.columns and 'Message' in df_old.columns:
        df_old = df_old[['Category', 'Message']]
        print(f"   ✅ Loaded {len(df_old)} rows from {OLD_FILE}")
        
        # Merge them
        print("🔄 Merging datasets...")
        df_final = pd.concat([df_old, df_new_ready], ignore_index=True)
    else:
        print(f"⚠️ Warning: '{OLD_FILE}' exists but has wrong columns. Using ONLY new data.")
        df_final = df_new_ready

except FileNotFoundError:
    print(f"⚠️ Warning: '{OLD_FILE}' not found. Creating dataset using ONLY the new file.")
    df_final = df_new_ready

# 5. Save the Result
df_final.to_csv(OUTPUT_FILE, index=False)
print("-" * 30)
print(f"🎉 SUCCESS! Saved '{OUTPUT_FILE}' with {len(df_final)} total emails.")
print("   You can now run 'train_model.py'!")