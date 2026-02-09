# 1. Use an official Python runtime
FROM python:3.9-slim

# 2. Install Tesseract OCR (The Image Reader Software)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

# 3. Set up the app
WORKDIR /app
COPY . /app

# 4. Install Python libraries
RUN pip install --no-cache-dir -r requirements.txt

# 5. Run the app
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:10000", "app:app"]