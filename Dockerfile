FROM python:3.9-slim

# Install Tesseract OCR (The Linux Software)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir --upgrade -r requirements.txt

CMD ["gunicorn", "--workers=1", "--threads=4", "--timeout=120", "--bind", "0.0.0.0:10000", "app:app"]