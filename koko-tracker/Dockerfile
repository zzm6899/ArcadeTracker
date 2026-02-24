FROM python:3.11-slim

WORKDIR /koko

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download jsQR at build time
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /koko/static/js && \
    curl -sL https://unpkg.com/jsqr@1.4.0/dist/jsQR.js -o /koko/static/js/jsQR.js

COPY app/ ./app/
COPY templates/ ./templates/
COPY static/ ./static/

RUN mkdir -p /data

ENV DB_PATH=/data/koko.db
ENV POLL_INTERVAL=60

EXPOSE 5000

CMD ["python", "app/app.py"]
