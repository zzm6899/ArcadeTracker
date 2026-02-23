FROM python:3.11-slim

WORKDIR /koko

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY templates/ ./templates/
COPY static/ ./static/

RUN mkdir -p /data

ENV DB_PATH=/data/koko.db
ENV POLL_INTERVAL=60
ENV SECRET_KEY=""

EXPOSE 5000

CMD ["python", "app/app.py"]
