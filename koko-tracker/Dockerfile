FROM python:3.11-slim

WORKDIR /koko

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY templates/ ./templates/

RUN mkdir -p /data /koko/static

ENV DB_PATH=/data/koko.db
ENV POLL_INTERVAL=60

EXPOSE 5000

CMD ["python", "app/app.py"]
