FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py bot_main.py service_manager.py ./
COPY data_layer/ ./data_layer/
COPY discord_handler/ ./discord_handler/
COPY utils/ ./utils/

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

CMD ["python", "bot_main.py"]
