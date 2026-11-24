FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    INSTANCE_DIR=/data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data/uploads
VOLUME ["/data"]

EXPOSE 8080

CMD ["sh", "-c", "waitress-serve --host=0.0.0.0 --port=${PORT:-8080} --call app:create_app"]
