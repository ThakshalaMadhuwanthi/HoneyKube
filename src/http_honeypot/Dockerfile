FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r src/http_honeypot/requirements.txt

EXPOSE 8080

CMD ["python", "-m", "src.http_honeypot.http_honeypot"]




