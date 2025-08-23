FROM python:3.12-slim

WORKDIR /app

# Copy the entire project
COPY . .

# Install dependencies from the correct path
RUN pip install --no-cache-dir -r src/ssh_honeypot/requirements.txt

EXPOSE 2222

CMD ["python", "-m", "src.ssh_honeypot.ssh_honeypot"]




