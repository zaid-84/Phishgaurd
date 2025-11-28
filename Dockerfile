# Selenium-ready Dockerfile (Python 3.10) with headless Chromium
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install necessary system packages and headless Chromium (no libgconf-2-4)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates unzip gnupg2 \
    build-essential gcc \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxss1 libx11-xcb1 libgbm1 \
    fonts-liberation fontconfig \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# (Optional) create symlink so selenium can find chromium binary
RUN if [ -f /usr/bin/chromium ]; then ln -s /usr/bin/chromium /usr/bin/google-chrome || true; fi

# Copy only requirements first to avoid accidental installs from other files
COPY requirements.txt .

RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Environment and expose port
ENV PORT=8080
EXPOSE 8080

# Start with gunicorn (adjust module:variable if needed)
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 180 --access-logfile - --error-logfile -"]
