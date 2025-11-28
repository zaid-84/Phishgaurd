# Selenium-ready Dockerfile (Python 3.10) with headless Chromium + chromedriver
FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system packages and chromium/chromedriver and fonts needed for headless chrome
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates unzip gnupg2 \
    build-essential gcc \
    libnss3 libgconf-2-4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxss1 libx11-xcb1 libgbm1 \
    fonts-liberation \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Create symlink for chromedriver (if the package puts it in different location)
RUN if [ -f /usr/lib/chromium/chromedriver ]; then ln -s /usr/lib/chromium/chromedriver /usr/bin/chromedriver || true; fi
RUN if [ -f /usr/bin/chromedriver ]; then echo "chromedriver present"; fi

# Copy only requirements first (avoid picking up other build files)
COPY requirements.txt .

RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy app sources
COPY . .

# Environment
ENV PORT=8080
EXPOSE 8080

# If your Selenium code expects the Chrome binary at /usr/bin/google-chrome or /usr/bin/chromium-browser,
# you can create a symlink:
RUN if [ -f /usr/bin/chromium ]; then ln -s /usr/bin/chromium /usr/bin/google-chrome || true; fi

# Start with gunicorn. If you need more workers, increase --workers.
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120 --access-logfile - --error-logfile -"]
