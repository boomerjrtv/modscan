FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps for common Python libs; keep minimal.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy repository
COPY . /app

# Install runtime deps. Avoid heavy headless browser deps by default.
# If you need screenshots/Playwright, install it in a derived image.
RUN pip install --no-cache-dir \
        aiohttp==3.* \
        requests==2.* \
        psutil==5.* \
        beautifulsoup4==4.*

# Optional: uncomment to include Playwright + Chromium (larger image)
# RUN pip install --no-cache-dir playwright==1.* && \
#     python -m playwright install --with-deps chromium

ENTRYPOINT ["python", "engine.py"]
CMD []

