FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m ppmapuser

WORKDIR /app

# Copy requirements files
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and create reports directory alongside ownership config
COPY ppmap/ ./ppmap/
COPY ppmap.py .
RUN mkdir -p /app/reports && chown -R ppmapuser:ppmapuser /app

# Switch to non-root user
USER ppmapuser

# Volumes for persistence
VOLUME ["/app/reports"]

# Define entrypoint
ENTRYPOINT ["python3", "ppmap.py"]
CMD ["-h"]
