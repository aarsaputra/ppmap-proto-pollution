# Stage 1: Builder
FROM python:3.11-slim as builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Build wheels for all dependencies to avoid installing build tools in the final image
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels -r requirements.txt

# Stage 2: Runner (Final Image)
FROM python:3.11-slim

# Install runtime dependencies (e.g., for Chromium payload processing if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -m ppmapuser

WORKDIR /app

# Copy wheels from builder and install them
COPY --from=builder /build/wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir /wheels/*

# Copy source code
COPY ppmap/ ./ppmap/
COPY ppmap.py .

# Setup permissions
RUN mkdir -p /app/reports && chown -R ppmapuser:ppmapuser /app

# Clean up wheels
RUN rm -rf /wheels

# Switch to non-root user
USER ppmapuser

# Volumes for persistence
VOLUME ["/app/reports"]

# Define entrypoint
ENTRYPOINT ["python3", "ppmap.py"]
CMD ["-h"]
