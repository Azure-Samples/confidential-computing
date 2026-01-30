# Combined container with Flask web app and attestation SKR service
# Uses multi-stage build to extract SKR binary from Microsoft's sidecar image

# Stage 1: Extract SKR binary from Microsoft's attestation sidecar
FROM mcr.microsoft.com/aci/skr:2.7 AS skr-source

# Stage 2: Build the combined application container
FROM python:3.11-slim-bookworm

WORKDIR /app

# Install supervisord to manage multiple processes
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy SKR binary from the sidecar image
COPY --from=skr-source /bin/skr /usr/local/bin/skr
RUN chmod +x /usr/local/bin/skr

# Install Python requirements
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/

# Create supervisord configuration to run both services
RUN mkdir -p /var/log/supervisor
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose port 80 for web traffic (SKR runs internally on 8080)
EXPOSE 80

# Start supervisord which manages both Flask and SKR processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
