# Combined container with Flask web app and attestation SKR service
# Uses multi-stage build to extract SKR binary from Microsoft's sidecar image

# Stage 1: Extract SKR binary from Microsoft's attestation sidecar
FROM mcr.microsoft.com/aci/skr:2.13 AS skr-source

# Stage 2: Build the combined application container
FROM python:3.13-slim-bookworm

WORKDIR /app

# Install supervisord to manage multiple processes
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy SKR binary from the sidecar image
COPY --from=skr-source /bin/skr /usr/local/bin/skr
RUN chmod +x /usr/local/bin/skr

# Install Python requirements
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Create a non-root user for the application
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Copy application files
COPY app.py .
COPY templates/ templates/

# Copy company data CSV files for seeding
COPY contoso-data.csv .
COPY fabrikam-data.csv .

# Create required directories with proper permissions
RUN mkdir -p /var/log/supervisor /var/run /app/encrypted-data \
    && chown -R appuser:appuser /app \
    && chmod -R 755 /app \
    && chown -R appuser:appuser /var/log/supervisor \
    && chown -R appuser:appuser /var/run

# Copy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose port 80 for web traffic (SKR runs internally on 8080)
EXPOSE 80

# Start supervisord which manages both Flask and SKR processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
