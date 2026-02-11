# Combined container with Flask web app, Nginx TLS proxy, and attestation SKR service
# Uses multi-stage build to extract SKR binary from Microsoft's sidecar image

# Stage 1: Extract SKR binary from Microsoft's attestation sidecar
FROM mcr.microsoft.com/aci/skr:2.13 AS skr-source

# Stage 2: Build the combined application container
FROM python:3.13-slim-bookworm

WORKDIR /app

# Install supervisord, nginx, and openssl for TLS termination
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    nginx \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Generate a self-signed TLS certificate at build time
# In production, replace with a certificate from a trusted CA or mount via secrets
RUN mkdir -p /etc/nginx/ssl \
    && openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
       -keyout /etc/nginx/ssl/server.key \
       -out /etc/nginx/ssl/server.crt \
       -subj "/C=US/ST=WA/L=Redmond/O=Confidential Computing Demo/CN=*.azurecontainer.io" \
       -addext "subjectAltName=DNS:*.azurecontainer.io,DNS:localhost" \
    && chmod 600 /etc/nginx/ssl/server.key \
    && chmod 644 /etc/nginx/ssl/server.crt

# Copy SKR binary from the sidecar image
COPY --from=skr-source /bin/skr /usr/local/bin/skr
RUN chmod +x /usr/local/bin/skr

# Install Python requirements
COPY requirements.txt requirements.txt
RUN pip3 install --no-cache-dir -r requirements.txt

# Create a non-root user for the application
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Copy Nginx configuration (HTTP:80 for browsers, HTTPS:443 for inter-container TLS)
COPY nginx.conf /etc/nginx/nginx.conf

# Copy application files
COPY app.py .
COPY templates/ templates/

# Copy company data CSV files for seeding
COPY contoso-data.csv .
COPY fabrikam-data.csv .

# Create required directories with proper permissions
RUN mkdir -p /var/log/supervisor /var/log/nginx /var/run /app/encrypted-data \
    && chown -R appuser:appuser /app \
    && chmod -R 755 /app \
    && chown -R appuser:appuser /var/log/supervisor \
    && chown -R appuser:appuser /var/run

# Copy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose port 80 (HTTP/browser) and 443 (HTTPS/inter-container)
# Gunicorn on 8000 and SKR on 8080 are internal only
EXPOSE 80 443

# Start supervisord which manages nginx, gunicorn, and SKR processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
