# Combined container with Flask web app, Nginx TLS proxy, and attestation SKR service
# Connects to PostgreSQL Flexible Server for financial transaction analytics
# Uses multi-stage build to extract SKR binary from Microsoft's sidecar image

# Stage 1: Extract SKR binary from Microsoft's attestation sidecar
FROM mcr.microsoft.com/aci/skr:2.13 AS skr-source

# Stage 2: Build the combined application container
FROM python:3.13-slim-bookworm

WORKDIR /app

# Install supervisord, nginx, openssl, and postgresql-client for connectivity testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    nginx \
    openssl \
    curl \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Generate a self-signed TLS certificate at build time
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

# Copy Nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy application files
COPY app.py .
COPY templates/ templates/

# Create required directories with proper permissions
RUN mkdir -p /var/log/supervisor /var/log/nginx /var/run \
    && chown -R appuser:appuser /app \
    && chmod -R 755 /app \
    && chown -R appuser:appuser /var/log/supervisor \
    && chown -R appuser:appuser /var/run

# Copy supervisord configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose port 80 (HTTP via AppGw) and 443 (HTTPS internal)
EXPOSE 80 443

# Start supervisord which manages nginx, gunicorn, and SKR processes
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
