FROM mcr.microsoft.com/aci/skr:2.13 AS skr-source

FROM python:3.13-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor nginx openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=skr-source /bin/skr /usr/local/bin/skr
RUN chmod +x /usr/local/bin/skr

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /var/log/supervisor /tmp/uploads /tmp/processed \
    && openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 \
    -keyout /etc/ssl/private/server.key \
    -out /etc/ssl/private/server.crt \
    -subj "/C=US/ST=WA/L=Redmond/O=ConfidentialComputing/CN=localhost"

ENV FLASK_SECRET_KEY=change-me-in-production
EXPOSE 443

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
