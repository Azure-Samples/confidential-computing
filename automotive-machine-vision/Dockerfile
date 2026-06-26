FROM mcr.microsoft.com/aci/skr:2.13 AS skr-source

FROM python:3.13-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    supervisor nginx openssl ffmpeg \
    && rm -rf /var/lib/apt/lists/*

COPY --from=skr-source /bin/skr /usr/local/bin/skr
RUN chmod +x /usr/local/bin/skr

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY start.sh /app/start.sh
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /var/log/supervisor /tmp/uploads /tmp/processed \
    && chmod +x /app/start.sh

ENV FLASK_SECRET_KEY=change-me-in-production
EXPOSE 443

CMD ["/app/start.sh"]
