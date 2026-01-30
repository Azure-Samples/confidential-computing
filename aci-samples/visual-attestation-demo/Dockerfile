FROM python:3.9-slim-buster

WORKDIR /app

# Install requirements
COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

# Copy application files
COPY app.py .
COPY templates/ templates/

EXPOSE 80

CMD ["python3", "app.py"]
