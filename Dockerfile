FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create a non-root user and group
RUN groupadd -r apexgroup && useradd -r -g apexgroup apexuser

COPY . .

RUN mkdir -p /app/reports_output && chown -R apexuser:apexgroup /app

USER apexuser

ENTRYPOINT ["python3", "apex.py"]
