FROM python:3.11-slim

# nmap is a system package, not a pip package
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# NOTE: -sV/-O service & OS detection need raw socket access.
# Run with: docker run --cap-add=NET_RAW --cap-add=NET_ADMIN netmap ...
ENTRYPOINT ["python", "main.py"]
CMD ["--demo"]
