FROM python:3.12-slim

# Common open-source scanners (optional but enable live scanning).
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -e ".[all]"

ENV SPECTER_HOME=/data
VOLUME ["/data"]
EXPOSE 8787

# Default to the team server; override CMD for CLI use, e.g.:
#   docker run --rm -e SPECTER_HOME=/data specter specter run --offline --demo
CMD ["specter", "serve", "--host", "0.0.0.0", "--port", "8787"]
