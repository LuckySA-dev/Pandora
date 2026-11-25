# PandoraBox dev image for containerlab tests. The project folder is bind-mounted at /app by the topology,
# so code changes are live without rebuilding.   docker build -t pandorabox-dev:latest lab/
FROM python:3.12-slim
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" jinja2 pyserial netmiko "pysnmp>=7,<8" \
      "cryptography>=47" tftpy scapy anthropic httpx websockets pyyaml pytest \
 && apt-get update && apt-get install -y --no-install-recommends iproute2 iputils-ping tcpdump \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
CMD ["sleep", "infinity"]
