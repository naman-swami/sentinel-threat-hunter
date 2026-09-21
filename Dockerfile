FROM python:3.11-slim
LABEL maintainer="Naman Swami <kgfg00100@gmail.com>"
LABEL domain="cybersecurity-threat-hunting-mitre"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
ENV PYTHONUNBUFFERED=1

USER 10001
CMD ["python", "main.py", "--demo"]
