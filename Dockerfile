FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/Sexlovr/aerolink-proxy.git .

RUN pip install --no-cache-dir -r requirements.txt

ENV CONFIG_PATH=/data/config.json
ENV PORT=7860
RUN mkdir -p /data

EXPOSE 7860

CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]
