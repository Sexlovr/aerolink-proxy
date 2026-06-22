FROM node:20-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/Sexlovr/aerolink-proxy.git .

RUN npm install --omit=dev

ENV CONFIG_PATH=/data/config.json
ENV PORT=7860
RUN mkdir -p /data

EXPOSE 7860

CMD ["node", "server.js"]
