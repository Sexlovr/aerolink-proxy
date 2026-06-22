FROM node:20-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

ENV GIT_SSL_NO_VERIFY=true

WORKDIR /app

RUN git clone https://github.com/Sexlovr/aerolink-proxy.git .

RUN npm install --omit=dev

RUN mkdir -p /data

ENV CONFIG_PATH=/data/config.json
ENV PORT=7860

EXPOSE 7860

CMD ["node", "server.js"]
