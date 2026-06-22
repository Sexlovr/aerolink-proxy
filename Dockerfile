FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --omit=dev

COPY server.js .

RUN mkdir -p /data

ENV CONFIG_PATH=/data/config.json
ENV PORT=7860

EXPOSE 7860

CMD ["node", "server.js"]
