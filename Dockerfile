FROM node:18-alpine

WORKDIR /app

COPY src/package.json ./

RUN npm install --production 2>/dev/null; exit 0

COPY src/ ./

EXPOSE 8080

CMD ["node", "index.js"]
